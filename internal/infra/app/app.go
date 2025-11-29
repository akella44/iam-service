package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
	"google.golang.org/grpc"

	"github.com/arklim/social-platform-iam/internal/core/port"
	"github.com/arklim/social-platform-iam/internal/infra/config"
	"github.com/arklim/social-platform-iam/internal/infra/database"
	kafkainfra "github.com/arklim/social-platform-iam/internal/infra/kafka"
	"github.com/arklim/social-platform-iam/internal/infra/logger"
	redisinfra "github.com/arklim/social-platform-iam/internal/infra/redis"
	"github.com/arklim/social-platform-iam/internal/infra/security"
	"github.com/arklim/social-platform-iam/internal/infra/telemetry"
	postgresrepo "github.com/arklim/social-platform-iam/internal/repository/postgres"
	redisrepo "github.com/arklim/social-platform-iam/internal/repository/redis"
	transportgrpc "github.com/arklim/social-platform-iam/internal/transport/grpc"
	"github.com/arklim/social-platform-iam/internal/transport/http/middleware"
	"github.com/arklim/social-platform-iam/internal/transport/http/routes"
	"github.com/arklim/social-platform-iam/internal/usecase"
)

type Application struct {
	cfg        *config.AppConfig
	engine     *gin.Engine
	logger     *zap.Logger
	pool       *pgxpool.Pool
	redis      *redisinfra.Client
	grpcServer *grpc.Server
	grpcAddr   string
}

func New(ctx context.Context, cfg *config.AppConfig) (*Application, error) {
	log, err := logger.New(cfg.App.Env)
	if err != nil {
		return nil, fmt.Errorf("init logger: %w", err)
	}

	if _, err := telemetry.Attach(ctx, cfg); err != nil {
		return nil, fmt.Errorf("init telemetry: %w", err)
	}

	pool, err := database.NewPostgresPool(ctx, cfg.Postgres, log)
	if err != nil {
		return nil, fmt.Errorf("init postgres: %w", err)
	}

	keyProvider, err := security.NewKeyProvider(cfg.App.Env, cfg.JWT.KeyDirectory)
	if err != nil {
		return nil, fmt.Errorf("init key provider: %w", err)
	}
	jwksManager := security.NewJWTManager(keyProvider)

	argonCfg := security.Argon2Config{
		Memory:      cfg.Argon2.Memory,
		Iterations:  cfg.Argon2.Iterations,
		Parallelism: cfg.Argon2.Parallelism,
		SaltLength:  cfg.Argon2.SaltLength,
		KeyLength:   cfg.Argon2.KeyLength,
	}
	if err := security.ConfigureArgon2(argonCfg); err != nil {
		return nil, fmt.Errorf("configure argon2: %w", err)
	}

	tokenGenerator, err := security.NewTokenGenerator(keyProvider, "v1")
	if err != nil {
		return nil, fmt.Errorf("init token generator: %w", err)
	}

	redisClient, err := redisinfra.NewClient(cfg.Redis, log)
	if err != nil {
		return nil, fmt.Errorf("init redis: %w", err)
	}

	sessionVersionCache := redisrepo.NewSessionVersionRepository(redisClient.Client(), cfg.Redis.SessionVersionPrefix)
	sessionVersionTTL := cfg.Redis.SessionVersionTTL
	if sessionVersionTTL <= 0 {
		sessionVersionTTL = 10 * time.Minute
	}

	sessionRevocationStore := redisrepo.NewSessionRevocationStore(redisClient.Client(), cfg.Redis.SessionRevocationPrefix)
	sessionRevocationTTL := cfg.Redis.SessionRevocationTTL
	if sessionRevocationTTL <= 0 {
		sessionRevocationTTL = maxDuration(cfg.JWT.AccessTokenTTL, cfg.JWT.RefreshTokenTTL)
	}
	if sessionRevocationTTL <= 0 {
		sessionRevocationTTL = 24 * time.Hour
	}

	repos := postgresrepo.NewRepositories(pool)

	// Initialize Kafka event publisher
	var eventPublisher port.EventPublisher
	if len(cfg.Kafka.Brokers) > 0 {
		kafkaProducer, err := kafkainfra.NewProducer(cfg.Kafka, log)
		if err != nil {
			log.Warn("failed to init kafka producer, using stub publisher", zap.Error(err))
			eventPublisher = kafkainfra.NewStubPublisher(log)
		} else {
			eventPublisher = kafkainfra.NewEventPublisher(kafkaProducer, cfg.App, log)
			log.Info("kafka event publisher initialized", zap.Strings("brokers", cfg.Kafka.Brokers))
		}
	} else {
		log.Info("kafka brokers not configured, using stub publisher")
		eventPublisher = kafkainfra.NewStubPublisher(log)
	}

	passwordValidator := security.DefaultPasswordValidator()
	passwordPolicy := security.NewPasswordPolicy()

	rateLimitWindow := cfg.RateLimit.WindowDuration
	if rateLimitWindow <= 0 {
		rateLimitWindow = time.Minute
	}
	rateLimitTTL := rateLimitWindow * 2
	rateLimitStore := redisrepo.NewRateLimitRepository(redisClient.Client(), redisrepo.SlidingWindowConfig{
		KeyPrefix: "iam:rate-limit",
		TTL:       rateLimitTTL,
	})

	rateLimiter := middleware.NewRateLimiter(rateLimitStore, log)

	authService, err := usecase.NewAuthService(cfg, repos.Users, repos.Roles, repos.Permissions, repos.Sessions, repos.Tokens, tokenGenerator, keyProvider, rateLimitStore, log)
	if err != nil {
		_ = redisClient.Close()
		return nil, fmt.Errorf("init auth service: %w", err)
	}

	sessionService := usecase.NewSessionService(repos.Sessions, repos.Tokens, eventPublisher, log).
		WithSessionVersionCache(sessionVersionCache, sessionVersionTTL).
		WithSessionRevocationStore(sessionRevocationStore, sessionRevocationTTL)
	authService.WithSessionService(sessionService)
	authService.WithSessionVersionCache(sessionVersionCache, sessionVersionTTL)
	authService.WithSessionRevocationStore(sessionRevocationStore, sessionRevocationTTL)
	registrationService := usecase.NewRegistrationService(repos.Users, repos.Tokens, passwordPolicy, eventPublisher).WithLogger(log)
	userService := usecase.NewUserService(repos.Users, repos.Permissions, repos.Roles, eventPublisher, passwordValidator).
		WithSessionService(sessionService)
	roleService := usecase.NewRoleService(repos.Roles, repos.Permissions, repos.Users).
		WithSessionService(sessionService)
	passwordResetService := usecase.NewPasswordResetService(cfg, repos.Users, repos.Tokens, rateLimitStore, eventPublisher, sessionService, passwordValidator, passwordPolicy, log)

	grpcSrv, err := transportgrpc.NewServer(transportgrpc.ServerDependencies{
		AuthService: authService,
		JWTManager:  jwksManager,
		Logger:      log,
		PublicMethods: []string{
			"/iam.v1.TokenService/GetJWKS",
		},
	})
	if err != nil {
		_ = redisClient.Close()
		return nil, fmt.Errorf("init grpc server: %w", err)
	}

	engine := routes.Register(routes.Dependencies{
		Config:      cfg,
		Logger:      log,
		RateLimiter: rateLimiter,
		JWTManager:  jwksManager,
		Database:    pool,
		Cache:       redisClient,
		Services: routes.ServiceSet{
			Auth:          authService,
			Registration:  registrationService,
			Users:         userService,
			Roles:         roleService,
			PasswordReset: passwordResetService,
			Sessions:      sessionService,
		},
	})

	return &Application{
		cfg:        cfg,
		engine:     engine,
		logger:     log,
		pool:       pool,
		redis:      redisClient,
		grpcServer: grpcSrv,
		grpcAddr:   fmt.Sprintf("%s:%d", cfg.GRPC.Host, cfg.GRPC.Port),
	}, nil
}

func (a *Application) Run(ctx context.Context) error {
	defer func() {
		_ = a.logger.Sync()
	}()
	defer func() {
		if a.pool != nil {
			a.pool.Close()
		}
	}()
	defer func() {
		if a.redis != nil {
			_ = a.redis.Close()
		}
	}()

	grpcErrCh := make(chan error, 1)
	var grpcListener net.Listener
	if a.grpcServer != nil && a.grpcAddr != "" {
		lis, err := net.Listen("tcp", a.grpcAddr)
		if err != nil {
			return fmt.Errorf("listen grpc: %w", err)
		}
		grpcListener = lis
		a.logger.Info("starting gRPC server",
			zap.String("address", a.grpcAddr),
		)
		go func() {
			defer func() {
				if r := recover(); r != nil {
					a.logger.Error("gRPC server panicked", zap.Any("panic", r))
					grpcErrCh <- fmt.Errorf("grpc server panicked: %v", r)
				}
			}()
			a.logger.Info("gRPC server goroutine started, calling Serve()")
			if err := a.grpcServer.Serve(lis); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
				a.logger.Error("gRPC server error", zap.Error(err))
				grpcErrCh <- fmt.Errorf("run grpc server: %w", err)
			} else {
				a.logger.Info("gRPC server stopped gracefully")
			}
		}()
	}
	defer func() {
		if grpcListener != nil {
			grpcListener.Close()
		}
		if a.grpcServer != nil {
			a.grpcServer.GracefulStop()
		}
	}()

	srv := &http.Server{
		Addr:              fmt.Sprintf("%s:%d", a.cfg.App.Host, a.cfg.App.Port),
		Handler:           a.engine,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	a.logger.Info("starting IAM API",
		zap.String("env", a.cfg.App.Env),
		zap.String("address", srv.Addr),
	)

	serverErrCh := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			serverErrCh <- fmt.Errorf("run server: %w", err)
		}
	}()

	select {
	case <-ctx.Done():
		if a.grpcServer != nil {
			a.grpcServer.GracefulStop()
		}
		if grpcListener != nil {
			_ = grpcListener.Close()
		}
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shutdown server: %w", err)
		}
		return nil
	case err := <-serverErrCh:
		return err
	case err := <-grpcErrCh:
		return err
	}
}

func maxDuration(values ...time.Duration) time.Duration {
	var max time.Duration
	for _, v := range values {
		if v > max {
			max = v
		}
	}
	return max
}
