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

	"github.com/arklim/social-platform-iam/internal/infra/config"
	"github.com/arklim/social-platform-iam/internal/infra/database"
	"github.com/arklim/social-platform-iam/internal/infra/logger"
	"github.com/arklim/social-platform-iam/internal/infra/security"
	"github.com/arklim/social-platform-iam/internal/infra/telemetry"
	postgresrepo "github.com/arklim/social-platform-iam/internal/repository/postgres"
	"github.com/arklim/social-platform-iam/internal/transport/grpc/iamv1"
	grpcserver "github.com/arklim/social-platform-iam/internal/transport/grpc/server"
	"github.com/arklim/social-platform-iam/internal/transport/http/routes"
	"github.com/arklim/social-platform-iam/internal/usecase"
)

type Application struct {
	cfg        *config.AppConfig
	engine     *gin.Engine
	logger     *zap.Logger
	pool       *pgxpool.Pool
	grpcServer *grpc.Server
	grpcAddr   string
}

func New(ctx context.Context, cfg *config.AppConfig) (*Application, error) {
	log, err := logger.New(cfg.App.Env)
	if err != nil {
		return nil, fmt.Errorf("init logger: %w", err)
	}

	telemetryProvider, err := telemetry.Attach(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("init telemetry: %w", err)
	}
	_ = telemetryProvider

	pool, err := database.NewPostgresPool(ctx, cfg.Postgres, log)
	if err != nil {
		return nil, fmt.Errorf("init postgres: %w", err)
	}

	keyProvider, err := security.NewKeyProvider(cfg.App.Env, cfg.JWT.KeyDirectory)
	if err != nil {
		return nil, fmt.Errorf("init key provider: %w", err)
	}

	tokenGenerator, err := security.NewTokenGenerator(keyProvider, "default-kid")
	if err != nil {
		return nil, fmt.Errorf("init token generator: %w", err)
	}

	repos := postgresrepo.NewRepositories(pool)

	passwordValidator := security.DefaultPasswordValidator()

	authService, err := usecase.NewAuthService(cfg, repos.Users, repos.Roles, repos.Permissions, repos.Sessions, repos.Tokens, tokenGenerator, keyProvider)
	if err != nil {
		return nil, fmt.Errorf("init auth service: %w", err)
	}

	registrationService := usecase.NewRegistrationService(repos.Users, repos.Tokens, passwordValidator)
	userService := usecase.NewUserService(repos.Users, repos.Permissions, passwordValidator)
	roleService := usecase.NewRoleService(repos.Roles, repos.Permissions, repos.Users)
	passwordResetService := usecase.NewPasswordResetService(repos.Users, repos.Tokens, passwordValidator)

	grpcSrv := grpc.NewServer()
	tokenValidationServer := grpcserver.NewTokenValidationServer(authService)
	iamv1.RegisterTokenValidationServiceServer(grpcSrv, tokenValidationServer)

	engine := routes.Register(routes.Dependencies{
		Config: cfg,
		Logger: log,
		Services: routes.ServiceSet{
			Auth:          authService,
			Registration:  registrationService,
			Users:         userService,
			Roles:         roleService,
			PasswordReset: passwordResetService,
		},
	})

	return &Application{
		cfg:        cfg,
		engine:     engine,
		logger:     log,
		pool:       pool,
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
			if err := a.grpcServer.Serve(lis); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
				grpcErrCh <- fmt.Errorf("run grpc server: %w", err)
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
