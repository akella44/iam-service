package routes

import (
	"context"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"

	"github.com/arklim/social-platform-iam/internal/infra/config"
	"github.com/arklim/social-platform-iam/internal/infra/security"
	"github.com/arklim/social-platform-iam/internal/transport/http/handlers"
	"github.com/arklim/social-platform-iam/internal/transport/http/middleware"
	"github.com/arklim/social-platform-iam/internal/usecase"
)

// ServiceSet groups the services the HTTP layer depends on.
type ServiceSet struct {
	Auth          *usecase.AuthService
	Registration  *usecase.RegistrationService
	Users         *usecase.UserService
	Roles         *usecase.RoleService
	PasswordReset *usecase.PasswordResetService
	Sessions      *usecase.SessionService
}

// Dependencies encapsulates the objects required to register routes.
type Dependencies struct {
	Config      *config.AppConfig
	Logger      *zap.Logger
	RateLimiter *middleware.RateLimiter
	Services    ServiceSet
	JWTManager  *security.JWTManager
	Database    DatabaseChecker
	Cache       CacheChecker
}

// DatabaseChecker exposes readiness behaviour for database connections.
type DatabaseChecker interface {
	Ping(ctx context.Context) error
}

// CacheChecker exposes readiness behaviour for cache backends.
type CacheChecker interface {
	HealthCheck(ctx context.Context) error
}

// Register configures the Gin engine with routes and middleware.
func Register(deps Dependencies) *gin.Engine {
	if deps.Config.App.Env == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(middleware.EnrichContext())
	r.Use(middleware.RequestID())
	r.Use(middleware.Logger(deps.Logger))

	// Create auth middleware
	authMiddleware := middleware.RequireAuth(deps.Services.Auth)

	healthOptions := make([]handlers.HealthOption, 0, 2)

	if deps.Database != nil {
		healthOptions = append(healthOptions, handlers.WithReadinessCheck("database", deps.Database.Ping))
	}

	if deps.Cache != nil {
		healthOptions = append(healthOptions, handlers.WithReadinessCheck("redis", deps.Cache.HealthCheck))
	}

	healthHandler := handlers.NewHealthHandler(healthOptions...)

	r.GET("/healthz", healthHandler.Status)
	r.GET("/readyz", healthHandler.Readiness)

	r.GET("/metrics", gin.WrapH(promhttp.Handler()))

	api := r.Group("/api/v1")
	{
		isDev := deps.Config.App.Env == "development"
		notificationDispatcher := handlers.NewLoggingNotificationDispatcher(deps.Logger)

		authGroup := api.Group("/auth")

		authHandler := handlers.NewAuthHandler(deps.Services.Auth)

		loginMiddlewares := buildLoginMiddlewares(deps)
		authHandler.RegisterRoutes(authGroup, loginMiddlewares...)

		userGroup := api.Group("/user")

		registrationHandler := handlers.NewRegistrationHandler(deps.Services.Registration, notificationDispatcher, isDev)
		registrationHandler.RegisterRoutes(userGroup)

		passwordHandler := handlers.NewPasswordHandler(deps.Services.PasswordReset, notificationDispatcher, isDev)

		passwordGroup := api.Group("/password")
		passwordGroup.POST("/change", authMiddleware, passwordHandler.ChangePassword)

		resetMiddlewares := buildPasswordResetMiddlewares(deps)
		resetGroup := passwordGroup.Group("/reset")
		if len(resetMiddlewares) > 0 {
			resetGroup.Use(resetMiddlewares...)
		}
		resetGroup.POST("/request", passwordHandler.ResetPassword)
		resetGroup.POST("/confirm", passwordHandler.ConfirmReset)

		// Legacy routes retained for backwards compatibility with existing clients.
		userGroup.POST("/password/change", authMiddleware, passwordHandler.ChangePassword)

		legacyResetHandlers := append([]gin.HandlerFunc{}, resetMiddlewares...)
		legacyResetHandlers = append(legacyResetHandlers, passwordHandler.ResetPassword)
		userGroup.POST("/password/reset", legacyResetHandlers...)

		legacyConfirmHandlers := append([]gin.HandlerFunc{}, resetMiddlewares...)
		legacyConfirmHandlers = append(legacyConfirmHandlers, passwordHandler.ConfirmReset)
		userGroup.POST("/password/reset/confirm", legacyConfirmHandlers...)

		sessionHandler := handlers.NewSessionHandler(deps.Services.Auth, deps.Services.Sessions)
		sessionGroup := api.Group("/sessions")
		sessionGroup.Use(authMiddleware)
		sessionHandler.RegisterRoutes(sessionGroup)
		// Backwards compatible alias for legacy validation endpoint
		userGroup.POST("/session/validate", authMiddleware, sessionHandler.ValidateSession)

		if deps.Services.Roles != nil {
			rolesGroup := api.Group("/roles")
			rolesGroup.Use(authMiddleware) // Apply auth to all role endpoints
			roleHandler := handlers.NewRoleHandler(deps.Services.Roles, deps.Services.Auth)
			roleHandler.RegisterRoutes(rolesGroup)
		}
	}

	handlers.RegisterSwagger(r)

	return r
}

func buildLoginMiddlewares(deps Dependencies) []gin.HandlerFunc {
	if deps.RateLimiter == nil || deps.Config == nil {
		return nil
	}

	limit := deps.Config.RateLimit.LoginMaxAttempts
	if limit <= 0 {
		return nil
	}

	window := deps.Config.RateLimit.WindowDuration
	if window <= 0 {
		window = time.Minute
	}

	rule := middleware.RateLimitRule{
		Name:       "auth_login_ip",
		Limit:      limit,
		Window:     window,
		Identifier: middleware.ClientIPIdentifier(),
	}

	return []gin.HandlerFunc{deps.RateLimiter.RateLimit(rule)}
}

func buildPasswordResetMiddlewares(deps Dependencies) []gin.HandlerFunc {
	if deps.RateLimiter == nil || deps.Config == nil {
		return nil
	}

	limit := deps.Config.RateLimit.PasswordResetMaxAttempts
	if limit <= 0 {
		return nil
	}

	window := deps.Config.RateLimit.WindowDuration
	if window <= 0 {
		window = time.Hour
	}

	rule := middleware.RateLimitRule{
		Name:       "password_reset_ip",
		Limit:      limit,
		Window:     window,
		Identifier: middleware.ClientIPIdentifier(),
	}

	return []gin.HandlerFunc{deps.RateLimiter.RateLimit(rule)}
}
