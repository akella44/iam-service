package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"

	"github.com/arklim/social-platform-iam/internal/infra/config"
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
}

// Dependencies encapsulates the objects required to register routes.
type Dependencies struct {
	Config   *config.AppConfig
	Logger   *zap.Logger
	Services ServiceSet
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

	healthHandler := handlers.NewHealthHandler()

	r.GET("/healthz", healthHandler.Status)

	r.GET("/metrics", gin.WrapH(promhttp.Handler()))

	api := r.Group("/api/v1")
	{
		authGroup := api.Group("/auth")
		tokenHandler := handlers.NewTokenHandler(deps.Services.Auth)
		tokenHandler.RegisterRoutes(authGroup)

		authHandler := handlers.NewAuthHandler(deps.Services.Auth)
		authHandler.RegisterRoutes(authGroup)

		userGroup := api.Group("/user")

		isDev := deps.Config.App.Env == "development"
		notificationDispatcher := handlers.NewLoggingNotificationDispatcher(deps.Logger)
		registrationHandler := handlers.NewRegistrationHandler(deps.Services.Registration, notificationDispatcher, isDev)
		registrationHandler.RegisterRoutes(userGroup)

		passwordHandler := handlers.NewPasswordHandler(deps.Services.Users, deps.Services.Auth, deps.Services.PasswordReset, notificationDispatcher, isDev)
		// Apply auth middleware only to password change endpoint
		userGroup.POST("/password/change", authMiddleware, passwordHandler.ChangePassword)
		userGroup.POST("/password/reset", passwordHandler.ResetPassword)
		userGroup.POST("/password/reset/confirm", passwordHandler.ConfirmReset)

		sessionHandler := handlers.NewSessionHandler(deps.Services.Auth)
		// Session endpoints require authentication
		userGroup.POST("/session/validate", authMiddleware, sessionHandler.ValidateSession)
		userGroup.GET("/session/list", authMiddleware, sessionHandler.ListSessions)
		userGroup.POST("/session/revoke", authMiddleware, sessionHandler.RevokeSession)

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
