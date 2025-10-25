package handlers

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/arklim/social-platform-iam/internal/core/domain"
	"github.com/arklim/social-platform-iam/internal/infra/security"
	"github.com/arklim/social-platform-iam/internal/repository"
	"github.com/arklim/social-platform-iam/internal/transport/http/middleware"
	"github.com/arklim/social-platform-iam/internal/usecase"
)

const (
	loginRateLimitProblemType  = "https://iam.social-platform.example.com/errors/rate-limit-exceeded"
	loginRateLimitProblemTitle = "Rate Limit Exceeded"
)

// AuthHandler exposes authentication endpoints.
type AuthHandler struct {
	auth         *usecase.AuthService
	registration *usecase.RegistrationService
	dispatcher   NotificationDispatcher
	isDev        bool
}

// AuthHandlerOption configures optional AuthHandler dependencies.
type AuthHandlerOption func(*AuthHandler)

// WithRegistrationService injects the registration service dependency.
func WithRegistrationService(registration *usecase.RegistrationService) AuthHandlerOption {
	return func(h *AuthHandler) {
		h.registration = registration
	}
}

// WithNotificationDispatcher injects the notification dispatcher used to deliver verification artifacts.
func WithNotificationDispatcher(dispatcher NotificationDispatcher) AuthHandlerOption {
	return func(h *AuthHandler) {
		if dispatcher == nil {
			dispatcher = noopDispatcher{}
		}
		h.dispatcher = dispatcher
	}
}

// WithDevMode toggles development-only behaviour (e.g. returning verification tokens).
func WithDevMode(isDev bool) AuthHandlerOption {
	return func(h *AuthHandler) {
		h.isDev = isDev
	}
}

// NewAuthHandler constructs AuthHandler.
func NewAuthHandler(auth *usecase.AuthService, opts ...AuthHandlerOption) *AuthHandler {
	handler := &AuthHandler{
		auth:       auth,
		dispatcher: noopDispatcher{},
	}

	for _, opt := range opts {
		if opt != nil {
			opt(handler)
		}
	}

	if handler.dispatcher == nil {
		handler.dispatcher = noopDispatcher{}
	}

	return handler
}

// RegisterRoutes binds authentication routes, applying optional middleware ahead of handlers.
func (h *AuthHandler) RegisterRoutes(r *gin.RouterGroup, loginMiddlewares ...gin.HandlerFunc) {
	r.POST("/register", h.register)

	if len(loginMiddlewares) > 0 {
		chain := append([]gin.HandlerFunc{}, loginMiddlewares...)
		chain = append(chain, h.login)
		r.POST("/login", chain...)
	} else {
		r.POST("/login", h.login)
	}

	r.POST("/refresh", h.refresh)
	r.POST("/logout", middleware.RequireAuth(h.auth), h.logout)
}

// Register godoc
// @Summary Register a new user account
// @Description Creates a new user with the supplied credentials and contact information.
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body RegistrationRequest true "Registration request payload"
// @Success 201 {object} RegistrationResponse
// @Failure 400 {object} ErrorResponse
// @Failure 409 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Failure 503 {object} ErrorResponse
// @Router /api/v1/auth/register [post]
func (h *AuthHandler) register(c *gin.Context) {
	if h.registration == nil {
		c.JSON(http.StatusServiceUnavailable, NewErrorResponse(c, "registration service unavailable"))
		return
	}

	var req RegistrationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, NewErrorResponse(c, "invalid registration payload"))
		return
	}

	req.Username = strings.TrimSpace(req.Username)
	req.Email = strings.TrimSpace(req.Email)
	req.Phone = strings.TrimSpace(req.Phone)

	if req.Username == "" {
		c.JSON(http.StatusBadRequest, NewErrorResponse(c, "username is required"))
		return
	}
	if req.Email == "" && req.Phone == "" {
		c.JSON(http.StatusBadRequest, NewErrorResponse(c, "either email or phone is required"))
		return
	}

	user, verification, err := h.registration.RegisterUser(c.Request.Context(), req.Username, req.Email, req.Phone, req.Password)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			switch pgErr.ConstraintName {
			case "users_email_key":
				c.JSON(http.StatusConflict, NewErrorResponse(c, "email already registered"))
			case "users_phone_key":
				c.JSON(http.StatusConflict, NewErrorResponse(c, "phone already registered"))
			default:
				c.JSON(http.StatusConflict, NewErrorResponse(c, "username or contact already exists"))
			}
			return
		}
		if errors.Is(err, usecase.ErrPasswordPolicyViolation) {
			c.JSON(http.StatusBadRequest, NewErrorResponse(c, "password does not meet requirements"))
			return
		}
		c.JSON(http.StatusInternalServerError, NewErrorResponse(c, "failed to register user"))
		return
	}

	user.PasswordHash = ""

	resp := RegistrationResponse{
		User:                 newUserSummary(user, nil),
		RequiresVerification: user.Status == domain.UserStatusPending,
	}

	if user.Status == domain.UserStatusPending {
		resp.Message = "verification required"
		if verification.Delivery != "" {
			delivery := verification.Delivery
			resp.Delivery = &delivery
		}
		if !verification.ExpiresAt.IsZero() {
			expires := verification.ExpiresAt.UTC().Format(time.RFC3339)
			resp.ExpiresAt = &expires
		}

		if h.isDev {
			if token := strings.TrimSpace(verification.Token); token != "" {
				resp.DevToken = &token
			}
			if code := strings.TrimSpace(verification.Code); code != "" {
				resp.DevCode = &code
			}
		}

		h.dispatchVerification(c.Request.Context(), req.Username, req.Email, req.Phone, verification)
	}

	c.JSON(http.StatusCreated, resp)
}

// Refresh godoc
// @Summary Refresh an access token
// @Description Issues a new access token and refresh token pair using a valid refresh token.
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body TokenRefreshRequest true "Refresh request"
// @Success 200 {object} TokenRefreshResponse
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Failure 403 {object} ErrorResponse
// @Failure 409 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Failure 503 {object} ErrorResponse
// @Router /api/v1/auth/refresh [post]
func (h *AuthHandler) refresh(c *gin.Context) {
	handleTokenRefresh(c, h.auth)
}

// Logout godoc
// @Summary Logout the current session
// @Description Revokes the caller's active session using the access token's session context.
// @Tags Authentication
// @Produce json
// @Success 204 {string} string ""
// @Failure 401 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /api/v1/auth/logout [post]
func (h *AuthHandler) logout(c *gin.Context) {
	claims := getAccessTokenClaims(c)
	if claims == nil {
		c.JSON(http.StatusUnauthorized, NewErrorResponse(c, "authentication required"))
		return
	}

	sessionID := strings.TrimSpace(claims.SessionID)
	if sessionID == "" {
		c.Status(http.StatusNoContent)
		return
	}

	if err := h.auth.RevokeSession(c.Request.Context(), sessionID, "user_logout"); err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			c.Status(http.StatusNoContent)
			return
		}
		c.JSON(http.StatusInternalServerError, NewErrorResponse(c, "failed to revoke session"))
		return
	}

	c.Status(http.StatusNoContent)
}

func (h *AuthHandler) dispatchVerification(ctx context.Context, username, email, phone string, verification usecase.RegistrationVerification) {
	if h.dispatcher == nil {
		return
	}

	contact := strings.TrimSpace(email)
	if contact == "" {
		contact = strings.TrimSpace(phone)
	}

	payload := RegistrationNotification{
		Delivery: verification.Delivery,
		Contact:  contact,
		Username: strings.TrimSpace(username),
		Email:    strings.TrimSpace(email),
		Phone:    strings.TrimSpace(phone),
		Expires:  verification.ExpiresAt,
	}

	if h.isDev {
		payload.DevToken = strings.TrimSpace(verification.Token)
		payload.DevCode = strings.TrimSpace(verification.Code)
	}

	_ = h.dispatcher.SendRegistrationVerification(ctx, payload)
}

func handleTokenRefresh(c *gin.Context, auth *usecase.AuthService) {
	if auth == nil {
		c.JSON(http.StatusServiceUnavailable, NewErrorResponse(c, "refresh token service unavailable"))
		return
	}

	var req TokenRefreshRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, NewErrorResponse(c, "refresh_token is required"))
		return
	}

	accessToken, newRefreshToken, user, roles, err := auth.RefreshAccessToken(c.Request.Context(), req.RefreshToken)
	if err != nil {
		switch {
		case errors.Is(err, usecase.ErrInvalidRefreshToken):
			c.JSON(http.StatusUnauthorized, NewErrorResponse(c, "invalid refresh token"))
		case errors.Is(err, usecase.ErrExpiredRefreshToken):
			c.JSON(http.StatusUnauthorized, NewErrorResponse(c, "refresh token expired"))
		case errors.Is(err, usecase.ErrInactiveAccount):
			c.JSON(http.StatusForbidden, NewErrorResponse(c, "account inactive"))
		case errors.Is(err, usecase.ErrAccountPending):
			c.JSON(http.StatusConflict, NewErrorResponse(c, "account pending verification"))
		case errors.Is(err, usecase.ErrRefreshTokenUnavailable):
			c.JSON(http.StatusServiceUnavailable, NewErrorResponse(c, "refresh tokens unavailable"))
		case errors.Is(err, usecase.ErrRefreshTokenReplay):
			c.JSON(http.StatusConflict, NewErrorResponse(c, "refresh token replay detected"))
		default:
			c.JSON(http.StatusInternalServerError, NewErrorResponse(c, "failed to refresh token"))
		}
		return
	}

	response := TokenRefreshResponse{
		AccessToken:  accessToken,
		RefreshToken: newRefreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    computeExpiresIn(accessToken, auth),
	}

	rawInclude := c.DefaultQuery("include_user", "false")
	includeUser := strings.EqualFold(rawInclude, "true") || strings.EqualFold(rawInclude, "1")
	if includeUser {
		summary := newUserSummary(user, roles)
		response.User = &summary
	}

	c.JSON(http.StatusOK, response)
}

func getAccessTokenClaims(c *gin.Context) *security.AccessTokenClaims {
	raw, exists := c.Get("claims")
	if !exists {
		return nil
	}

	claims, ok := raw.(*security.AccessTokenClaims)
	if !ok {
		return nil
	}

	return claims
}

func computeExpiresIn(token string, auth *usecase.AuthService) int {
	if auth == nil {
		return 0
	}
	claims, err := auth.ParseAccessToken(token)
	if err != nil || claims == nil || claims.ExpiresAt == nil {
		return 0
	}

	remaining := time.Until(claims.ExpiresAt.Time)
	if remaining <= 0 {
		return 0
	}

	seconds := int(remaining.Seconds())
	if seconds < 0 {
		return 0
	}

	return seconds
}

// Login godoc
// @Summary Authenticate a user with credentials
// @Description Validates the provided identifier and password, returning access and refresh tokens on success.
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body AuthLoginRequest true "Login request"
// @Success 200 {object} AuthLoginResponse "Successfully authenticated"
// @Failure 400 {object} ErrorResponse "Invalid request payload"
// @Failure 401 {object} ErrorResponse "Invalid credentials"
// @Failure 403 {object} AuthPendingResponse "Account pending verification or inactive"
// @Failure 500 {object} ErrorResponse "Internal server error"
// @Failure 503 {object} ErrorResponse "Service temporarily unavailable"
// @Failure 429 {object} middleware.ProblemDetails "Rate limit exceeded"
// @Router /api/v1/auth/login [post]
func (h *AuthHandler) login(c *gin.Context) {
	var req AuthLoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, NewErrorResponse(c, "invalid login payload"))
		return
	}

	input := usecase.LoginInput{
		Identifier:  strings.TrimSpace(req.Identifier),
		Password:    req.Password,
		DeviceID:    strings.TrimSpace(req.DeviceID),
		DeviceLabel: strings.TrimSpace(req.DeviceLabel),
		IP:          strings.TrimSpace(c.ClientIP()),
		UserAgent:   strings.TrimSpace(c.Request.UserAgent()),
	}

	result, err := h.auth.Login(c.Request.Context(), input)
	if err != nil {
		h.respondLoginError(c, err)
		return
	}

	summary := newUserSummary(result.User, result.Roles)
	session := newSessionSummary(result.Session)

	c.JSON(http.StatusOK, AuthLoginResponse{
		AccessToken:  result.AccessToken,
		RefreshToken: result.RefreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    result.ExpiresIn,
		User:         summary,
		Session:      session,
	})
}

func (h *AuthHandler) respondLoginError(c *gin.Context, err error) {
	var authErr *usecase.AuthenticationError
	if errors.As(err, &authErr) {
		switch {
		case errors.Is(authErr.Err, usecase.ErrAccountPending):
			if authErr.User != nil {
				c.JSON(http.StatusForbidden, AuthPendingResponse{
					Message: "account pending verification",
					User:    newUserSummary(*authErr.User, authErr.Roles),
				})
			} else {
				c.JSON(http.StatusForbidden, NewErrorResponse(c, "account pending verification"))
			}
			return
		case errors.Is(authErr.Err, usecase.ErrInvalidCredentials):
			c.JSON(http.StatusUnauthorized, NewErrorResponse(c, "invalid credentials"))
			return
		case errors.Is(authErr.Err, usecase.ErrInactiveAccount):
			c.JSON(http.StatusForbidden, NewErrorResponse(c, "account inactive"))
			return
		}
	}

	var rateErr *usecase.RateLimitExceededError
	if errors.As(err, &rateErr) {
		respondRateLimitExceeded(c, rateErr)
		return
	}

	switch {
	case errors.Is(err, usecase.ErrInvalidCredentials):
		c.JSON(http.StatusUnauthorized, NewErrorResponse(c, "invalid credentials"))
	case errors.Is(err, usecase.ErrInactiveAccount):
		c.JSON(http.StatusForbidden, NewErrorResponse(c, "account inactive"))
	case errors.Is(err, usecase.ErrRefreshTokenUnavailable):
		c.JSON(http.StatusServiceUnavailable, NewErrorResponse(c, "refresh tokens unavailable"))
	default:
		c.JSON(http.StatusInternalServerError, NewErrorResponse(c, "authentication failed"))
	}
}

func respondRateLimitExceeded(c *gin.Context, rateErr *usecase.RateLimitExceededError) {
	retryAfter := int(rateErr.RetryAfter / time.Second)
	if rateErr.RetryAfter%time.Second != 0 {
		retryAfter++
	}
	if retryAfter < 0 {
		retryAfter = 0
	}

	detail := "Слишком много попыток входа. Попробуйте позже."
	if rateErr.RetryAfter > 0 {
		detail = fmt.Sprintf("Слишком много попыток входа. Попробуйте через %d секунд.", retryAfter)
	}

	instance := c.FullPath()
	if instance == "" {
		instance = c.Request.URL.Path
	}

	problem := middleware.ProblemDetails{
		Type:       loginRateLimitProblemType,
		Title:      loginRateLimitProblemTitle,
		Status:     http.StatusTooManyRequests,
		Detail:     detail,
		Instance:   instance,
		RetryAfter: retryAfter,
		TraceID:    middleware.GetTraceID(c),
	}

	c.JSON(http.StatusTooManyRequests, problem)
}
