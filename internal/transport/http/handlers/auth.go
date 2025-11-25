package handlers

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

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
	auth *usecase.AuthService
}

// NewAuthHandler constructs AuthHandler.
func NewAuthHandler(auth *usecase.AuthService) *AuthHandler {
	return &AuthHandler{auth: auth}
}

// RegisterRoutes binds authentication routes, applying optional middleware ahead of handlers.
func (h *AuthHandler) RegisterRoutes(r *gin.RouterGroup, loginMiddlewares ...gin.HandlerFunc) {
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
// @Failure 401 {object} middleware.ProblemDetails "Refresh token stale"
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
		var versionErr *usecase.SessionVersionMismatchError
		if errors.As(err, &versionErr) {
			respondStaleRefreshToken(c, versionErr)
			return
		}
		cases := []ErrorCase{
			{Err: usecase.ErrInvalidRefreshToken, Status: http.StatusUnauthorized, Message: "invalid refresh token"},
			{Err: usecase.ErrExpiredRefreshToken, Status: http.StatusUnauthorized, Message: "refresh token expired"},
			{Err: usecase.ErrInactiveAccount, Status: http.StatusForbidden, Message: "account inactive"},
			{Err: usecase.ErrAccountPending, Status: http.StatusConflict, Message: "account pending verification"},
			{Err: usecase.ErrRefreshTokenUnavailable, Status: http.StatusServiceUnavailable, Message: "refresh tokens unavailable"},
			{Err: usecase.ErrRefreshTokenReplay, Status: http.StatusConflict, Message: "refresh token replay detected"},
			{Err: usecase.ErrSessionRevoked, Status: http.StatusUnauthorized, Message: "session revoked"},
			{Err: usecase.ErrSessionExpired, Status: http.StatusUnauthorized, Message: "session expired"},
		}
		RespondWithMappedError(c, err, cases, http.StatusInternalServerError, "failed to refresh token")
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
	claims, err := auth.ParseAccessToken(context.Background(), token)
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

func respondStaleRefreshToken(c *gin.Context, details *usecase.SessionVersionMismatchError) {
	if c == nil {
		return
	}

	instance := c.FullPath()
	if instance == "" {
		instance = c.Request.URL.Path
	}

	problem := middleware.ProblemDetails{
		Type:     "iam/token-stale",
		Title:    "Refresh Token Stale",
		Status:   http.StatusUnauthorized,
		Detail:   "refresh token is stale; re-authentication required",
		Instance: instance,
		TraceID:  middleware.GetTraceID(c),
		Extensions: map[string]any{
			"session_id":      strings.TrimSpace(details.SessionID),
			"token_version":   details.TokenVersion,
			"session_version": details.CurrentVersion,
		},
	}

	c.JSON(http.StatusUnauthorized, problem)
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
