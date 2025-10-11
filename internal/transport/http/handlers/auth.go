package handlers

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/arklim/social-platform-iam/internal/core/domain"
	"github.com/arklim/social-platform-iam/internal/usecase"
)

// AuthHandler exposes authentication endpoints.
type AuthHandler struct {
	auth *usecase.AuthService
}

// NewAuthHandler constructs AuthHandler.
func NewAuthHandler(auth *usecase.AuthService) *AuthHandler {
	return &AuthHandler{auth: auth}
}

// RegisterRoutes binds authentication routes.
func (h *AuthHandler) RegisterRoutes(r *gin.RouterGroup) {
	r.POST("/login", h.login)
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
// @Router /api/v1/auth/login [post]
func (h *AuthHandler) login(c *gin.Context) {
	var req AuthLoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, NewErrorResponse(c, "invalid login payload"))
		return
	}

	token, user, roles, err := h.auth.Authenticate(c.Request.Context(), req.Identifier, req.Password)
	if err != nil {
		switch {
		case errors.Is(err, usecase.ErrAccountPending):
			c.JSON(http.StatusForbidden, AuthPendingResponse{
				Message: "account pending verification",
				User:    newUserSummary(user, nil),
			})
		case errors.Is(err, usecase.ErrInvalidCredentials):
			c.JSON(http.StatusUnauthorized, NewErrorResponse(c, "invalid credentials"))
		case errors.Is(err, usecase.ErrInactiveAccount):
			c.JSON(http.StatusForbidden, NewErrorResponse(c, "account inactive"))
		default:
			c.JSON(http.StatusInternalServerError, NewErrorResponse(c, "authentication failed"))
		}
		return
	}

	if user.Status == domain.UserStatusPending {
		c.JSON(http.StatusForbidden, AuthPendingResponse{
			Message: "account pending verification",
			User:    newUserSummary(user, roles),
		})
		return
	}

	refreshToken, _, err := h.auth.IssueRefreshToken(c.Request.Context(), user, map[string]any{"source": "login"})
	if err != nil {
		switch {
		case errors.Is(err, usecase.ErrRefreshTokenUnavailable):
			c.JSON(http.StatusServiceUnavailable, NewErrorResponse(c, "refresh tokens unavailable"))
		default:
			c.JSON(http.StatusInternalServerError, NewErrorResponse(c, "failed to issue refresh token"))
		}
		return
	}

	c.JSON(http.StatusOK, AuthLoginResponse{
		AccessToken:  token,
		TokenType:    "Bearer",
		RefreshToken: refreshToken,
		User:         newUserSummary(user, roles),
	})
}
