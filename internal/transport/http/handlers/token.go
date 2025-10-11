package handlers

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/arklim/social-platform-iam/internal/usecase"
)

// TokenHandler exposes endpoints for JWT issuance and refresh.
type TokenHandler struct {
	auth *usecase.AuthService
}

func NewTokenHandler(auth *usecase.AuthService) *TokenHandler {
	return &TokenHandler{auth: auth}
}

// RegisterRoutes binds token endpoints.
func (h *TokenHandler) RegisterRoutes(r *gin.RouterGroup) {
	r.POST("/token/refresh", h.RefreshToken)
}

// RefreshToken godoc
// @Summary Refresh an access token
// @Description Issues a new access token using a valid refresh token.
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
// @Router /api/v1/auth/token/refresh [post]
func (h *TokenHandler) RefreshToken(c *gin.Context) {
	var req TokenRefreshRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "refresh_token is required"})
		return
	}

	accessToken, newRefreshToken, user, roles, err := h.auth.RefreshAccessToken(c.Request.Context(), req.RefreshToken)
	if err != nil {
		switch {
		case errors.Is(err, usecase.ErrInvalidRefreshToken):
			c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "invalid refresh token"})
		case errors.Is(err, usecase.ErrExpiredRefreshToken):
			c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "refresh token expired"})
		case errors.Is(err, usecase.ErrInactiveAccount):
			c.JSON(http.StatusForbidden, ErrorResponse{Error: "account inactive"})
		case errors.Is(err, usecase.ErrAccountPending):
			c.JSON(http.StatusConflict, ErrorResponse{Error: "account pending verification"})
		case errors.Is(err, usecase.ErrRefreshTokenUnavailable):
			c.JSON(http.StatusServiceUnavailable, ErrorResponse{Error: "refresh tokens unavailable"})
		default:
			c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "failed to refresh token"})
		}
		return
	}

	response := TokenRefreshResponse{
		AccessToken:  accessToken,
		RefreshToken: newRefreshToken,
		TokenType:    "Bearer",
	}

	rawInclude := c.DefaultQuery("include_user", "false")
	includeUser := strings.EqualFold(rawInclude, "true") || strings.EqualFold(rawInclude, "1")
	if includeUser {
		summary := newUserSummary(user, roles)
		response.User = &summary
	}

	c.JSON(http.StatusOK, response)
}
