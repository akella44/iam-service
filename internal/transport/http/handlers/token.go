package handlers

import (
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
	handleTokenRefresh(c, h.auth)
}
