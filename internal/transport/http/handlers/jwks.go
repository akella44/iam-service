package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/arklim/social-platform-iam/internal/infra/security"
)

const jwksCacheControl = "public, max-age=3600"

// JWKSHandler provides the JSON Web Key Set used for offline JWT validation.
type JWKSHandler struct {
	manager *security.JWTManager
}

// NewJWKSHandler constructs a JWKS handler backed by the supplied manager.
func NewJWKSHandler(manager *security.JWTManager) *JWKSHandler {
	return &JWKSHandler{manager: manager}
}

// Keys godoc
// @Summary Retrieve JSON Web Key Set
// @Description Exposes the public keys used to verify IAM JWT signatures.
// @Tags Public
// @Produce json
// @Success 200 {object} JWKSResponse
// @Failure 500 {object} ErrorResponse
// @Failure 503 {object} ErrorResponse
// @Router /.well-known/jwks.json [get]
func (h *JWKSHandler) Keys(c *gin.Context) {
	if h == nil || h.manager == nil {
		c.JSON(http.StatusServiceUnavailable, NewErrorResponse(c, "jwks not available"))
		return
	}

	payload, err := h.manager.JWKS()
	if err != nil {
		c.JSON(http.StatusInternalServerError, NewErrorResponse(c, "failed to render jwks"))
		return
	}

	c.Header("Cache-Control", jwksCacheControl)
	c.Data(http.StatusOK, "application/json", payload)
}
