package handlers

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// HealthHandler exposes liveness information.
type HealthHandler struct {
	startedAt time.Time
}

// NewHealthHandler builds a new health handler instance.
func NewHealthHandler() *HealthHandler {
	return &HealthHandler{startedAt: time.Now().UTC()}
}

// Status godoc
// @Summary Service health check
// @Description Returns the status and start time of the service.
// @Tags Health
// @Produce json
// @Success 200 {object} HealthResponse
// @Router /healthz [get]
func (h *HealthHandler) Status(c *gin.Context) {
	c.JSON(http.StatusOK, HealthResponse{
		Status:    "ok",
		StartedAt: h.startedAt,
	})
}
