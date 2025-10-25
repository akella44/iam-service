package handlers

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

const defaultReadinessTimeout = 2 * time.Second

// HealthHandler exposes liveness and readiness information.
type HealthHandler struct {
	startedAt        time.Time
	readinessTimeout time.Duration
	readinessChecks  map[string]func(context.Context) error
}

// HealthOption configures optional behaviour for HealthHandler.
type HealthOption func(*HealthHandler)

// WithReadinessCheck registers a named readiness probe executed on /readyz.
func WithReadinessCheck(name string, check func(context.Context) error) HealthOption {
	return func(h *HealthHandler) {
		if name == "" || check == nil {
			return
		}
		h.readinessChecks[name] = check
	}
}

// WithReadinessTimeout overrides the default timeout used for readiness checks.
func WithReadinessTimeout(timeout time.Duration) HealthOption {
	return func(h *HealthHandler) {
		if timeout > 0 {
			h.readinessTimeout = timeout
		}
	}
}

// NewHealthHandler builds a new health handler instance.
func NewHealthHandler(opts ...HealthOption) *HealthHandler {
	handler := &HealthHandler{
		startedAt:        time.Now().UTC(),
		readinessTimeout: defaultReadinessTimeout,
		readinessChecks:  make(map[string]func(context.Context) error),
	}

	for _, opt := range opts {
		opt(handler)
	}

	return handler
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
		Timestamp: time.Now().UTC(),
	})
}

// Readiness godoc
// @Summary Service readiness check
// @Description Returns readiness status including dependency checks.
// @Tags Health
// @Produce json
// @Success 200 {object} ReadyResponse
// @Failure 503 {object} ReadyResponse
// @Router /readyz [get]
func (h *HealthHandler) Readiness(c *gin.Context) {
	if len(h.readinessChecks) == 0 {
		c.JSON(http.StatusOK, ReadyResponse{
			Status:    "ready",
			Timestamp: time.Now().UTC(),
		})
		return
	}

	results := make(map[string]string, len(h.readinessChecks))
	ready := true

	for name, check := range h.readinessChecks {
		ctx, cancel := context.WithTimeout(c.Request.Context(), h.readinessTimeout)
		err := check(ctx)
		cancel()

		if err != nil {
			ready = false
			results[name] = fmt.Sprintf("error: %v", err)
			continue
		}
		results[name] = "ok"
	}

	response := ReadyResponse{
		Status:    "ready",
		Checks:    results,
		Timestamp: time.Now().UTC(),
	}

	if !ready {
		response.Status = "not_ready"
		c.JSON(http.StatusServiceUnavailable, response)
		return
	}

	c.JSON(http.StatusOK, response)
}
