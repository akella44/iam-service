package middleware

import (
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// Logger emits access logs for every HTTP request with trace ID.
func Logger(log *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()

		c.Next()

		latency := time.Since(start)
		status := c.Writer.Status()
		traceID := GetTraceID(c)

		fields := []zap.Field{
			zap.String("trace_id", traceID),
			zap.Int("status", status),
			zap.String("method", c.Request.Method),
			zap.String("path", c.Request.URL.Path),
			zap.Duration("latency", latency),
			zap.String("client_ip", c.ClientIP()),
		}

		if len(c.Errors) > 0 {
			log.Error("request failed", append(fields, zap.String("errors", c.Errors.String()))...)
			return
		}

		log.Info("request completed", fields...)
	}
}
