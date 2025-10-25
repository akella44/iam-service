package middleware

import (
	"context"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	appLogger "github.com/arklim/social-platform-iam/internal/infra/logger"
)

// Logger emits access logs for every HTTP request with correlation identifiers and masked PII.
func Logger(log *zap.Logger) gin.HandlerFunc {
	if log == nil {
		log = zap.NewNop()
	}

	return func(c *gin.Context) {
		start := time.Now()

		c.Next()

		latency := time.Since(start)
		status := c.Writer.Status()
		traceID := GetTraceID(c)
		requestID := requestIDFromContext(c.Request.Context())
		clientIP := appLogger.MaskIP(c.ClientIP())

		if requestID != "" {
			c.Set("request_id", requestID)
		}

		fields := []zap.Field{
			zap.String("trace_id", traceID),
			zap.String("request_id", requestID),
			zap.Int("status", status),
			zap.String("method", c.Request.Method),
			zap.String("path", c.Request.URL.Path),
			zap.Duration("latency", latency),
			zap.String("client_ip", clientIP),
		}

		if ua := c.Request.UserAgent(); ua != "" {
			fields = append(fields, zap.String("user_agent", ua))
		}

		if len(c.Errors) > 0 {
			log.Error("request failed", append(fields, zap.String("errors", c.Errors.String()))...)
			return
		}

		log.Info("request completed", fields...)
	}
}

func requestIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	if id, ok := ctx.Value(appLogger.RequestIDKey{}).(string); ok {
		return id
	}
	return ""
}
