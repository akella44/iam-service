package middleware

import (
	"context"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/arklim/social-platform-iam/internal/infra/logger"
)

const requestIDHeader = "X-Request-ID"

// RequestID injects a correlation identifier into the context and headers.
func RequestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		reqID := c.GetHeader(requestIDHeader)
		if reqID == "" {
			reqID = uuid.NewString()
		}

		c.Writer.Header().Set(requestIDHeader, reqID)
		ctx := context.WithValue(c.Request.Context(), logger.RequestIDKey{}, reqID)
		c.Request = c.Request.WithContext(ctx)

		c.Next()
	}
}
