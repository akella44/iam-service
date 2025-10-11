package middleware

import (
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

const (
	// TraceIDHeader is the HTTP header name for trace ID
	TraceIDHeader = "X-Trace-ID"
	// TraceIDKey is the context key for trace ID
	TraceIDKey = "trace_id"
	// UserIDKey is the context key for authenticated user ID
	UserIDKey = "user_id"
)

// RequestContext holds request-scoped information
type RequestContext struct {
	TraceID   string
	UserID    string
	IP        string
	UserAgent string
}

// EnrichContext adds trace ID and request context to each request
func EnrichContext() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Check if trace ID already exists in header, otherwise generate one
		traceID := c.GetHeader(TraceIDHeader)
		if traceID == "" {
			traceID = uuid.NewString()
		}

		// Set trace ID in context and response header
		c.Set(TraceIDKey, traceID)
		c.Header(TraceIDHeader, traceID)

		// Store request metadata
		reqCtx := &RequestContext{
			TraceID:   traceID,
			IP:        c.ClientIP(),
			UserAgent: c.Request.UserAgent(),
		}
		c.Set("request_context", reqCtx)

		c.Next()
	}
}

// GetTraceID retrieves the trace ID from the context
func GetTraceID(c *gin.Context) string {
	if traceID, exists := c.Get(TraceIDKey); exists {
		if id, ok := traceID.(string); ok {
			return id
		}
	}
	return ""
}

// GetRequestContext retrieves the full request context
func GetRequestContext(c *gin.Context) *RequestContext {
	if ctx, exists := c.Get("request_context"); exists {
		if reqCtx, ok := ctx.(*RequestContext); ok {
			return reqCtx
		}
	}
	return &RequestContext{}
}
