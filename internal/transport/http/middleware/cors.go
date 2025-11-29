package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// CORS adds Cross-Origin Resource Sharing headers to responses.
func CORS(allowedOrigins []string) gin.HandlerFunc {
	originsMap := make(map[string]bool)
	allowAll := false

	for _, origin := range allowedOrigins {
		if origin == "*" {
			allowAll = true
			break
		}
		originsMap[origin] = true
	}

	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")

		if allowAll {
			c.Header("Access-Control-Allow-Origin", "*")
		} else if originsMap[origin] {
			c.Header("Access-Control-Allow-Origin", origin)
		}

		if c.Request.Method == http.MethodOptions {
			c.Header("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,HEAD,OPTIONS")
			c.Header("Access-Control-Allow-Headers", "Origin,Content-Type,Accept,Authorization,X-Request-ID,X-Trace-ID")
			c.Header("Access-Control-Allow-Credentials", "true")
			c.Header("Access-Control-Max-Age", "86400")

			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}
