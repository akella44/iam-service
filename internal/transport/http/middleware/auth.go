package middleware

import (
	"errors"
	"net/http"
	"strings"

	"github.com/arklim/social-platform-iam/internal/usecase"
	"github.com/gin-gonic/gin"
)

// ErrorResponse matches the handlers.ErrorResponse structure
type ErrorResponse struct {
	Error   string `json:"error"`
	TraceID string `json:"trace_id,omitempty"`
}

// newErrorResponse creates an error response with trace ID
func newErrorResponse(c *gin.Context, errorMsg string) ErrorResponse {
	return ErrorResponse{
		Error:   errorMsg,
		TraceID: GetTraceID(c),
	}
}

// RequireAuth validates the Authorization header and extracts user claims
func RequireAuth(authService *usecase.AuthService) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized,
				newErrorResponse(c, "missing authorization header"))
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 {
			c.AbortWithStatusJSON(http.StatusUnauthorized,
				newErrorResponse(c, "invalid authorization format: expected 'Bearer <token>'"))
			return
		}

		if !strings.EqualFold(parts[0], "Bearer") {
			c.AbortWithStatusJSON(http.StatusUnauthorized,
				newErrorResponse(c, "invalid authorization format: must start with 'Bearer'"))
			return
		}

		token := strings.TrimSpace(parts[1])
		if token == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized,
				newErrorResponse(c, "missing access token"))
			return
		}

		claims, err := authService.ParseAccessToken(c.Request.Context(), token)
		if err != nil {
			switch {
			case errors.Is(err, usecase.ErrExpiredAccessToken):
				c.AbortWithStatusJSON(http.StatusUnauthorized,
					newErrorResponse(c, "access token expired"))
			case errors.Is(err, usecase.ErrInvalidAccessToken):
				c.AbortWithStatusJSON(http.StatusUnauthorized,
					newErrorResponse(c, "invalid access token"))
			default:
				c.AbortWithStatusJSON(http.StatusInternalServerError,
					newErrorResponse(c, "authentication failed"))
			}
			return
		}

		// Store user information in context
		c.Set(UserIDKey, claims.UserID)
		c.Set("claims", claims)
		c.Set("roles", claims.Roles)

		// Update request context with user ID
		if reqCtx := GetRequestContext(c); reqCtx != nil {
			reqCtx.UserID = claims.UserID
		}

		c.Next()
	}
}

// RequireRole checks if the authenticated user has any of the specified roles
func RequireRole(roles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		rolesVal, exists := c.Get("roles")
		if !exists {
			c.AbortWithStatusJSON(http.StatusUnauthorized,
				newErrorResponse(c, "authentication required"))
			return
		}

		userRoles, ok := rolesVal.([]string)
		if !ok {
			c.AbortWithStatusJSON(http.StatusInternalServerError,
				newErrorResponse(c, "invalid roles format"))
			return
		}

		if !hasAnyRole(userRoles, roles) {
			c.AbortWithStatusJSON(http.StatusForbidden,
				newErrorResponse(c, "insufficient permissions"))
			return
		}

		c.Next()
	}
}

// hasAnyRole checks if the user has any of the required roles
func hasAnyRole(userRoles []string, requiredRoles []string) bool {
	roleMap := make(map[string]bool, len(userRoles))
	for _, role := range userRoles {
		roleMap[role] = true
	}

	for _, required := range requiredRoles {
		if roleMap[required] {
			return true
		}
	}
	return false
}

// GetAuthenticatedUserID retrieves the user ID from context (helper for handlers)
func GetAuthenticatedUserID(c *gin.Context) (string, bool) {
	userID, exists := c.Get(UserIDKey)
	if !exists {
		return "", false
	}

	if id, ok := userID.(string); ok {
		return id, true
	}

	return "", false
}
