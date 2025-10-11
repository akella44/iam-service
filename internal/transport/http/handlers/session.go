package handlers

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/arklim/social-platform-iam/internal/repository"
	"github.com/arklim/social-platform-iam/internal/transport/http/middleware"
	"github.com/arklim/social-platform-iam/internal/usecase"
)

// SessionHandler exposes endpoints for session management and validation.
type SessionHandler struct {
	auth *usecase.AuthService
}

func NewSessionHandler(auth *usecase.AuthService) *SessionHandler {
	return &SessionHandler{auth: auth}
}

// ValidateSession godoc
// @Summary Validate a session
// @Description Checks whether the provided session is still valid.
// @Tags Sessions
// @Accept json
// @Produce json
// @Param request body SessionValidateRequest true "Session validation request"
// @Success 200 {object} SessionValidateResponse
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /api/v1/user/session/validate [post]
func (h *SessionHandler) ValidateSession(c *gin.Context) {
	var req SessionValidateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, NewErrorResponse(c, "session_id is required"))
		return
	}

	session, err := h.auth.ValidateSession(c.Request.Context(), req.SessionID)
	if err != nil {
		switch {
		case errors.Is(err, repository.ErrNotFound):
			c.JSON(http.StatusNotFound, NewErrorResponse(c, "session not found"))
		case errors.Is(err, usecase.ErrSessionRevoked):
			c.JSON(http.StatusUnauthorized, NewErrorResponse(c, "session revoked"))
		case errors.Is(err, usecase.ErrSessionExpired):
			c.JSON(http.StatusUnauthorized, NewErrorResponse(c, "session expired"))
		default:
			c.JSON(http.StatusInternalServerError, NewErrorResponse(c, "failed to validate session"))
		}
		return
	}

	c.JSON(http.StatusOK, SessionValidateResponse{
		Valid:   true,
		Session: newSessionPayload(*session),
	})
}

// ListSessions godoc
// @Summary List active sessions for authenticated user
// @Description Retrieves all active sessions for the authenticated user.
// @Tags Sessions
// @Security Bearer
// @Produce json
// @Param Authorization header string true "Bearer access token"
// @Success 200 {object} SessionListResponse
// @Failure 401 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /api/v1/user/session/list [get]
func (h *SessionHandler) ListSessions(c *gin.Context) {
	// Get authenticated user ID from middleware
	userIDStr, ok := middleware.GetAuthenticatedUserID(c)
	if !ok || userIDStr == "" {
		c.JSON(http.StatusUnauthorized, NewErrorResponse(c, "invalid authentication"))
		return
	}

	sessions, err := h.auth.ListActiveSessions(c.Request.Context(), userIDStr)
	if err != nil {
		c.JSON(http.StatusInternalServerError, NewErrorResponse(c, "failed to list sessions"))
		return
	}

	response := make([]SessionPayload, 0, len(sessions))
	for _, session := range sessions {
		payload := newSessionPayload(session)
		response = append(response, payload)
	}

	c.JSON(http.StatusOK, SessionListResponse{Sessions: response})
}

//TODO: make blacklist when used nonactive refresh token

// RevokeSession godoc
// @Summary Revoke a session
// @Description Revokes an active session using its identifier.
// @Tags Sessions
// @Security Bearer
// @Accept json
// @Produce json
// @Param Authorization header string true "Bearer access token"
// @Param request body SessionRevokeRequest true "Session revoke request"
// @Success 200 {object} SessionRevokeResponse
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /api/v1/user/session/revoke [post]
func (h *SessionHandler) RevokeSession(c *gin.Context) {
	var req SessionRevokeRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, NewErrorResponse(c, "session_id is required"))
		return
	}

	if err := h.auth.RevokeSession(c.Request.Context(), req.SessionID, req.Reason); err != nil {
		switch {
		case errors.Is(err, repository.ErrNotFound):
			c.JSON(http.StatusNotFound, NewErrorResponse(c, "session not found"))
		default:
			c.JSON(http.StatusInternalServerError, NewErrorResponse(c, "failed to revoke session"))
		}
		return
	}

	c.JSON(http.StatusOK, SessionRevokeResponse{Revoked: true})
}
