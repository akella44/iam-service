package handlers

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/arklim/social-platform-iam/internal/repository"
	"github.com/arklim/social-platform-iam/internal/transport/http/middleware"
	"github.com/arklim/social-platform-iam/internal/usecase"
)

// SessionHandler exposes endpoints for session management and validation.
type SessionHandler struct {
	auth     *usecase.AuthService
	sessions *usecase.SessionService
}

// NewSessionHandler constructs a session handler.
func NewSessionHandler(auth *usecase.AuthService, sessions *usecase.SessionService) *SessionHandler {
	return &SessionHandler{auth: auth, sessions: sessions}
}

// RegisterRoutes binds REST session management routes to the provided router group.
func (h *SessionHandler) RegisterRoutes(r *gin.RouterGroup) {
	if r == nil {
		return
	}

	r.GET("", h.ListSessions)
	r.DELETE("/others", h.RevokeOtherSessions)
	r.DELETE("/:session_id", h.RevokeSession)
	r.DELETE("", h.RevokeAllSessions)
	r.POST("/validate", h.ValidateSession)
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
// @Router /api/v1/sessions/validate [post]
func (h *SessionHandler) ValidateSession(c *gin.Context) {
	if h.auth == nil {
		c.JSON(http.StatusServiceUnavailable, NewErrorResponse(c, "session validation unavailable"))
		return
	}

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
// @Summary List sessions for authenticated user
// @Description Retrieves sessions for the authenticated user with optional filtering.
// @Tags Sessions
// @Security Bearer
// @Produce json
// @Param Authorization header string true "Bearer access token"
// @Param active_only query bool false "When true (default) only active sessions are returned"
// @Success 200 {object} SessionListResponse
// @Failure 401 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /api/v1/sessions [get]
func (h *SessionHandler) ListSessions(c *gin.Context) {
	if h.sessions == nil {
		c.JSON(http.StatusServiceUnavailable, NewErrorResponse(c, "session service unavailable"))
		return
	}

	userID, ok := middleware.GetAuthenticatedUserID(c)
	if !ok || userID == "" {
		c.JSON(http.StatusUnauthorized, NewErrorResponse(c, "authentication required"))
		return
	}

	activeOnly := true
	if raw := c.Query("active_only"); raw != "" {
		if parsed, err := strconv.ParseBool(raw); err == nil {
			activeOnly = parsed
		}
	}

	sessions, err := h.sessions.ListSessions(c.Request.Context(), userID, activeOnly)
	if err != nil {
		cases := []ErrorCase{{Err: usecase.ErrSessionNotFound, Status: http.StatusNotFound, Message: "session not found"}}
		RespondWithMappedError(c, err, cases, http.StatusInternalServerError, "failed to list sessions")
		return
	}

	currentSessionID := ""
	if claims := getAccessTokenClaims(c); claims != nil {
		currentSessionID = strings.TrimSpace(claims.SessionID)
	}

	response := make([]SessionPayload, 0, len(sessions))
	for _, session := range sessions {
		payload := newSessionPayload(session)
		if currentSessionID != "" && session.ID == currentSessionID {
			payload.IsCurrent = true
		}
		response = append(response, payload)
	}

	c.JSON(http.StatusOK, SessionListResponse{Sessions: response, Total: len(response)})
}

// RevokeSession godoc
// @Summary Revoke a specific session
// @Description Revokes an active session owned by the authenticated user.
// @Tags Sessions
// @Security Bearer
// @Produce json
// @Param Authorization header string true "Bearer access token"
// @Param session_id path string true "Session identifier"
// @Param reason query string false "Optional revocation reason"
// @Success 204 "Session revoked"
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Failure 403 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /api/v1/sessions/{session_id} [delete]
func (h *SessionHandler) RevokeSession(c *gin.Context) {
	if h.sessions == nil {
		c.JSON(http.StatusServiceUnavailable, NewErrorResponse(c, "session service unavailable"))
		return
	}

	userID, ok := middleware.GetAuthenticatedUserID(c)
	if !ok || userID == "" {
		c.JSON(http.StatusUnauthorized, NewErrorResponse(c, "authentication required"))
		return
	}

	sessionID := strings.TrimSpace(c.Param("session_id"))
	if sessionID == "" {
		c.JSON(http.StatusBadRequest, NewErrorResponse(c, "session_id is required"))
		return
	}

	reason := strings.TrimSpace(c.Query("reason"))
	_, _, err := h.sessions.RevokeSession(c.Request.Context(), userID, sessionID, reason, userID)
	if err != nil {
		if errors.Is(err, usecase.ErrSessionAlreadyRevoked) {
			c.Status(http.StatusNoContent)
			return
		}
		cases := []ErrorCase{
			{Err: usecase.ErrSessionForbidden, Status: http.StatusForbidden, Message: "session not owned by user"},
			{Err: usecase.ErrSessionNotFound, Status: http.StatusNotFound, Message: "session not found"},
		}
		RespondWithMappedError(c, err, cases, http.StatusInternalServerError, "failed to revoke session")
		return
	}

	c.Status(http.StatusNoContent)
}

// RevokeAllSessions godoc
// @Summary Revoke all sessions
// @Description Revokes all active sessions for the authenticated user (including the current one).
// @Tags Sessions
// @Security Bearer
// @Produce json
// @Param Authorization header string true "Bearer access token"
// @Param all query bool true "Must be true to confirm bulk revocation"
// @Param reason query string false "Optional revocation reason"
// @Success 200 {object} SessionBulkRevokeResponse
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /api/v1/sessions [delete]
func (h *SessionHandler) RevokeAllSessions(c *gin.Context) {
	if h.sessions == nil {
		c.JSON(http.StatusServiceUnavailable, NewErrorResponse(c, "session service unavailable"))
		return
	}

	userID, ok := middleware.GetAuthenticatedUserID(c)
	if !ok || userID == "" {
		c.JSON(http.StatusUnauthorized, NewErrorResponse(c, "authentication required"))
		return
	}

	confirm, err := strconv.ParseBool(c.DefaultQuery("all", "false"))
	if err != nil || !confirm {
		c.JSON(http.StatusBadRequest, NewErrorResponse(c, "query parameter all=true required"))
		return
	}

	reason := strings.TrimSpace(c.Query("reason"))
	count, tokens, revokeErr := h.sessions.RevokeAllSessions(c.Request.Context(), userID, reason, userID)
	if revokeErr != nil {
		RespondWithMappedError(c, revokeErr, nil, http.StatusInternalServerError, "failed to revoke sessions")
		return
	}

	c.JSON(http.StatusOK, SessionBulkRevokeResponse{
		RevokedCount:  count,
		TokensRevoked: tokens,
	})
}

// RevokeOtherSessions godoc
// @Summary Revoke all other sessions
// @Description Revokes all active sessions except the current session.
// @Tags Sessions
// @Security Bearer
// @Produce json
// @Param Authorization header string true "Bearer access token"
// @Param reason query string false "Optional revocation reason"
// @Success 200 {object} SessionBulkRevokeResponse
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /api/v1/sessions/others [delete]
func (h *SessionHandler) RevokeOtherSessions(c *gin.Context) {
	if h.sessions == nil {
		c.JSON(http.StatusServiceUnavailable, NewErrorResponse(c, "session service unavailable"))
		return
	}

	userID, ok := middleware.GetAuthenticatedUserID(c)
	if !ok || userID == "" {
		c.JSON(http.StatusUnauthorized, NewErrorResponse(c, "authentication required"))
		return
	}

	claims := getAccessTokenClaims(c)
	if claims == nil || strings.TrimSpace(claims.SessionID) == "" {
		c.JSON(http.StatusBadRequest, NewErrorResponse(c, "current session unknown"))
		return
	}

	reason := strings.TrimSpace(c.Query("reason"))
	count, tokens, err := h.sessions.RevokeAllExceptCurrent(c.Request.Context(), userID, strings.TrimSpace(claims.SessionID), reason, userID)
	if err != nil {
		cases := []ErrorCase{{Err: usecase.ErrSessionNotFound, Status: http.StatusNotFound, Message: "session not found"}}
		RespondWithMappedError(c, err, cases, http.StatusInternalServerError, "failed to revoke other sessions")
		return
	}

	c.JSON(http.StatusOK, SessionBulkRevokeResponse{
		RevokedCount:  count,
		TokensRevoked: tokens,
	})
}
