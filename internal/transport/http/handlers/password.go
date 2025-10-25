package handlers

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	uuid "github.com/google/uuid"

	"github.com/arklim/social-platform-iam/internal/transport/http/middleware"
	"github.com/arklim/social-platform-iam/internal/usecase"
)

// PasswordHandler exposes endpoints for password management.
type PasswordHandler struct {
	reset      *usecase.PasswordResetService
	dispatcher NotificationDispatcher
	isDev      bool
}

func NewPasswordHandler(reset *usecase.PasswordResetService, dispatcher NotificationDispatcher, isDev bool) *PasswordHandler {
	if dispatcher == nil {
		dispatcher = noopDispatcher{}
	}
	return &PasswordHandler{
		reset:      reset,
		dispatcher: dispatcher,
		isDev:      isDev,
	}
}

// ChangePassword godoc
// @Summary Change the password for an authenticated user
// @Description Updates the password for the current user or a delegated user when permitted.
// @Tags Password
// @Accept json
// @Produce json
// @Param Authorization header string true "Bearer access token"
// @Param request body PasswordChangeRequest true "Password change request"
// @Success 200 {object} PasswordChangeResponse
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Failure 403 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 503 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /api/v1/password/change [post]
func (h *PasswordHandler) ChangePassword(c *gin.Context) {
	if h.reset == nil {
		c.JSON(http.StatusServiceUnavailable, NewErrorResponse(c, "password handler not fully configured"))
		return
	}

	// Get authenticated user ID from middleware
	actorIDStr, ok := middleware.GetAuthenticatedUserID(c)
	if !ok || actorIDStr == "" {
		c.JSON(http.StatusUnauthorized, NewErrorResponse(c, "invalid authentication"))
		return
	}

	actorID := strings.TrimSpace(actorIDStr)

	var req PasswordChangeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, NewErrorResponse(c, "invalid change password payload"))
		return
	}

	targetUserID := strings.TrimSpace(req.UserID)
	if targetUserID == "" {
		targetUserID = actorID
	}

	input := usecase.PasswordChangeInput{
		UserID:          targetUserID,
		ActorID:         actorID,
		CurrentPassword: req.CurrentPassword,
		NewPassword:     req.NewPassword,
		IP:              c.ClientIP(),
		UserAgent:       c.GetHeader("User-Agent"),
	}

	result, err := h.reset.ChangePassword(c.Request.Context(), input)
	if err != nil {
		RespondWithMappedError(c, err, []ErrorCase{
			{Err: usecase.ErrCurrentPasswordRequired, Status: http.StatusBadRequest, Message: "current password is required"},
			{Err: usecase.ErrCurrentPasswordInvalid, Status: http.StatusUnauthorized, Message: "current password is incorrect"},
			{Err: usecase.ErrNewPasswordInvalid, Status: http.StatusBadRequest, Message: "new password is invalid"},
			{Err: usecase.ErrPermissionDenied, Status: http.StatusForbidden, Message: "insufficient permissions"},
			{Err: usecase.ErrUserNotFound, Status: http.StatusNotFound, Message: "user not found"},
			{Err: usecase.ErrPasswordResetUnavailable, Status: http.StatusServiceUnavailable, Message: "password reset unavailable"},
		}, http.StatusInternalServerError, "failed to change password")
		return
	}

	if result == nil {
		c.JSON(http.StatusInternalServerError, NewErrorResponse(c, "password change result unavailable"))
		return
	}

	c.JSON(http.StatusOK, PasswordChangeResponse{
		Message:         "Password changed successfully",
		ChangedAt:       result.ChangedAt,
		RevokedSessions: result.SessionsRevoked,
		RevokedTokens:   result.TokensRevoked,
	})
}

// ResetPassword godoc
// @Summary Initiate a password reset
// @Description Starts the password reset flow and always returns an accepted response to avoid account enumeration.
// @Tags Password
// @Accept json
// @Produce json
// @Param request body PasswordResetRequest true "Password reset request"
// @Success 202 {object} PasswordResetResponse
// @Failure 400 {object} ErrorResponse
// @Failure 429 {object} ErrorResponse
// @Failure 503 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /api/v1/password/reset/request [post]
func (h *PasswordHandler) ResetPassword(c *gin.Context) {
	if h.reset == nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "password reset handler not configured"})
		return
	}

	var req PasswordResetRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "invalid password reset request"})
		return
	}

	input := usecase.PasswordResetRequestInput{
		Identifier: strings.TrimSpace(req.EmailOrPhone),
		IP:         c.ClientIP(),
		UserAgent:  c.GetHeader("User-Agent"),
	}

	result, err := h.reset.RequestPasswordReset(c.Request.Context(), input)
	if err != nil {
		if errors.Is(err, usecase.ErrUserNotFound) {
			response := PasswordResetResponse{
				Message:   "If the account exists, instructions have been sent",
				RequestID: uuid.NewString(),
			}
			c.JSON(http.StatusAccepted, response)
			return
		}

		var rateErr *usecase.RateLimitExceededError
		if errors.As(err, &rateErr) {
			retryAfter := int(rateErr.RetryAfter.Round(time.Second) / time.Second)
			if retryAfter > 0 {
				c.Header("Retry-After", strconv.Itoa(retryAfter))
			}
			c.JSON(http.StatusTooManyRequests, ErrorResponse{Error: "too many password reset requests"})
			return
		}

		if errors.Is(err, usecase.ErrPasswordResetContactMissing) {
			c.JSON(http.StatusBadRequest, ErrorResponse{Error: "no contact method available"})
			return
		}

		if errors.Is(err, usecase.ErrPasswordResetUnavailable) {
			c.JSON(http.StatusServiceUnavailable, ErrorResponse{Error: "password reset unavailable"})
			return
		}

		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "failed to initiate password reset"})
		return
	}

	response := PasswordResetResponse{
		Message:           "If the account exists, instructions have been sent",
		RequestID:         result.RequestID,
		Delivery:          result.Delivery,
		MaskedDestination: maskResetDestination(result.Delivery, result.Contact),
	}

	expires := result.ExpiresAt
	response.ExpiresAt = &expires

	// SECURITY: Only expose raw tokens/codes in development mode
	// In production, reset credentials should only be sent via secure channels
	if h.isDev {
		if token := strings.TrimSpace(result.Token); token != "" {
			response.DevToken = &token
		}
		if code := strings.TrimSpace(result.Code); code != "" {
			response.DevCode = &code
		}
	}

	h.dispatchReset(c.Request.Context(), result)

	c.JSON(http.StatusAccepted, response)
}

// ConfirmReset godoc
// @Summary Complete a password reset
// @Description Finalizes the password reset using a token or verification code.
// @Tags Password
// @Accept json
// @Produce json
// @Param request body PasswordResetConfirmRequest true "Password reset confirm request"
// @Success 200 {object} PasswordResetConfirmResponse
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 503 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /api/v1/password/reset/confirm [post]
func (h *PasswordHandler) ConfirmReset(c *gin.Context) {
	if h.reset == nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "password reset handler not configured"})
		return
	}

	var req PasswordResetConfirmRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "invalid confirm reset request"})
		return
	}

	token := strings.TrimSpace(req.Token)
	code := strings.TrimSpace(req.Code)
	if token == "" && code == "" {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "token or code is required"})
		return
	}

	input := usecase.PasswordResetConfirmInput{
		Token:       token,
		Code:        code,
		NewPassword: req.NewPassword,
		IP:          c.ClientIP(),
		UserAgent:   c.GetHeader("User-Agent"),
	}

	result, err := h.reset.ConfirmPasswordReset(c.Request.Context(), input)
	if err != nil {
		if errors.Is(err, usecase.ErrPasswordResetTokenInvalid) {
			c.JSON(http.StatusBadRequest, ErrorResponse{Error: "password reset credential invalid"})
			return
		}
		if errors.Is(err, usecase.ErrPasswordResetTokenExpired) {
			c.JSON(http.StatusBadRequest, ErrorResponse{Error: "password reset credential expired"})
			return
		}
		if errors.Is(err, usecase.ErrNewPasswordInvalid) {
			c.JSON(http.StatusBadRequest, ErrorResponse{Error: "new password invalid"})
			return
		}
		if errors.Is(err, usecase.ErrUserNotFound) {
			c.JSON(http.StatusNotFound, ErrorResponse{Error: "user not found"})
			return
		}
		if errors.Is(err, usecase.ErrPasswordResetUnavailable) {
			c.JSON(http.StatusServiceUnavailable, ErrorResponse{Error: "password reset unavailable"})
			return
		}

		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "failed to confirm password reset"})
		return
	}

	if result == nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "password reset result unavailable"})
		return
	}

	c.JSON(http.StatusOK, PasswordResetConfirmResponse{
		Message:         "Password reset successful",
		UserID:          result.UserID,
		ChangedAt:       result.ChangedAt,
		RevokedSessions: result.SessionsRevoked,
		RevokedTokens:   result.TokensRevoked,
	})
}

func (h *PasswordHandler) dispatchReset(ctx context.Context, result *usecase.ResetInitiationResult) {
	if h.dispatcher == nil || result == nil {
		return
	}

	payload := PasswordResetNotification{
		Delivery: result.Delivery,
		Contact:  strings.TrimSpace(result.Contact),
		Expires:  result.ExpiresAt,
	}

	if h.isDev {
		payload.DevToken = strings.TrimSpace(result.Token)
		payload.DevCode = strings.TrimSpace(result.Code)
	}

	_ = h.dispatcher.SendPasswordReset(ctx, payload)
}

func maskResetDestination(delivery, value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}

	switch strings.ToLower(strings.TrimSpace(delivery)) {
	case "email":
		if idx := strings.Index(trimmed, "@"); idx > 0 {
			local := trimmed[:idx]
			domainPart := trimmed[idx:]
			if len(local) <= 3 {
				return "***" + domainPart
			}
			return local[:3] + "***" + domainPart
		}
		if len(trimmed) <= 3 {
			return "***"
		}
		return trimmed[:3] + "***"
	case "sms", "phone":
		runes := []rune(trimmed)
		if len(runes) <= 4 {
			return "***"
		}
		prefix := string(runes[:minInt(len(runes)-4, 4)])
		suffix := string(runes[len(runes)-4:])
		return prefix + "***" + suffix
	default:
		if len(trimmed) <= 3 {
			return "***"
		}
		return trimmed[:3] + "***"
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
