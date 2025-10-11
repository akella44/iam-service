package handlers

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/arklim/social-platform-iam/internal/transport/http/middleware"
	"github.com/arklim/social-platform-iam/internal/usecase"
)

// PasswordHandler exposes endpoints for password management.
type PasswordHandler struct {
	users      *usecase.UserService
	auth       *usecase.AuthService
	reset      *usecase.PasswordResetService
	dispatcher NotificationDispatcher
	isDev      bool
}

func NewPasswordHandler(users *usecase.UserService, auth *usecase.AuthService, reset *usecase.PasswordResetService, dispatcher NotificationDispatcher, isDev bool) *PasswordHandler {
	if dispatcher == nil {
		dispatcher = noopDispatcher{}
	}
	return &PasswordHandler{
		users:      users,
		auth:       auth,
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
// @Failure 500 {object} ErrorResponse
// @Router /api/v1/user/password/change [post]
func (h *PasswordHandler) ChangePassword(c *gin.Context) {
	if h.users == nil {
		c.JSON(http.StatusInternalServerError, NewErrorResponse(c, "password handler not fully configured"))
		return
	}

	// Get authenticated user ID from middleware
	actorIDStr, ok := middleware.GetAuthenticatedUserID(c)
	if !ok || actorIDStr == "" {
		c.JSON(http.StatusUnauthorized, NewErrorResponse(c, "invalid authentication"))
		return
	}

	var req PasswordChangeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, NewErrorResponse(c, "invalid change password payload"))
		return
	}

	input := usecase.ChangePasswordInput{
		TargetUserID:    strings.TrimSpace(req.UserID),
		CurrentPassword: req.CurrentPassword,
		NewPassword:     req.NewPassword,
	}

	if err := h.users.ChangePassword(c.Request.Context(), actorIDStr, input); err != nil {
		RespondWithMappedError(c, err, []ErrorCase{
			{Err: usecase.ErrCurrentPasswordRequired, Status: http.StatusBadRequest, Message: "current password is required"},
			{Err: usecase.ErrCurrentPasswordInvalid, Status: http.StatusUnauthorized, Message: "current password is incorrect"},
			{Err: usecase.ErrNewPasswordInvalid, Status: http.StatusBadRequest, Message: "new password is invalid"},
			{Err: usecase.ErrPermissionDenied, Status: http.StatusForbidden, Message: "insufficient permissions"},
			{Err: usecase.ErrUserNotFound, Status: http.StatusNotFound, Message: "user not found"},
		}, http.StatusInternalServerError, "failed to change password")
		return
	}

	c.JSON(http.StatusOK, PasswordChangeResponse{Changed: true})
}

// ResetPassword godoc
// @Summary Initiate a password reset
// @Description Starts the password reset flow for a user by issuing a reset token or code.
// @Tags Password
// @Accept json
// @Produce json
// @Param request body PasswordResetRequest true "Password reset request"
// @Success 200 {object} PasswordResetResponse
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /api/v1/user/password/reset [post]
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

	result, err := h.reset.InitiateReset(c.Request.Context(), req.Identifier)
	if err != nil {
		switch {
		case errors.Is(err, usecase.ErrUserNotFound):
			c.JSON(http.StatusNotFound, ErrorResponse{Error: "user not found"})
		case errors.Is(err, usecase.ErrPasswordResetContactMissing):
			c.JSON(http.StatusBadRequest, ErrorResponse{Error: "no contact method available"})
		case errors.Is(err, usecase.ErrPasswordResetUnavailable):
			c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "password reset unavailable"})
		default:
			c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "failed to initiate password reset"})
		}
		return
	}

	response := PasswordResetResponse{
		Delivery:  result.Delivery,
		ExpiresAt: result.ExpiresAt.UTC().Format(time.RFC3339),
	}

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

	c.JSON(http.StatusOK, response)
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
// @Failure 500 {object} ErrorResponse
// @Router /api/v1/user/password/reset/confirm [post]
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

	var err error
	if token != "" {
		err = h.reset.CompleteWithToken(c.Request.Context(), token, req.NewPassword)
	} else {
		err = h.reset.CompleteWithCode(c.Request.Context(), code, req.NewPassword)
	}

	if err != nil {
		switch {
		case errors.Is(err, usecase.ErrPasswordResetTokenInvalid):
			c.JSON(http.StatusBadRequest, ErrorResponse{Error: "password reset token invalid"})
		case errors.Is(err, usecase.ErrPasswordResetTokenExpired):
			c.JSON(http.StatusBadRequest, ErrorResponse{Error: "password reset token expired"})
		case errors.Is(err, usecase.ErrNewPasswordInvalid):
			c.JSON(http.StatusBadRequest, ErrorResponse{Error: "new password invalid"})
		case errors.Is(err, usecase.ErrUserNotFound):
			c.JSON(http.StatusNotFound, ErrorResponse{Error: "user not found"})
		case errors.Is(err, usecase.ErrPasswordResetUnavailable):
			c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "password reset unavailable"})
		default:
			c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "failed to confirm password reset"})
		}
		return
	}

	c.JSON(http.StatusOK, PasswordResetConfirmResponse{Reset: true})
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
