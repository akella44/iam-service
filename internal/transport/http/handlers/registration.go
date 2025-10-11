package handlers

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/arklim/social-platform-iam/internal/core/domain"
	"github.com/arklim/social-platform-iam/internal/usecase"
)

// RegistrationHandler exposes endpoints for user registration and verification.
type RegistrationHandler struct {
	registration *usecase.RegistrationService
	dispatcher   NotificationDispatcher
	isDev        bool // Development mode flag
}

func NewRegistrationHandler(registration *usecase.RegistrationService, dispatcher NotificationDispatcher, isDev bool) *RegistrationHandler {
	if dispatcher == nil {
		dispatcher = noopDispatcher{}
	}
	return &RegistrationHandler{
		registration: registration,
		dispatcher:   dispatcher,
		isDev:        isDev,
	}
}

// RegisterRoutes binds registration endpoints.
func (h *RegistrationHandler) RegisterRoutes(r *gin.RouterGroup) {
	r.POST("/register", h.Register)
	r.POST("/verify", h.Verify)
}

// Register godoc
// @Summary Register a new user account
// @Description Creates a new user with the provided credentials and contact information.
// @Tags Registration
// @Accept json
// @Produce json
// @Param request body RegistrationRequest true "Registration request"
// @Success 201 {object} RegistrationResponse
// @Failure 400 {object} ErrorResponse
// @Failure 409 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /api/v1/user/register [post]
func (h *RegistrationHandler) Register(c *gin.Context) {
	var req RegistrationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "invalid registration payload"})
		return
	}

	req.Username = strings.TrimSpace(req.Username)
	req.Email = strings.TrimSpace(req.Email)
	req.Phone = strings.TrimSpace(req.Phone)

	if req.Username == "" {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "username is required"})
		return
	}

	if req.Email == "" && req.Phone == "" {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "either email or phone is required"})
		return
	}

	user, verification, err := h.registration.RegisterUser(c.Request.Context(), req.Username, req.Email, req.Phone, req.Password)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			switch pgErr.ConstraintName {
			case "users_email_key":
				c.JSON(http.StatusConflict, ErrorResponse{Error: "email already registered"})
			case "users_phone_key":
				c.JSON(http.StatusConflict, ErrorResponse{Error: "phone already registered"})
			default:
				c.JSON(http.StatusConflict, ErrorResponse{Error: "username or contact already exists"})
			}
			return
		}
		if errors.Is(err, usecase.ErrPasswordPolicyViolation) {
			c.JSON(http.StatusBadRequest, ErrorResponse{Error: "password does not meet requirements"})
			return
		}
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "failed to register user"})
		return
	}

	user.PasswordHash = ""

	resp := RegistrationResponse{
		User:                 newUserSummary(user, nil),
		RequiresVerification: user.Status == domain.UserStatusPending,
	}

	if user.Status == domain.UserStatusPending {
		resp.Message = "verification required"
		if verification.Delivery != "" {
			delivery := verification.Delivery
			resp.Delivery = &delivery
		}
		if !verification.ExpiresAt.IsZero() {
			expires := verification.ExpiresAt.UTC().Format(time.RFC3339)
			resp.ExpiresAt = &expires
		}

		// SECURITY: Only expose raw tokens/codes in development mode
		// In production, tokens should only be sent via secure channels (email/SMS)
		if h.isDev {
			if token := strings.TrimSpace(verification.Token); token != "" {
				resp.DevToken = &token
			}
			if code := strings.TrimSpace(verification.Code); code != "" {
				resp.DevCode = &code
			}
		}

		h.dispatchVerification(c.Request.Context(), req.Username, req.Email, req.Phone, verification)
	}

	c.JSON(http.StatusCreated, resp)
}

// Verify godoc
// @Summary Verify a pending user account
// @Description Confirms a verification code to activate a pending user account.
// @Tags Registration
// @Accept json
// @Produce json
// @Param request body RegistrationVerifyRequest true "Verification request"
// @Success 200 {object} RegistrationVerifyResponse
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /api/v1/user/verify [post]
func (h *RegistrationHandler) Verify(c *gin.Context) {
	var req RegistrationVerifyRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "invalid verification payload"})
		return
	}

	req.Code = strings.TrimSpace(req.Code)
	if req.Code == "" {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "verification code is required"})
		return
	}

	user, err := h.registration.VerifyCode(c.Request.Context(), req.Code)
	if err != nil {
		switch {
		case errors.Is(err, usecase.ErrVerificationCodeInvalid):
			c.JSON(http.StatusBadRequest, ErrorResponse{Error: "verification code is invalid"})
		case errors.Is(err, usecase.ErrVerificationCodeExpired):
			c.JSON(http.StatusBadRequest, ErrorResponse{Error: "verification code has expired"})
		default:
			c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "failed to verify code"})
		}
		return
	}

	user.PasswordHash = ""

	c.JSON(http.StatusOK, RegistrationVerifyResponse{
		Message: "account verified",
		User:    newUserSummary(user, nil),
	})
}

func (h *RegistrationHandler) dispatchVerification(ctx context.Context, username, email, phone string, verification usecase.RegistrationVerification) {
	if h.dispatcher == nil {
		return
	}

	contact := strings.TrimSpace(email)
	if contact == "" {
		contact = strings.TrimSpace(phone)
	}

	payload := RegistrationNotification{
		Delivery: verification.Delivery,
		Contact:  contact,
		Username: strings.TrimSpace(username),
		Email:    strings.TrimSpace(email),
		Phone:    strings.TrimSpace(phone),
		Expires:  verification.ExpiresAt,
	}

	if h.isDev {
		payload.DevToken = strings.TrimSpace(verification.Token)
		payload.DevCode = strings.TrimSpace(verification.Code)
	}

	_ = h.dispatcher.SendRegistrationVerification(ctx, payload)
}
