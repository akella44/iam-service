package handlers

import (
	"strings"
	"time"

	"github.com/arklim/social-platform-iam/internal/core/domain"
	"github.com/gin-gonic/gin"
)

// ErrorResponse represents a generic error payload with trace ID for debugging.
type ErrorResponse struct {
	Error   string `json:"error"`
	TraceID string `json:"trace_id,omitempty"`
}

// NewErrorResponse creates an error response with trace ID from context
func NewErrorResponse(c *gin.Context, errorMsg string) ErrorResponse {
	traceID, _ := c.Get("trace_id")
	traceIDStr, _ := traceID.(string)

	return ErrorResponse{
		Error:   errorMsg,
		TraceID: traceIDStr,
	}
}

// MessageResponse represents a simple message payload.
type MessageResponse struct {
	Message string `json:"message"`
}

// UserSummary describes a minimal view of a user returned by the API.
type UserSummary struct {
	ID       string            `json:"id"`
	Username string            `json:"username"`
	Status   domain.UserStatus `json:"status"`
	Email    *string           `json:"email,omitempty"`
	Phone    *string           `json:"phone,omitempty"`
	Roles    []string          `json:"roles,omitempty"`
}

// AuthLoginRequest defines the payload for the login endpoint.
type AuthLoginRequest struct {
	Identifier  string `json:"identifier" binding:"required"`
	Password    string `json:"password" binding:"required"`
	DeviceID    string `json:"device_id"`
	DeviceLabel string `json:"device_label"`
}

// SessionSummary provides a compact view of session context in login responses.
type SessionSummary struct {
	ID             string    `json:"id"`
	DeviceLabel    *string   `json:"device_label,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
	ExpiresAt      time.Time `json:"expires_at"`
	LastSeen       time.Time `json:"last_seen"`
	SessionVersion int64     `json:"session_version"`
}

// AuthLoginResponse describes the response returned for a successful login.
type AuthLoginResponse struct {
	AccessToken  string         `json:"access_token"`
	RefreshToken string         `json:"refresh_token"`
	TokenType    string         `json:"token_type"`
	ExpiresIn    int            `json:"expires_in"`
	User         UserSummary    `json:"user"`
	Session      SessionSummary `json:"session"`
}

// AuthPendingResponse is returned when a login requires additional verification.
type AuthPendingResponse struct {
	Message string      `json:"message"`
	User    UserSummary `json:"user"`
}

// TokenRefreshRequest represents the payload to refresh an access token.
type TokenRefreshRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

// TokenRefreshResponse contains tokens issued by the refresh endpoint.
type TokenRefreshResponse struct {
	AccessToken  string       `json:"access_token"`
	RefreshToken string       `json:"refresh_token"`
	TokenType    string       `json:"token_type"`
	ExpiresIn    int          `json:"expires_in,omitempty"`
	User         *UserSummary `json:"user,omitempty"`
}

// RegistrationRequest defines the account registration payload.
type RegistrationRequest struct {
	Username string `json:"username" binding:"required"`
	Email    string `json:"email" binding:"omitempty,email"`
	Phone    string `json:"phone" binding:"omitempty"`
	Password string `json:"password" binding:"required,min=8"`
}

// RegistrationResponse contains registration results and next steps.
type RegistrationResponse struct {
	User                 UserSummary `json:"user"`
	RequiresVerification bool        `json:"requires_verification"`
	Message              string      `json:"message,omitempty"`
	Delivery             *string     `json:"delivery,omitempty"`
	ExpiresAt            *string     `json:"expires_at,omitempty"`
	// SECURITY: DevToken and DevCode are ONLY exposed in development mode
	// In production, verification credentials are sent via secure channels
	DevToken *string `json:"dev_token,omitempty"` // Development only
	DevCode  *string `json:"dev_code,omitempty"`  // Development only
}

// RegistrationVerifyRequest holds the verification payload.
type RegistrationVerifyRequest struct {
	Code string `json:"code" binding:"required"`
}

// RegistrationVerifyResponse is returned after a successful verification.
type RegistrationVerifyResponse struct {
	Message string      `json:"message"`
	User    UserSummary `json:"user"`
}

// PermissionPayload describes a permission in role operations.
type PermissionPayload struct {
	ID          string  `json:"id,omitempty"`
	Name        string  `json:"name" binding:"required"`
	Description *string `json:"description,omitempty"`
}

// RoleCreateRequest defines the payload for creating a role.
type RoleCreateRequest struct {
	Name          string              `json:"name" binding:"required"`
	Description   *string             `json:"description,omitempty"`
	Permissions   []PermissionPayload `json:"permissions"`
	AssignUserIDs []string            `json:"assign_user_ids"`
}

// RoleUpdateRequest defines the payload for updating a role.
type RoleUpdateRequest struct {
	Name        *string             `json:"name,omitempty"`
	Description *string             `json:"description,omitempty"`
	Permissions []PermissionPayload `json:"permissions"`
}

// RolePayload summarizes a role entity.
type RolePayload struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	Description *string `json:"description,omitempty"`
}

// RoleCreateResponse contains the created role and associated data.
type RoleCreateResponse struct {
	Role            RolePayload         `json:"role"`
	Permissions     []PermissionPayload `json:"permissions"`
	AssignedUserIDs []string            `json:"assigned_user_ids"`
}

// RoleResponse returns role details.
type RoleResponse struct {
	Role        RolePayload         `json:"role"`
	Permissions []PermissionPayload `json:"permissions"`
}

// RoleListResponse wraps multiple roles.
type RoleListResponse struct {
	Roles []RolePayload `json:"roles"`
}

// RoleAssignmentRequest assigns or unassigns users to a role.
type RoleAssignmentRequest struct {
	UserIDs []string `json:"user_ids" binding:"required"`
}

// RoleAssignmentResponse returns assignment results.
type RoleAssignmentResponse struct {
	RoleID            string   `json:"role_id"`
	AssignedUserIDs   []string `json:"assigned_user_ids"`
	UnassignedUserIDs []string `json:"unassigned_user_ids"`
}

// SessionPayload describes a session view in API responses.
type SessionPayload struct {
	ID             string     `json:"id"`
	UserID         string     `json:"user_id"`
	RefreshTokenID *string    `json:"refresh_token_id,omitempty"`
	DeviceID       *string    `json:"device_id,omitempty"`
	DeviceLabel    *string    `json:"device_label,omitempty"`
	IPFirst        *string    `json:"ip_first,omitempty"`
	IPLast         *string    `json:"ip_last,omitempty"`
	UserAgent      *string    `json:"user_agent,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	LastSeen       time.Time  `json:"last_seen"`
	ExpiresAt      time.Time  `json:"expires_at"`
	RevokedAt      *time.Time `json:"revoked_at,omitempty"`
	RevokeReason   *string    `json:"revoke_reason,omitempty"`
	IsActive       bool       `json:"is_active"`
	IsCurrent      bool       `json:"is_current,omitempty"`
	SessionVersion int64      `json:"session_version"`
	IssuedVersion  *int64     `json:"issued_version,omitempty"`
}

// SessionValidateRequest contains the session ID to validate
type SessionValidateRequest struct {
	SessionID string `json:"session_id" binding:"required"`
}

// SessionValidateResponse conveys session validation results.
type SessionValidateResponse struct {
	Valid   bool           `json:"valid"`
	Session SessionPayload `json:"session"`
}

// SessionListResponse wraps a list of sessions for a user.
type SessionListResponse struct {
	Sessions []SessionPayload `json:"sessions"`
	Total    int              `json:"total"`
}

// SessionBulkRevokeResponse summarises bulk revocation operations.
type SessionBulkRevokeResponse struct {
	RevokedCount  int `json:"revoked_count"`
	TokensRevoked int `json:"tokens_revoked,omitempty"`
}

// SessionRevokeRequest contains the session revocation payload.
type SessionRevokeRequest struct {
	SessionID string `json:"session_id" binding:"required"`
	Reason    string `json:"reason"`
}

// SessionRevokeResponse indicates whether the session was revoked.
type SessionRevokeResponse struct {
	Revoked bool `json:"revoked"`
}

// PasswordChangeRequest captures a password change request body.
type PasswordChangeRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password" binding:"required"`
	UserID          string `json:"user_id"`
}

// PasswordChangeResponse conveys the result of a password change.
type PasswordChangeResponse struct {
	Message         string    `json:"message"`
	ChangedAt       time.Time `json:"changed_at"`
	RevokedSessions int       `json:"revoked_sessions"`
	RevokedTokens   int       `json:"revoked_tokens"`
}

// PasswordResetRequest represents a password reset initiation payload.
type PasswordResetRequest struct {
	EmailOrPhone string `json:"email_or_phone" binding:"required"`
}

// PasswordResetResponse returns information about the generated reset artifact.
type PasswordResetResponse struct {
	Message           string     `json:"message"`
	RequestID         string     `json:"request_id,omitempty"`
	Delivery          string     `json:"delivery,omitempty"`
	MaskedDestination string     `json:"masked_destination,omitempty"`
	ExpiresAt         *time.Time `json:"expires_at,omitempty"`
	// SECURITY: DevToken and DevCode are ONLY exposed in development mode
	DevToken *string `json:"dev_token,omitempty"`
	DevCode  *string `json:"dev_code,omitempty"`
}

// PasswordResetConfirmRequest captures a password reset confirmation payload.
type PasswordResetConfirmRequest struct {
	Token       string `json:"token"`
	Code        string `json:"code"`
	NewPassword string `json:"new_password" binding:"required"`
}

// PasswordResetConfirmResponse indicates that a password reset completed successfully.
type PasswordResetConfirmResponse struct {
	Message         string    `json:"message"`
	UserID          string    `json:"user_id"`
	ChangedAt       time.Time `json:"changed_at"`
	RevokedSessions int       `json:"revoked_sessions"`
	RevokedTokens   int       `json:"revoked_tokens"`
}

// HealthResponse describes the service health payload.
type HealthResponse struct {
	Status    string    `json:"status"`
	StartedAt time.Time `json:"started_at"`
	Timestamp time.Time `json:"timestamp"`
}

// ReadyResponse describes readiness probe results with dependency checks.
type ReadyResponse struct {
	Status    string            `json:"status"`
	Checks    map[string]string `json:"checks,omitempty"`
	Timestamp time.Time         `json:"timestamp"`
}

// JWKSKey describes an individual JSON Web Key in the JWKS response.
type JWKSKey struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// JWKSResponse represents the JSON Web Key Set payload.
type JWKSResponse struct {
	Keys []JWKSKey `json:"keys"`
}

// newUserSummary converts a domain user to a summary suitable for API responses.
func newUserSummary(user domain.User, roles []string) UserSummary {
	summary := UserSummary{
		ID:       user.ID,
		Username: user.Username,
		Status:   user.Status,
	}

	if email := user.Email; email != "" {
		summary.Email = &email
	}

	if user.Phone != nil {
		phone := strings.TrimSpace(*user.Phone)
		if phone != "" {
			summary.Phone = &phone
		}
	}

	if len(roles) > 0 {
		rolesCopy := make([]string, len(roles))
		copy(rolesCopy, roles)
		summary.Roles = rolesCopy
	}

	return summary
}

// newSessionPayload converts a domain session to an API session payload.
func newSessionPayload(session domain.Session) SessionPayload {
	payload := SessionPayload{
		ID:             session.ID,
		UserID:         session.UserID,
		CreatedAt:      session.CreatedAt,
		LastSeen:       session.LastSeen,
		ExpiresAt:      session.ExpiresAt,
		IsActive:       session.IsActive(time.Now().UTC()),
		SessionVersion: session.Version,
	}

	if session.RefreshTokenID != nil {
		payload.RefreshTokenID = session.RefreshTokenID
	}
	if session.DeviceID != nil {
		payload.DeviceID = session.DeviceID
	}
	if session.DeviceLabel != nil {
		payload.DeviceLabel = session.DeviceLabel
	}
	if session.IPFirst != nil {
		payload.IPFirst = session.IPFirst
	}
	if session.IPLast != nil {
		payload.IPLast = session.IPLast
	}
	if session.UserAgent != nil {
		payload.UserAgent = session.UserAgent
	}
	if session.RevokedAt != nil {
		payload.RevokedAt = session.RevokedAt
	}
	if session.RevokeReason != nil {
		payload.RevokeReason = session.RevokeReason
	}
	if session.IssuedVersion != nil {
		payload.IssuedVersion = session.IssuedVersion
	}

	return payload
}

func newSessionSummary(session domain.Session) SessionSummary {
	summary := SessionSummary{
		ID:             session.ID,
		CreatedAt:      session.CreatedAt,
		ExpiresAt:      session.ExpiresAt,
		LastSeen:       session.LastSeen,
		SessionVersion: session.Version,
	}

	if session.DeviceLabel != nil {
		summary.DeviceLabel = session.DeviceLabel
	}

	return summary
}
