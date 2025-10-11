package usecase

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	uuid "github.com/google/uuid"

	"github.com/arklim/social-platform-iam/internal/core/domain"
	"github.com/arklim/social-platform-iam/internal/core/port"
	"github.com/arklim/social-platform-iam/internal/infra/security"
	"github.com/arklim/social-platform-iam/internal/repository"
)

const (
	resetDeliveryEmail = "email"
	resetDeliveryPhone = "sms"

	defaultResetTTL    = time.Hour
	fallbackCodeLength = 6
)

var (
	// ErrPasswordResetUnavailable indicates the service is not properly configured.
	ErrPasswordResetUnavailable = errors.New("password reset service unavailable")
	// ErrPasswordResetContactMissing indicates the user has no reachable contact method.
	ErrPasswordResetContactMissing = errors.New("no contact method available for password reset")
	// ErrPasswordResetTokenInvalid indicates the supplied reset token/code is invalid or already used.
	ErrPasswordResetTokenInvalid = errors.New("password reset token invalid")
	// ErrPasswordResetTokenExpired indicates the supplied token/code is expired.
	ErrPasswordResetTokenExpired = errors.New("password reset token expired")
)

// PasswordResetService coordinates password reset initiation and completion.
type PasswordResetService struct {
	users             port.UserRepository
	tokens            port.TokenRepository
	passwordValidator *security.PasswordValidator
	now               func() time.Time
	resetTTL          time.Duration
}

// ResetInitiationResult describes the generated reset artifact returned to the caller.
type ResetInitiationResult struct {
	Delivery  string
	Contact   string
	Token     string
	Code      string
	ExpiresAt time.Time
}

// NewPasswordResetService constructs a PasswordResetService.
func NewPasswordResetService(users port.UserRepository, tokens port.TokenRepository, validator *security.PasswordValidator) *PasswordResetService {
	if validator == nil {
		validator = security.DefaultPasswordValidator()
	}
	return &PasswordResetService{
		users:             users,
		tokens:            tokens,
		passwordValidator: validator,
		now:               time.Now,
		resetTTL:          defaultResetTTL,
	}
}

// InitiateReset creates a password reset token or code for the provided identifier.
func (s *PasswordResetService) InitiateReset(ctx context.Context, identifier string) (*ResetInitiationResult, error) {
	identifier = strings.TrimSpace(identifier)
	if identifier == "" {
		return nil, fmt.Errorf("identifier is required")
	}
	if s.users == nil || s.tokens == nil {
		return nil, ErrPasswordResetUnavailable
	}

	user, err := s.users.GetByIdentifier(ctx, identifier)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("lookup user: %w", err)
	}

	now := s.now().UTC()
	expiresAt := now.Add(s.resetTTL)

	result := &ResetInitiationResult{ExpiresAt: expiresAt}
	metadata := map[string]any{}

	email := strings.TrimSpace(user.Email)
	var phone string
	if user.Phone != nil {
		phone = strings.TrimSpace(*user.Phone)
	}

	switch {
	case email != "":
		raw, err := security.GenerateSecureToken(32)
		if err != nil {
			return nil, fmt.Errorf("generate reset token: %w", err)
		}
		metadata["delivery"] = resetDeliveryEmail
		metadata["contact"] = email
		result.Delivery = resetDeliveryEmail
		result.Contact = email
		result.Token = raw
		if err := s.storeResetToken(ctx, user.ID, raw, expiresAt, metadata, nil, nil); err != nil {
			return nil, err
		}
	case phone != "":
		raw, err := security.GenerateNumericCode(fallbackCodeLength)
		if err != nil {
			return nil, fmt.Errorf("generate reset code: %w", err)
		}
		raw = strings.TrimSpace(raw)
		metadata["delivery"] = resetDeliveryPhone
		metadata["contact"] = phone
		result.Delivery = resetDeliveryPhone
		result.Contact = phone
		result.Code = raw
		if err := s.storeResetToken(ctx, user.ID, raw, expiresAt, metadata, nil, nil); err != nil {
			return nil, err
		}
	default:
		return nil, ErrPasswordResetContactMissing
	}

	return result, nil
}

func (s *PasswordResetService) storeResetToken(ctx context.Context, userID string, raw string, expiresAt time.Time, metadata map[string]any, ip, ua *string) error {
	hashed := security.HashToken(raw)
	token := domain.PasswordResetToken{
		ID:        uuid.NewString(),
		UserID:    userID,
		TokenHash: hashed,
		IP:        ip,
		UserAgent: ua,
		CreatedAt: s.now().UTC(),
		ExpiresAt: expiresAt,
		Metadata:  metadata,
	}
	if err := s.tokens.CreatePasswordReset(ctx, token); err != nil {
		return fmt.Errorf("store password reset token: %w", err)
	}
	return nil
}

// CompleteWithToken finalizes a password reset using a raw token (magic link).
func (s *PasswordResetService) CompleteWithToken(ctx context.Context, token, newPassword string) error {
	return s.complete(ctx, token, newPassword)
}

// CompleteWithCode finalizes a password reset using a verification code (e.g., SMS).
func (s *PasswordResetService) CompleteWithCode(ctx context.Context, code, newPassword string) error {
	return s.complete(ctx, code, newPassword)
}

func (s *PasswordResetService) complete(ctx context.Context, credential, newPassword string) error {
	credential = strings.TrimSpace(credential)
	if credential == "" {
		return fmt.Errorf("reset credential is required")
	}
	newPassword = strings.TrimSpace(newPassword)
	if newPassword == "" {
		return fmt.Errorf("new password is required")
	}
	if s.users == nil || s.tokens == nil {
		return ErrPasswordResetUnavailable
	}

	if err := s.passwordValidator.Validate(newPassword); err != nil {
		return fmt.Errorf("%w: %v", ErrNewPasswordInvalid, err)
	}

	hash := security.HashToken(credential)
	token, err := s.tokens.GetPasswordResetByHash(ctx, hash)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return ErrPasswordResetTokenInvalid
		}
		return fmt.Errorf("lookup password reset token: %w", err)
	}

	now := s.now().UTC()
	if token.RevokedAt != nil || token.UsedAt != nil {
		return ErrPasswordResetTokenInvalid
	}
	if now.After(token.ExpiresAt) {
		return ErrPasswordResetTokenExpired
	}

	user, err := s.users.GetByID(ctx, token.UserID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return ErrUserNotFound
		}
		return fmt.Errorf("lookup user: %w", err)
	}

	if matches, err := security.VerifyPassword(newPassword, user.PasswordHash); err != nil {
		return fmt.Errorf("validate new password: %w", err)
	} else if matches {
		return ErrNewPasswordInvalid
	}

	hashedPassword, err := security.HashPassword(newPassword)
	if err != nil {
		return fmt.Errorf("hash new password: %w", err)
	}

	changedAt := now
	if err := s.users.UpdatePassword(ctx, user.ID, hashedPassword, "argon2id", changedAt); err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return ErrUserNotFound
		}
		return fmt.Errorf("update password: %w", err)
	}

	if err := s.tokens.ConsumePasswordReset(ctx, token.ID); err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return ErrPasswordResetTokenInvalid
		}
		return fmt.Errorf("consume password reset token: %w", err)
	}

	return nil
}

// WithClock allows tests to override the clock used by the service.
func (s *PasswordResetService) WithClock(clock func() time.Time) {
	if clock != nil {
		s.now = clock
	}
}

// WithTTL allows tests to override the default reset TTL.
func (s *PasswordResetService) WithTTL(ttl time.Duration) {
	if ttl > 0 {
		s.resetTTL = ttl
	}
}
