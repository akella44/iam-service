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
	verificationPurposeRegistration = "user_registration"
	verificationDeliveryEmail       = "email"
	verificationDeliveryPhone       = "sms"
	defaultVerificationTTL          = 24 * time.Hour
)

var (
	// ErrVerificationCodeInvalid indicates the provided verification code is invalid or already used.
	ErrVerificationCodeInvalid = errors.New("verification code invalid")
	// ErrVerificationCodeExpired indicates the code exists but is expired.
	ErrVerificationCodeExpired = errors.New("verification code expired")
	// ErrPasswordPolicyViolation indicates the password does not satisfy complexity requirements.
	ErrPasswordPolicyViolation = errors.New("password does not meet complexity requirements")
)

// RegistrationService handles new account onboarding.
type RegistrationService struct {
	users             port.UserRepository
	tokens            port.TokenRepository
	passwordValidator *security.PasswordValidator
}

// NewRegistrationService constructs a registration service.
func NewRegistrationService(users port.UserRepository, tokens port.TokenRepository, validator *security.PasswordValidator) *RegistrationService {
	if validator == nil {
		validator = security.DefaultPasswordValidator()
	}
	return &RegistrationService{users: users, tokens: tokens, passwordValidator: validator}
}

// RegistrationVerification captures the verification artifact for a newly registered user.
type RegistrationVerification struct {
	Delivery  string
	Token     string
	Code      string
	ExpiresAt time.Time
}

// RegisterUser scaffolds user creation and returns the verification details.
func (s *RegistrationService) RegisterUser(ctx context.Context, username, email, phone, password string) (domain.User, RegistrationVerification, error) {
	var zero RegistrationVerification
	if username == "" {
		return domain.User{}, zero, fmt.Errorf("username is required")
	}
	trimmedEmail := strings.TrimSpace(email)
	trimmedPhone := strings.TrimSpace(phone)
	if trimmedEmail == "" && trimmedPhone == "" {
		return domain.User{}, zero, fmt.Errorf("email or phone is required")
	}
	password = strings.TrimSpace(password)
	if password == "" {
		return domain.User{}, zero, fmt.Errorf("password is required")
	}
	if s.tokens == nil {
		return domain.User{}, zero, fmt.Errorf("token repository not configured")
	}

	if err := s.passwordValidator.Validate(password); err != nil {
		return domain.User{}, zero, fmt.Errorf("%w: %v", ErrPasswordPolicyViolation, err)
	}

	passwordHash, err := security.HashPassword(password)
	if err != nil {
		return domain.User{}, zero, fmt.Errorf("hash password: %w", err)
	}

	now := time.Now().UTC()
	user := domain.User{
		ID:                 uuid.NewString(),
		Username:           username,
		Email:              trimmedEmail,
		PasswordHash:       passwordHash,
		PasswordAlgo:       "argon2id",
		Status:             domain.UserStatusPending,
		IsActive:           true,
		RegisteredAt:       now,
		LastPasswordChange: now,
	}
	if trimmedPhone != "" {
		user.Phone = &trimmedPhone
	}

	if err := s.users.Create(ctx, user); err != nil {
		return domain.User{}, zero, err
	}

	expiresAt := now.Add(defaultVerificationTTL)
	result := RegistrationVerification{ExpiresAt: expiresAt}
	metadata := map[string]any{}

	switch {
	case trimmedEmail != "":
		rawToken, err := security.GenerateSecureToken(32)
		if err != nil {
			return domain.User{}, zero, fmt.Errorf("generate verification token: %w", err)
		}
		metadata["delivery"] = verificationDeliveryEmail
		metadata["contact"] = trimmedEmail
		result.Delivery = verificationDeliveryEmail
		result.Token = rawToken
		hashed := security.HashToken(rawToken)
		token := domain.VerificationToken{
			ID:        uuid.NewString(),
			UserID:    user.ID,
			TokenHash: hashed,
			Purpose:   verificationPurposeRegistration,
			CreatedAt: now,
			ExpiresAt: expiresAt,
			Metadata:  metadata,
		}
		if err := s.tokens.CreateVerification(ctx, token); err != nil {
			return domain.User{}, zero, fmt.Errorf("store verification token: %w", err)
		}
	case trimmedPhone != "":
		rawCode, err := security.GenerateNumericCode(6)
		if err != nil {
			return domain.User{}, zero, fmt.Errorf("generate verification code: %w", err)
		}
		rawCode = strings.TrimSpace(rawCode)
		metadata["delivery"] = verificationDeliveryPhone
		metadata["contact"] = trimmedPhone
		result.Delivery = verificationDeliveryPhone
		result.Code = rawCode
		hashed := security.HashToken(rawCode)
		token := domain.VerificationToken{
			ID:        uuid.NewString(),
			UserID:    user.ID,
			TokenHash: hashed,
			Purpose:   verificationPurposeRegistration,
			CreatedAt: now,
			ExpiresAt: expiresAt,
			Metadata:  metadata,
		}
		if err := s.tokens.CreateVerification(ctx, token); err != nil {
			return domain.User{}, zero, fmt.Errorf("store verification token: %w", err)
		}
	default:
		return domain.User{}, zero, fmt.Errorf("no contact method available")
	}

	return user, result, nil
}

// VerifyCode validates the provided verification code and activates the user.
func (s *RegistrationService) VerifyCode(ctx context.Context, code string) (domain.User, error) {
	code = strings.TrimSpace(code)
	if code == "" {
		return domain.User{}, fmt.Errorf("verification code is required")
	}
	if s.tokens == nil {
		return domain.User{}, fmt.Errorf("token repository not configured")
	}

	hash := security.HashToken(code)
	token, err := s.tokens.GetVerificationByHash(ctx, hash)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return domain.User{}, ErrVerificationCodeInvalid
		}
		return domain.User{}, fmt.Errorf("lookup verification token: %w", err)
	}

	if token.UsedAt != nil || token.RevokedAt != nil || token.Purpose != verificationPurposeRegistration {
		return domain.User{}, ErrVerificationCodeInvalid
	}
	if time.Now().UTC().After(token.ExpiresAt) {
		return domain.User{}, ErrVerificationCodeExpired
	}

	user, err := s.users.GetByID(ctx, token.UserID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return domain.User{}, ErrVerificationCodeInvalid
		}
		return domain.User{}, fmt.Errorf("lookup user: %w", err)
	}

	if err := s.users.UpdateStatus(ctx, user.ID, domain.UserStatusActive); err != nil {
		return domain.User{}, fmt.Errorf("activate user: %w", err)
	}

	if err := s.tokens.ConsumeVerification(ctx, token.ID); err != nil {
		return domain.User{}, fmt.Errorf("consume verification token: %w", err)
	}

	user.Status = domain.UserStatusActive

	return *user, nil
}
