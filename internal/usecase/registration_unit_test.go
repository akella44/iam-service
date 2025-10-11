package usecase

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/arklim/social-platform-iam/internal/core/domain"
	"github.com/arklim/social-platform-iam/internal/infra/security"
	"github.com/arklim/social-platform-iam/internal/repository"
)

type mockUserRepository struct {
	createErr   error
	createCalls int
	createdUser domain.User

	getByIDResult *domain.User
	getByIDErr    error
	getByIDCalls  int
	getByIDLastID string

	updateStatusErr    error
	updateStatusCalls  int
	updateStatusID     string
	updateStatusStatus domain.UserStatus
}

func (m *mockUserRepository) Create(_ context.Context, user domain.User) error {
	m.createCalls++
	m.createdUser = user
	return m.createErr
}

func (m *mockUserRepository) GetByID(_ context.Context, id string) (*domain.User, error) {
	m.getByIDCalls++
	m.getByIDLastID = id
	if m.getByIDResult != nil {
		copy := *m.getByIDResult
		return &copy, m.getByIDErr
	}
	return nil, m.getByIDErr
}

func (m *mockUserRepository) GetByIdentifier(context.Context, string) (*domain.User, error) {
	return nil, errors.New("unexpected call: GetByIdentifier")
}

func (m *mockUserRepository) UpdateStatus(_ context.Context, id string, status domain.UserStatus) error {
	m.updateStatusCalls++
	m.updateStatusID = id
	m.updateStatusStatus = status
	return m.updateStatusErr
}

func (m *mockUserRepository) UpdatePassword(context.Context, string, string, string, time.Time) error {
	return errors.New("unexpected call: UpdatePassword")
}

type mockTokenRepository struct {
	createVerificationErr error
	createCalls           int
	createdToken          domain.VerificationToken

	getVerificationErr      error
	getVerificationResult   *domain.VerificationToken
	getVerificationCalls    int
	getVerificationLastHash string

	consumeVerificationErr    error
	consumeVerificationCalls  int
	consumeVerificationLastID string
}

func (m *mockTokenRepository) CreateVerification(_ context.Context, token domain.VerificationToken) error {
	m.createCalls++
	m.createdToken = token
	return m.createVerificationErr
}

func (m *mockTokenRepository) GetVerificationByHash(_ context.Context, hash string) (*domain.VerificationToken, error) {
	m.getVerificationCalls++
	m.getVerificationLastHash = hash
	if m.getVerificationResult != nil {
		copy := *m.getVerificationResult
		return &copy, m.getVerificationErr
	}
	return nil, m.getVerificationErr
}

func (m *mockTokenRepository) ConsumeVerification(_ context.Context, id string) error {
	m.consumeVerificationCalls++
	m.consumeVerificationLastID = id
	return m.consumeVerificationErr
}

func (m *mockTokenRepository) CreatePasswordReset(context.Context, domain.PasswordResetToken) error {
	return errors.New("unexpected call: CreatePasswordReset")
}

func (m *mockTokenRepository) GetPasswordResetByHash(context.Context, string) (*domain.PasswordResetToken, error) {
	return nil, errors.New("unexpected call: GetPasswordResetByHash")
}

func (m *mockTokenRepository) ConsumePasswordReset(context.Context, string) error {
	return errors.New("unexpected call: ConsumePasswordReset")
}

func (m *mockTokenRepository) CreateRefreshToken(context.Context, domain.RefreshToken) error {
	return errors.New("unexpected call: CreateRefreshToken")
}

func (m *mockTokenRepository) GetRefreshTokenByHash(context.Context, string) (*domain.RefreshToken, error) {
	return nil, errors.New("unexpected call: GetRefreshTokenByHash")
}

func (m *mockTokenRepository) RevokeRefreshToken(context.Context, string) error {
	return errors.New("unexpected call: RevokeRefreshToken")
}

func (m *mockTokenRepository) RevokeRefreshTokensForUser(context.Context, string) error {
	return errors.New("unexpected call: RevokeRefreshTokensForUser")
}

func (m *mockTokenRepository) StoreAccessTokenJTI(context.Context, domain.AccessTokenJTI) error {
	return errors.New("unexpected call: StoreAccessTokenJTI")
}

func (m *mockTokenRepository) BlacklistAccessTokenJTI(context.Context, domain.RevokedAccessTokenJTI) error {
	return errors.New("unexpected call: BlacklistAccessTokenJTI")
}

func (m *mockTokenRepository) IsAccessTokenJTIRevoked(context.Context, string) (bool, error) {
	return false, errors.New("unexpected call: IsAccessTokenJTIRevoked")
}

func TestRegistrationService_RegisterUser_EmailMagicLink(t *testing.T) {
	userRepo := &mockUserRepository{}
	tokenRepo := &mockTokenRepository{}

	service := NewRegistrationService(userRepo, tokenRepo, security.DefaultPasswordValidator())

	user, verification, err := service.RegisterUser(context.Background(), "alice", "alice@example.com", "", "Password123")
	if err != nil {
		t.Fatalf("RegisterUser returned error: %v", err)
	}

	if verification.Delivery != verificationDeliveryEmail {
		t.Fatalf("expected delivery email, got %s", verification.Delivery)
	}
	if verification.Token == "" {
		t.Fatalf("expected verification token for email delivery")
	}
	if !verification.ExpiresAt.After(time.Now().Add(-time.Minute)) {
		t.Fatalf("expected expires_at to be in the future, got %v", verification.ExpiresAt)
	}

	expectedHash := security.HashToken(verification.Token)

	if userRepo.createCalls != 1 {
		t.Fatalf("expected Create to be called once, got %d", userRepo.createCalls)
	}

	if tokenRepo.createCalls != 1 {
		t.Fatalf("expected CreateVerification to be called once, got %d", tokenRepo.createCalls)
	}

	if tokenRepo.createdToken.UserID != user.ID {
		t.Fatalf("expected token user ID %s, got %s", user.ID, tokenRepo.createdToken.UserID)
	}
	if tokenRepo.createdToken.TokenHash != expectedHash {
		t.Fatalf("expected token hash %s, got %s", expectedHash, tokenRepo.createdToken.TokenHash)
	}
	if tokenRepo.createdToken.Purpose != verificationPurposeRegistration {
		t.Fatalf("expected purpose %s, got %s", verificationPurposeRegistration, tokenRepo.createdToken.Purpose)
	}
	if tokenRepo.createdToken.Metadata["delivery"] != verificationDeliveryEmail {
		t.Fatalf("expected metadata delivery email, got %v", tokenRepo.createdToken.Metadata["delivery"])
	}
	if tokenRepo.createdToken.Metadata["contact"] != "alice@example.com" {
		t.Fatalf("expected metadata contact email, got %v", tokenRepo.createdToken.Metadata["contact"])
	}

	if user.Status != domain.UserStatusPending {
		t.Fatalf("expected user status pending, got %s", user.Status)
	}

	if userRepo.createdUser.PasswordHash == "" {
		t.Fatalf("expected password hash to be stored")
	}

	if ok, err := security.VerifyPassword("Password123", userRepo.createdUser.PasswordHash); err != nil || !ok {
		t.Fatalf("expected stored hash to match original password")
	}
}

func TestRegistrationService_RegisterUser_PhoneFallbackCode(t *testing.T) {
	userRepo := &mockUserRepository{}
	tokenRepo := &mockTokenRepository{}

	service := NewRegistrationService(userRepo, tokenRepo, security.DefaultPasswordValidator())

	user, verification, err := service.RegisterUser(context.Background(), "alice", "", "+15555550123", "Password123")
	if err != nil {
		t.Fatalf("RegisterUser returned error: %v", err)
	}

	if verification.Delivery != verificationDeliveryPhone {
		t.Fatalf("expected delivery sms, got %s", verification.Delivery)
	}
	if verification.Code == "" {
		t.Fatalf("expected verification code for sms delivery")
	}
	if strings.TrimSpace(verification.Token) != "" {
		t.Fatalf("expected token to be empty for sms delivery")
	}

	expectedHash := security.HashToken(verification.Code)
	if tokenRepo.createdToken.TokenHash != expectedHash {
		t.Fatalf("expected token hash %s, got %s", expectedHash, tokenRepo.createdToken.TokenHash)
	}
	if tokenRepo.createdToken.Metadata["delivery"] != verificationDeliveryPhone {
		t.Fatalf("expected metadata delivery sms, got %v", tokenRepo.createdToken.Metadata["delivery"])
	}
	if tokenRepo.createdToken.Metadata["contact"] != "+15555550123" {
		t.Fatalf("expected metadata contact phone, got %v", tokenRepo.createdToken.Metadata["contact"])
	}

	if user.Phone == nil || *user.Phone != "+15555550123" {
		t.Fatalf("expected phone to be stored on user")
	}
}

func TestRegistrationService_RegisterUser_ValidationErrors(t *testing.T) {
	service := NewRegistrationService(&mockUserRepository{}, &mockTokenRepository{}, security.DefaultPasswordValidator())

	cases := []struct {
		name     string
		username string
		email    string
		phone    string
		password string
	}{
		{"missing username", "", "a@example.com", "", "Password123"},
		{"missing contact", "alice", "", "", "Password123"},
		{"missing password", "alice", "a@example.com", "", ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := service.RegisterUser(context.Background(), tc.username, tc.email, tc.phone, tc.password); err == nil {
				t.Fatalf("expected error for %s", tc.name)
			}
		})
	}
}

func TestRegistrationService_RegisterUser_PasswordPolicyViolation(t *testing.T) {
	service := NewRegistrationService(&mockUserRepository{}, &mockTokenRepository{}, security.DefaultPasswordValidator())

	_, _, err := service.RegisterUser(context.Background(), "alice", "alice@example.com", "", "password")
	if !errors.Is(err, ErrPasswordPolicyViolation) {
		t.Fatalf("expected ErrPasswordPolicyViolation, got %v", err)
	}
}

func TestRegistrationService_RegisterUser_CreateError(t *testing.T) {
	userRepo := &mockUserRepository{createErr: errors.New("boom")}
	tokenRepo := &mockTokenRepository{}

	service := NewRegistrationService(userRepo, tokenRepo, security.DefaultPasswordValidator())

	if _, _, err := service.RegisterUser(context.Background(), "alice", "alice@example.com", "", "Password123"); err == nil {
		t.Fatalf("expected error when user creation fails")
	}

	if userRepo.createCalls != 1 {
		t.Fatalf("expected Create to be called once, got %d", userRepo.createCalls)
	}
}

func TestRegistrationService_RegisterUser_TokenError(t *testing.T) {
	userRepo := &mockUserRepository{}
	tokenRepo := &mockTokenRepository{createVerificationErr: errors.New("boom")}

	service := NewRegistrationService(userRepo, tokenRepo, security.DefaultPasswordValidator())

	if _, _, err := service.RegisterUser(context.Background(), "alice", "alice@example.com", "", "Password123"); err == nil {
		t.Fatalf("expected error when token creation fails")
	}

	if tokenRepo.createCalls != 1 {
		t.Fatalf("expected CreateVerification to be called once, got %d", tokenRepo.createCalls)
	}
}

func TestRegistrationService_VerifyCode_Success(t *testing.T) {
	userID := "user-123"
	code := "123456"
	tokenID := "token-123"

	token := domain.VerificationToken{
		ID:        tokenID,
		UserID:    userID,
		TokenHash: security.HashToken(code),
		Purpose:   verificationPurposeRegistration,
		ExpiresAt: time.Now().Add(time.Hour),
	}

	userRepo := &mockUserRepository{
		getByIDResult: &domain.User{ID: userID, Username: "alice", Status: domain.UserStatusPending},
	}
	tokenRepo := &mockTokenRepository{
		getVerificationResult: &token,
	}

	service := NewRegistrationService(userRepo, tokenRepo, security.DefaultPasswordValidator())

	user, err := service.VerifyCode(context.Background(), code)
	if err != nil {
		t.Fatalf("VerifyCode returned error: %v", err)
	}

	if user.ID != userID {
		t.Fatalf("expected user ID %s, got %s", userID, user.ID)
	}

	if user.Status != domain.UserStatusActive {
		t.Fatalf("expected user status active, got %s", user.Status)
	}

	if tokenRepo.consumeVerificationCalls != 1 || tokenRepo.consumeVerificationLastID != tokenID {
		t.Fatalf("expected ConsumeVerification to be called once with %s", tokenID)
	}

	if userRepo.updateStatusCalls != 1 || userRepo.updateStatusStatus != domain.UserStatusActive {
		t.Fatalf("expected UpdateStatus to mark user active, calls=%d status=%s", userRepo.updateStatusCalls, userRepo.updateStatusStatus)
	}

	expectedHash := security.HashToken(code)
	if tokenRepo.getVerificationLastHash != expectedHash {
		t.Fatalf("expected hash %s, got %s", expectedHash, tokenRepo.getVerificationLastHash)
	}
}

func TestRegistrationService_VerifyCode_Invalid(t *testing.T) {
	tokenRepo := &mockTokenRepository{getVerificationErr: repository.ErrNotFound}
	service := NewRegistrationService(&mockUserRepository{}, tokenRepo, security.DefaultPasswordValidator())

	if _, err := service.VerifyCode(context.Background(), "123456"); !errors.Is(err, ErrVerificationCodeInvalid) {
		t.Fatalf("expected ErrVerificationCodeInvalid, got %v", err)
	}
}

func TestRegistrationService_VerifyCode_Expired(t *testing.T) {
	code := "123456"
	token := domain.VerificationToken{
		ID:        "token-1",
		UserID:    "user-1",
		TokenHash: security.HashToken(code),
		Purpose:   verificationPurposeRegistration,
		ExpiresAt: time.Now().Add(-time.Minute),
	}

	tokenRepo := &mockTokenRepository{getVerificationResult: &token}
	service := NewRegistrationService(&mockUserRepository{}, tokenRepo, security.DefaultPasswordValidator())

	if _, err := service.VerifyCode(context.Background(), code); !errors.Is(err, ErrVerificationCodeExpired) {
		t.Fatalf("expected ErrVerificationCodeExpired, got %v", err)
	}
}

func TestRegistrationService_VerifyCode_InvalidState(t *testing.T) {
	code := "123456"
	now := time.Now().Add(time.Hour)

	cases := []struct {
		name  string
		token domain.VerificationToken
	}{
		{
			name: "wrong purpose",
			token: domain.VerificationToken{
				ID:        "token1",
				UserID:    "user1",
				TokenHash: security.HashToken(code),
				Purpose:   "other",
				ExpiresAt: now,
			},
		},
		{
			name: "already used",
			token: domain.VerificationToken{
				ID:        "token2",
				UserID:    "user1",
				TokenHash: security.HashToken(code),
				Purpose:   verificationPurposeRegistration,
				ExpiresAt: now,
				UsedAt:    ptrTime(time.Now()),
			},
		},
		{
			name: "revoked",
			token: domain.VerificationToken{
				ID:        "token3",
				UserID:    "user1",
				TokenHash: security.HashToken(code),
				Purpose:   verificationPurposeRegistration,
				ExpiresAt: now,
				RevokedAt: ptrTime(time.Now()),
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tokenRepo := &mockTokenRepository{getVerificationResult: &tc.token}
			service := NewRegistrationService(&mockUserRepository{}, tokenRepo, security.DefaultPasswordValidator())

			if _, err := service.VerifyCode(context.Background(), code); !errors.Is(err, ErrVerificationCodeInvalid) {
				t.Fatalf("expected ErrVerificationCodeInvalid, got %v", err)
			}
		})
	}
}

func TestRegistrationService_VerifyCode_UpdateStatusError(t *testing.T) {
	code := "123456"
	token := domain.VerificationToken{
		ID:        "token-1",
		UserID:    "user-1",
		TokenHash: security.HashToken(code),
		Purpose:   verificationPurposeRegistration,
		ExpiresAt: time.Now().Add(time.Hour),
	}

	userRepo := &mockUserRepository{
		getByIDResult:   &domain.User{ID: "user-1", Status: domain.UserStatusPending},
		updateStatusErr: errors.New("boom"),
	}

	tokenRepo := &mockTokenRepository{getVerificationResult: &token}
	service := NewRegistrationService(userRepo, tokenRepo, security.DefaultPasswordValidator())

	if _, err := service.VerifyCode(context.Background(), code); err == nil || !strings.Contains(err.Error(), "activate user") {
		t.Fatalf("expected activate user error, got %v", err)
	}
}

func TestRegistrationService_VerifyCode_ConsumeError(t *testing.T) {
	code := "123456"
	token := domain.VerificationToken{
		ID:        "token-1",
		UserID:    "user-1",
		TokenHash: security.HashToken(code),
		Purpose:   verificationPurposeRegistration,
		ExpiresAt: time.Now().Add(time.Hour),
	}

	userRepo := &mockUserRepository{
		getByIDResult: &domain.User{ID: "user-1", Status: domain.UserStatusPending},
	}

	tokenRepo := &mockTokenRepository{
		getVerificationResult:  &token,
		consumeVerificationErr: errors.New("boom"),
	}

	service := NewRegistrationService(userRepo, tokenRepo, security.DefaultPasswordValidator())

	if _, err := service.VerifyCode(context.Background(), code); err == nil || !strings.Contains(err.Error(), "consume verification token") {
		t.Fatalf("expected consume verification token error, got %v", err)
	}
}

func ptrTime(t time.Time) *time.Time {
	return &t
}
