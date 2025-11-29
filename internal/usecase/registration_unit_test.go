package usecase

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/arklim/social-platform-iam/internal/core/domain"
	"github.com/arklim/social-platform-iam/internal/core/port"
	"github.com/arklim/social-platform-iam/internal/infra/security"
	"github.com/arklim/social-platform-iam/internal/repository"
)

const strongRegistrationPassword = "Sup3r!SecurePass#7890"

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

	listHistoryResult []domain.UserPasswordHistory
	listHistoryErr    error
	listHistoryCalls  int
	listHistoryUserID string
	listHistoryLimit  int

	addHistoryCalls int
	addHistoryErr   error

	trimHistoryCalls  int
	trimHistoryErr    error
	trimHistoryUserID string
	trimHistoryLimit  int

	lastHistoryEntry domain.UserPasswordHistory
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

func (m *mockUserRepository) AssignRoles(context.Context, string, []string) error {
	return errors.New("unexpected call: AssignRoles")
}

func (m *mockUserRepository) RevokeRoles(context.Context, string, []string) error {
	return errors.New("unexpected call: RevokeRoles")
}

func (m *mockUserRepository) GetUserRoles(context.Context, string) ([]domain.UserRole, error) {
	return nil, errors.New("unexpected call: GetUserRoles")
}

func (m *mockUserRepository) ListPasswordHistory(_ context.Context, userID string, limit int) ([]domain.UserPasswordHistory, error) {
	m.listHistoryCalls++
	m.listHistoryUserID = userID
	m.listHistoryLimit = limit
	if m.listHistoryErr != nil {
		return nil, m.listHistoryErr
	}
	if m.listHistoryResult == nil {
		return []domain.UserPasswordHistory{}, nil
	}

	out := make([]domain.UserPasswordHistory, len(m.listHistoryResult))
	copy(out, m.listHistoryResult)
	return out, nil
}

func (m *mockUserRepository) AddPasswordHistory(_ context.Context, entry domain.UserPasswordHistory) error {
	m.addHistoryCalls++
	m.lastHistoryEntry = entry
	return m.addHistoryErr
}

func (m *mockUserRepository) TrimPasswordHistory(_ context.Context, userID string, limit int) error {
	m.trimHistoryCalls++
	m.trimHistoryUserID = userID
	m.trimHistoryLimit = limit
	return m.trimHistoryErr
}

func (m *mockUserRepository) Update(context.Context, domain.User) error {
	return errors.New("unexpected call: Update")
}

func (m *mockUserRepository) SoftDelete(context.Context, string) error {
	return errors.New("unexpected call: SoftDelete")
}

func (m *mockUserRepository) List(context.Context, port.UserFilter) ([]domain.User, error) {
	return nil, errors.New("unexpected call: List")
}

func (m *mockUserRepository) Count(context.Context, port.UserFilter) (int, error) {
	return 0, errors.New("unexpected call: Count")
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

func (m *mockTokenRepository) MarkRefreshTokenUsed(context.Context, string, time.Time) error {
	return nil
}

func (m *mockTokenRepository) RevokeRefreshTokensByFamily(context.Context, string, string) (int, error) {
	return 0, nil
}

func (m *mockTokenRepository) RevokeRefreshTokensForUser(context.Context, string) error {
	return errors.New("unexpected call: RevokeRefreshTokensForUser")
}

func (m *mockTokenRepository) UpdateRefreshTokenIssuedVersion(context.Context, string, int64) error {
	return errors.New("unexpected call: UpdateRefreshTokenIssuedVersion")
}

func newRegistrationService(userRepo *mockUserRepository, tokenRepo *mockTokenRepository, publisher port.EventPublisher) *RegistrationService {
	return NewRegistrationService(userRepo, tokenRepo, security.NewPasswordPolicy(), publisher)
}

type mockEventPublisher struct {
	calls int
	event domain.UserRegisteredEvent
	err   error
}

func (m *mockEventPublisher) PublishUserRegistered(_ context.Context, event domain.UserRegisteredEvent) error {
	m.calls++
	m.event = event
	return m.err
}

func (m *mockEventPublisher) PublishPasswordChanged(context.Context, domain.PasswordChangedEvent) error {
	return nil
}

func (m *mockEventPublisher) PublishPasswordResetRequested(context.Context, domain.PasswordResetRequestedEvent) error {
	return nil
}

func (m *mockEventPublisher) PublishRolesAssigned(context.Context, domain.RolesAssignedEvent) error {
	return nil
}

func (m *mockEventPublisher) PublishRolesRevoked(context.Context, domain.RolesRevokedEvent) error {
	return nil
}

func (m *mockEventPublisher) PublishSessionRevoked(context.Context, domain.SessionRevokedEvent) error {
	return nil
}

func (m *mockEventPublisher) PublishSessionVersionBumped(context.Context, domain.SessionVersionBumpedEvent) error {
	return nil
}

func TestRegistrationService_RegisterUser_EmailMagicLink(t *testing.T) {
	userRepo := &mockUserRepository{}
	tokenRepo := &mockTokenRepository{}

	service := newRegistrationService(userRepo, tokenRepo, nil)

	user, verification, err := service.RegisterUser(context.Background(), "alice", "alice@example.com", "", strongRegistrationPassword)
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

	if ok, err := security.VerifyPassword(strongRegistrationPassword, userRepo.createdUser.PasswordHash); err != nil || !ok {
		t.Fatalf("expected stored hash to match original password")
	}

	if userRepo.listHistoryCalls != 1 {
		t.Fatalf("expected password history check to run once, got %d", userRepo.listHistoryCalls)
	}

	if userRepo.addHistoryCalls != 1 {
		t.Fatalf("expected password history entry to be stored once, got %d", userRepo.addHistoryCalls)
	}

	if userRepo.lastHistoryEntry.UserID != user.ID {
		t.Fatalf("expected password history user id %s, got %s", user.ID, userRepo.lastHistoryEntry.UserID)
	}

	if userRepo.trimHistoryCalls != 1 {
		t.Fatalf("expected password history trim to run once, got %d", userRepo.trimHistoryCalls)
	}

	if userRepo.trimHistoryUserID != user.ID {
		t.Fatalf("expected trim history for user %s, got %s", user.ID, userRepo.trimHistoryUserID)
	}

	if userRepo.trimHistoryLimit != defaultPasswordHistoryEntries {
		t.Fatalf("expected trim history limit %d, got %d", defaultPasswordHistoryEntries, userRepo.trimHistoryLimit)
	}
}

func TestRegistrationService_RegisterUser_PublishesEvent(t *testing.T) {
	userRepo := &mockUserRepository{}
	tokenRepo := &mockTokenRepository{}
	publisher := &mockEventPublisher{}

	service := newRegistrationService(userRepo, tokenRepo, publisher)
	fixedNow := time.Date(2025, 1, 2, 15, 4, 5, 0, time.UTC)
	service.WithClock(func() time.Time { return fixedNow })

	user, verification, err := service.RegisterUser(context.Background(), "bob", "bob@example.com", "", strongRegistrationPassword)
	if err != nil {
		t.Fatalf("RegisterUser returned error: %v", err)
	}

	if publisher.calls != 1 {
		t.Fatalf("expected event publisher to be called once, got %d", publisher.calls)
	}

	event := publisher.event
	if event.UserID != user.ID {
		t.Fatalf("expected event user ID %s, got %s", user.ID, event.UserID)
	}
	if event.Username != "bob" {
		t.Fatalf("expected username bob, got %s", event.Username)
	}
	if event.RegisteredAt != fixedNow {
		t.Fatalf("expected registered_at %v, got %v", fixedNow, event.RegisteredAt)
	}
	if event.RegistrationMethod != verificationDeliveryEmail {
		t.Fatalf("expected registration method %s, got %s", verificationDeliveryEmail, event.RegistrationMethod)
	}
	if event.Email == nil || *event.Email != "bob@example.com" {
		t.Fatalf("expected email pointer with value bob@example.com")
	}
	if event.Phone != nil {
		t.Fatalf("expected phone to be nil for email registration")
	}
	if verification.Delivery != verificationDeliveryEmail {
		t.Fatalf("expected delivery email, got %s", verification.Delivery)
	}
	if got := event.Metadata["verification_delivery"]; got != verificationDeliveryEmail {
		t.Fatalf("expected metadata delivery %s, got %v", verificationDeliveryEmail, got)
	}
}

func TestRegistrationService_RegisterUser_EventFailureDoesNotBlock(t *testing.T) {
	userRepo := &mockUserRepository{}
	tokenRepo := &mockTokenRepository{}
	publisher := &mockEventPublisher{err: errors.New("kafka down")}

	service := newRegistrationService(userRepo, tokenRepo, publisher)

	if _, _, err := service.RegisterUser(context.Background(), "carol", "carol@example.com", "", strongRegistrationPassword); err != nil {
		t.Fatalf("expected registration to succeed despite event failure, got %v", err)
	}

	if publisher.calls != 1 {
		t.Fatalf("expected publisher to be invoked even on failure")
	}
}

func TestRegistrationService_RegisterUser_PhoneFallbackCode(t *testing.T) {
	userRepo := &mockUserRepository{}
	tokenRepo := &mockTokenRepository{}

	service := newRegistrationService(userRepo, tokenRepo, nil)

	user, verification, err := service.RegisterUser(context.Background(), "alice", "", "+15555550123", strongRegistrationPassword)
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
	service := newRegistrationService(&mockUserRepository{}, &mockTokenRepository{}, nil)

	cases := []struct {
		name     string
		username string
		email    string
		phone    string
		password string
	}{
		{"missing username", "", "a@example.com", "", strongRegistrationPassword},
		{"missing contact", "alice", "", "", strongRegistrationPassword},
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
	service := newRegistrationService(&mockUserRepository{}, &mockTokenRepository{}, nil)

	_, _, err := service.RegisterUser(context.Background(), "alice", "alice@example.com", "", "password")
	if !errors.Is(err, ErrPasswordPolicyViolation) {
		t.Fatalf("expected ErrPasswordPolicyViolation, got %v", err)
	}
}

func TestRegistrationService_RegisterUser_PasswordHistoryViolation(t *testing.T) {
	hashed, err := security.HashPassword(strongRegistrationPassword)
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}

	userRepo := &mockUserRepository{
		listHistoryResult: []domain.UserPasswordHistory{{
			ID:           "history-1",
			UserID:       "user-1",
			PasswordHash: hashed,
			SetAt:        time.Now(),
		}},
	}
	tokenRepo := &mockTokenRepository{}

	service := newRegistrationService(userRepo, tokenRepo, nil)

	if _, _, err := service.RegisterUser(context.Background(), "dave", "dave@example.com", "", strongRegistrationPassword); !errors.Is(err, ErrPasswordPolicyViolation) {
		t.Fatalf("expected password reuse error, got %v", err)
	}

	if userRepo.createCalls != 0 {
		t.Fatalf("expected user not to be created when history check fails")
	}
}

func TestRegistrationService_RegisterUser_AddHistoryError(t *testing.T) {
	userRepo := &mockUserRepository{addHistoryErr: errors.New("db down")}
	tokenRepo := &mockTokenRepository{}

	service := newRegistrationService(userRepo, tokenRepo, nil)

	if _, _, err := service.RegisterUser(context.Background(), "erin", "erin@example.com", "", strongRegistrationPassword); err == nil || !strings.Contains(err.Error(), "store password history") {
		t.Fatalf("expected store password history error, got %v", err)
	}

	if userRepo.createCalls != 1 {
		t.Fatalf("expected user create to be attempted once, got %d", userRepo.createCalls)
	}

	if tokenRepo.createCalls != 0 {
		t.Fatalf("expected verification token not to be created when history storage fails")
	}

	if userRepo.trimHistoryCalls != 0 {
		t.Fatalf("expected trim history not to run when add fails")
	}
}

func TestRegistrationService_RegisterUser_TrimHistoryError(t *testing.T) {
	userRepo := &mockUserRepository{trimHistoryErr: errors.New("db down")}
	tokenRepo := &mockTokenRepository{}

	service := newRegistrationService(userRepo, tokenRepo, nil)

	if _, _, err := service.RegisterUser(context.Background(), "frank", "frank@example.com", "", strongRegistrationPassword); err == nil || !strings.Contains(err.Error(), "trim password history") {
		t.Fatalf("expected trim password history error, got %v", err)
	}

	if userRepo.createCalls != 1 {
		t.Fatalf("expected user create to run once, got %d", userRepo.createCalls)
	}

	if userRepo.trimHistoryCalls != 1 {
		t.Fatalf("expected trim history to be attempted once, got %d", userRepo.trimHistoryCalls)
	}

	if tokenRepo.createCalls != 0 {
		t.Fatalf("expected verification token not to be created when trim fails")
	}
}

func TestRegistrationService_RegisterUser_SkipTrimWhenHistoryLimitZero(t *testing.T) {
	userRepo := &mockUserRepository{}
	tokenRepo := &mockTokenRepository{}

	service := newRegistrationService(userRepo, tokenRepo, nil)
	service.WithHistoryLimit(0)

	if _, _, err := service.RegisterUser(context.Background(), "gina", "gina@example.com", "", strongRegistrationPassword); err != nil {
		t.Fatalf("RegisterUser returned error: %v", err)
	}

	if userRepo.addHistoryCalls != 1 {
		t.Fatalf("expected password history entry to be added once, got %d", userRepo.addHistoryCalls)
	}

	if userRepo.trimHistoryCalls != 0 {
		t.Fatalf("expected trim history not to run when limit is zero, got %d", userRepo.trimHistoryCalls)
	}
}

func TestRegistrationService_RegisterUser_CreateError(t *testing.T) {
	userRepo := &mockUserRepository{createErr: errors.New("boom")}
	tokenRepo := &mockTokenRepository{}

	service := newRegistrationService(userRepo, tokenRepo, nil)

	if _, _, err := service.RegisterUser(context.Background(), "alice", "alice@example.com", "", strongRegistrationPassword); err == nil {
		t.Fatalf("expected error when user creation fails")
	}

	if userRepo.createCalls != 1 {
		t.Fatalf("expected Create to be called once, got %d", userRepo.createCalls)
	}
}

func TestRegistrationService_RegisterUser_TokenError(t *testing.T) {
	userRepo := &mockUserRepository{}
	tokenRepo := &mockTokenRepository{createVerificationErr: errors.New("boom")}

	service := newRegistrationService(userRepo, tokenRepo, nil)

	if _, _, err := service.RegisterUser(context.Background(), "alice", "alice@example.com", "", strongRegistrationPassword); err == nil {
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

	service := newRegistrationService(userRepo, tokenRepo, nil)

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
	service := newRegistrationService(&mockUserRepository{}, tokenRepo, nil)

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
	service := newRegistrationService(&mockUserRepository{}, tokenRepo, nil)

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
			service := newRegistrationService(&mockUserRepository{}, tokenRepo, nil)

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
	service := newRegistrationService(userRepo, tokenRepo, nil)

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

	service := newRegistrationService(userRepo, tokenRepo, nil)

	if _, err := service.VerifyCode(context.Background(), code); err == nil || !strings.Contains(err.Error(), "consume verification token") {
		t.Fatalf("expected consume verification token error, got %v", err)
	}
}

func ptrTime(t time.Time) *time.Time {
	return &t
}
