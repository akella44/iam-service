package usecase

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/arklim/social-platform-iam/internal/core/domain"
	"github.com/arklim/social-platform-iam/internal/core/port"
	"github.com/arklim/social-platform-iam/internal/infra/security"
	"github.com/arklim/social-platform-iam/internal/repository"
)

const strongResetPassword = "C0mplex!Passphrase#2025"

type passwordResetUserRepoMock struct {
	byIdentifier     map[string]domain.User
	byID             map[string]domain.User
	updatedID        string
	updatedHash      string
	updatedAlgo      string
	updatedAt        time.Time
	history          []domain.UserPasswordHistory
	addHistoryCalls  int
	trimHistoryCalls int
}

func (m *passwordResetUserRepoMock) Create(context.Context, domain.User) error {
	return errors.New("unexpected call: Create")
}

func (m *passwordResetUserRepoMock) GetByID(_ context.Context, id string) (*domain.User, error) {
	if user, ok := m.byID[id]; ok {
		u := user
		return &u, nil
	}
	return nil, repository.ErrNotFound
}

func (m *passwordResetUserRepoMock) GetByIdentifier(_ context.Context, identifier string) (*domain.User, error) {
	if user, ok := m.byIdentifier[identifier]; ok {
		u := user
		return &u, nil
	}
	return nil, repository.ErrNotFound
}

func (m *passwordResetUserRepoMock) UpdateStatus(context.Context, string, domain.UserStatus) error {
	return errors.New("unexpected call: UpdateStatus")
}

func (m *passwordResetUserRepoMock) UpdatePassword(_ context.Context, id string, hash string, algo string, changedAt time.Time) error {
	m.updatedID = id
	m.updatedHash = hash
	m.updatedAlgo = algo
	m.updatedAt = changedAt
	return nil
}

func (m *passwordResetUserRepoMock) AssignRoles(context.Context, string, []string) error {
	return errors.New("unexpected call: AssignRoles")
}

func (m *passwordResetUserRepoMock) RevokeRoles(context.Context, string, []string) error {
	return errors.New("unexpected call: RevokeRoles")
}

func (m *passwordResetUserRepoMock) GetUserRoles(context.Context, string) ([]domain.UserRole, error) {
	return nil, errors.New("unexpected call: GetUserRoles")
}

func (m *passwordResetUserRepoMock) ListPasswordHistory(_ context.Context, userID string, limit int) ([]domain.UserPasswordHistory, error) {
	if strings.TrimSpace(userID) == "" {
		return nil, fmt.Errorf("user id is required")
	}
	history := make([]domain.UserPasswordHistory, len(m.history))
	copy(history, m.history)
	if limit > 0 && len(history) > limit {
		history = history[:limit]
	}
	return history, nil
}

func (m *passwordResetUserRepoMock) AddPasswordHistory(_ context.Context, entry domain.UserPasswordHistory) error {
	if strings.TrimSpace(entry.UserID) == "" {
		return fmt.Errorf("user id is required")
	}
	m.history = append([]domain.UserPasswordHistory{entry}, m.history...)
	m.addHistoryCalls++
	return nil
}

func (m *passwordResetUserRepoMock) TrimPasswordHistory(_ context.Context, userID string, maxEntries int) error {
	if strings.TrimSpace(userID) == "" {
		return fmt.Errorf("user id is required")
	}
	if maxEntries <= 0 {
		m.history = nil
		m.trimHistoryCalls++
		return nil
	}
	if len(m.history) > maxEntries {
		m.history = m.history[:maxEntries]
	}
	m.trimHistoryCalls++
	return nil
}

func (m *passwordResetUserRepoMock) Update(context.Context, domain.User) error {
	return errors.New("unexpected call: Update")
}

func (m *passwordResetUserRepoMock) SoftDelete(context.Context, string) error {
	return errors.New("unexpected call: SoftDelete")
}

func (m *passwordResetUserRepoMock) List(context.Context, port.UserFilter) ([]domain.User, error) {
	return nil, errors.New("unexpected call: List")
}

func (m *passwordResetUserRepoMock) Count(context.Context, port.UserFilter) (int, error) {
	return 0, errors.New("unexpected call: Count")
}

type passwordResetTokenRepoMock struct {
	storedToken                 *domain.PasswordResetToken
	consumedID                  string
	createErr                   error
	getErr                      error
	consumeErr                  error
	revokedRefreshTokensForUser bool
	revokedRefreshTokensUserID  string
}

func (m *passwordResetTokenRepoMock) CreateVerification(context.Context, domain.VerificationToken) error {
	return errors.New("unexpected call: CreateVerification")
}

func (m *passwordResetTokenRepoMock) GetVerificationByHash(context.Context, string) (*domain.VerificationToken, error) {
	return nil, errors.New("unexpected call: GetVerificationByHash")
}

func (m *passwordResetTokenRepoMock) ConsumeVerification(context.Context, string) error {
	return errors.New("unexpected call: ConsumeVerification")
}

func (m *passwordResetTokenRepoMock) CreatePasswordReset(_ context.Context, token domain.PasswordResetToken) error {
	if m.createErr != nil {
		return m.createErr
	}
	copy := token
	m.storedToken = &copy
	return nil
}

func (m *passwordResetTokenRepoMock) GetPasswordResetByHash(_ context.Context, hash string) (*domain.PasswordResetToken, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	if m.storedToken == nil {
		return nil, repository.ErrNotFound
	}
	if m.storedToken.TokenHash != hash {
		return nil, repository.ErrNotFound
	}
	copy := *m.storedToken
	return &copy, nil
}

func (m *passwordResetTokenRepoMock) ConsumePasswordReset(_ context.Context, id string) error {
	if m.consumeErr != nil {
		return m.consumeErr
	}
	m.consumedID = id
	m.storedToken = nil
	return nil
}

func (m *passwordResetTokenRepoMock) CreateRefreshToken(context.Context, domain.RefreshToken) error {
	return errors.New("unexpected call: CreateRefreshToken")
}

func (m *passwordResetTokenRepoMock) GetRefreshTokenByHash(context.Context, string) (*domain.RefreshToken, error) {
	return nil, errors.New("unexpected call: GetRefreshTokenByHash")
}

func (m *passwordResetTokenRepoMock) RevokeRefreshToken(context.Context, string) error {
	return errors.New("unexpected call: RevokeRefreshToken")
}

func (m *passwordResetTokenRepoMock) MarkRefreshTokenUsed(context.Context, string, time.Time) error {
	return nil
}

func (m *passwordResetTokenRepoMock) RevokeRefreshTokensByFamily(context.Context, string, string) (int, error) {
	return 0, nil
}

func (m *passwordResetTokenRepoMock) RevokeRefreshTokensForUser(_ context.Context, userID string) error {
	m.revokedRefreshTokensForUser = true
	m.revokedRefreshTokensUserID = userID
	return nil
}

func (m *passwordResetTokenRepoMock) UpdateRefreshTokenIssuedVersion(context.Context, string, int64) error {
	return nil
}

func TestPasswordResetServiceInitiateEmail(t *testing.T) {
	user := domain.User{ID: "user-1", Email: "person@example.com"}
	userRepo := &passwordResetUserRepoMock{
		byIdentifier: map[string]domain.User{
			"person@example.com": user,
		},
		byID: map[string]domain.User{
			user.ID: user,
		},
	}
	tokenRepo := &passwordResetTokenRepoMock{}

	svc := NewPasswordResetService(nil, userRepo, tokenRepo, nil, nil, nil, nil, nil, nil)
	fixed := time.Date(2023, 7, 10, 12, 0, 0, 0, time.UTC)
	svc.WithClock(func() time.Time { return fixed })
	svc.WithTTL(30 * time.Minute)

	res, err := svc.InitiateReset(context.Background(), "person@example.com")
	if err != nil {
		t.Fatalf("InitiateReset returned error: %v", err)
	}

	if res.Delivery != resetDeliveryEmail {
		t.Fatalf("expected delivery email, got %s", res.Delivery)
	}
	if res.Token == "" {
		t.Fatalf("expected token to be returned")
	}
	if res.Contact != "person@example.com" {
		t.Fatalf("expected contact to be person@example.com, got %s", res.Contact)
	}
	if tokenRepo.storedToken == nil {
		t.Fatalf("expected token to be stored")
	}

	expectedHash := security.HashToken(res.Token)
	if tokenRepo.storedToken.TokenHash != expectedHash {
		t.Fatalf("expected stored hash %s, got %s", expectedHash, tokenRepo.storedToken.TokenHash)
	}
	if !tokenRepo.storedToken.ExpiresAt.Equal(fixed.Add(30 * time.Minute)) {
		t.Fatalf("expected expires_at %v, got %v", fixed.Add(30*time.Minute), tokenRepo.storedToken.ExpiresAt)
	}
	if tokenRepo.storedToken.Metadata["delivery"] != resetDeliveryEmail {
		t.Fatalf("expected metadata delivery email, got %v", tokenRepo.storedToken.Metadata["delivery"])
	}
	if tokenRepo.storedToken.Metadata["contact"] != "person@example.com" {
		t.Fatalf("expected metadata contact email, got %v", tokenRepo.storedToken.Metadata["contact"])
	}
}

func TestPasswordResetServiceInitiateFallbackSMS(t *testing.T) {
	phone := "+15551234567"
	user := domain.User{ID: "user-2", Phone: &phone}
	userRepo := &passwordResetUserRepoMock{
		byIdentifier: map[string]domain.User{
			"someone": user,
		},
		byID: map[string]domain.User{
			user.ID: user,
		},
	}
	tokenRepo := &passwordResetTokenRepoMock{}

	svc := NewPasswordResetService(nil, userRepo, tokenRepo, nil, nil, nil, nil, nil, nil)
	fixed := time.Date(2023, 7, 10, 12, 0, 0, 0, time.UTC)
	svc.WithClock(func() time.Time { return fixed })
	svc.WithTTL(15 * time.Minute)

	res, err := svc.InitiateReset(context.Background(), "someone")
	if err != nil {
		t.Fatalf("InitiateReset returned error: %v", err)
	}

	if res.Delivery != resetDeliveryPhone {
		t.Fatalf("expected delivery sms, got %s", res.Delivery)
	}
	if res.Code == "" {
		t.Fatalf("expected sms code to be returned")
	}
	if res.Contact != "+15551234567" {
		t.Fatalf("expected contact to be +15551234567, got %s", res.Contact)
	}

	expectedHash := security.HashToken(res.Code)
	if tokenRepo.storedToken.TokenHash != expectedHash {
		t.Fatalf("expected stored hash %s, got %s", expectedHash, tokenRepo.storedToken.TokenHash)
	}
	if tokenRepo.storedToken.Metadata["delivery"] != resetDeliveryPhone {
		t.Fatalf("expected metadata delivery sms, got %v", tokenRepo.storedToken.Metadata["delivery"])
	}
	if tokenRepo.storedToken.Metadata["contact"] != "+15551234567" {
		t.Fatalf("expected metadata contact phone, got %v", tokenRepo.storedToken.Metadata["contact"])
	}
}

func TestPasswordResetServiceInitiateNoContact(t *testing.T) {
	user := domain.User{ID: "user-3"}
	userRepo := &passwordResetUserRepoMock{
		byIdentifier: map[string]domain.User{
			"nocontact": user,
		},
		byID: map[string]domain.User{
			user.ID: user,
		},
	}
	tokenRepo := &passwordResetTokenRepoMock{}

	svc := NewPasswordResetService(nil, userRepo, tokenRepo, nil, nil, nil, nil, nil, nil)

	_, err := svc.InitiateReset(context.Background(), "nocontact")
	if !errors.Is(err, ErrPasswordResetContactMissing) {
		t.Fatalf("expected ErrPasswordResetContactMissing, got %v", err)
	}
}

func TestPasswordResetServiceCompleteWithToken(t *testing.T) {
	originalHash, err := security.HashPassword("Oldpass123")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	user := domain.User{ID: "user-4", PasswordHash: originalHash}

	userRepo := &passwordResetUserRepoMock{
		byID: map[string]domain.User{
			user.ID: user,
		},
	}
	tokenRepo := &passwordResetTokenRepoMock{}

	svc := NewPasswordResetService(nil, userRepo, tokenRepo, nil, nil, nil, nil, nil, nil)
	fixed := time.Date(2023, 7, 10, 12, 0, 0, 0, time.UTC)
	svc.WithClock(func() time.Time { return fixed })

	record := domain.PasswordResetToken{
		ID:        "reset-1",
		UserID:    user.ID,
		TokenHash: security.HashToken("rawtoken"),
		ExpiresAt: fixed.Add(10 * time.Minute),
	}
	tokenRepo.storedToken = &record

	if err := svc.CompleteWithToken(context.Background(), "rawtoken", strongResetPassword); err != nil {
		t.Fatalf("CompleteWithToken returned error: %v", err)
	}

	if userRepo.updatedID != user.ID {
		t.Fatalf("expected UpdatePassword for %s, got %s", user.ID, userRepo.updatedID)
	}
	if userRepo.updatedAlgo != "argon2id" {
		t.Fatalf("expected argon2id algorithm, got %s", userRepo.updatedAlgo)
	}
	if userRepo.updatedAt.IsZero() {
		t.Fatalf("expected updatedAt to be set")
	}
	if ok, err := security.VerifyPassword(strongResetPassword, userRepo.updatedHash); err != nil || !ok {
		t.Fatalf("expected stored hash to match new password")
	}
	if tokenRepo.consumedID != record.ID {
		t.Fatalf("expected token %s to be consumed, got %s", record.ID, tokenRepo.consumedID)
	}
}

func TestPasswordResetServiceCompleteExpired(t *testing.T) {
	originalHash, err := security.HashPassword("Oldpass123")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	user := domain.User{ID: "user-5", PasswordHash: originalHash}

	userRepo := &passwordResetUserRepoMock{
		byID: map[string]domain.User{
			user.ID: user,
		},
	}
	tokenRepo := &passwordResetTokenRepoMock{}

	svc := NewPasswordResetService(nil, userRepo, tokenRepo, nil, nil, nil, nil, nil, nil)
	fixed := time.Date(2023, 7, 10, 12, 0, 0, 0, time.UTC)
	svc.WithClock(func() time.Time { return fixed })

	record := domain.PasswordResetToken{
		ID:        "reset-2",
		UserID:    user.ID,
		TokenHash: security.HashToken("rawtoken"),
		ExpiresAt: fixed.Add(-time.Minute),
	}
	tokenRepo.storedToken = &record

	err = svc.CompleteWithToken(context.Background(), "rawtoken", strongResetPassword)
	if !errors.Is(err, ErrPasswordResetTokenExpired) {
		t.Fatalf("expected ErrPasswordResetTokenExpired, got %v", err)
	}
}
