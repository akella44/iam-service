package usecase

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/arklim/social-platform-iam/internal/core/domain"
	"github.com/arklim/social-platform-iam/internal/infra/config"
	"github.com/arklim/social-platform-iam/internal/infra/security"
	"github.com/arklim/social-platform-iam/internal/repository"
)

type passwordResetSessionRepoMock struct {
	sessions    map[string]*domain.Session
	tokenCounts map[string]int
	toFail      map[string]error
	events      []domain.SessionEvent
	revokedIDs  []string
	now         func() time.Time
}

func TestPasswordResetServiceChangePasswordDefaultsUserIDToActor(t *testing.T) {
	currentHash, err := security.HashPassword("Curr3nt#Passw0rd")
	if err != nil {
		t.Fatalf("hash current password: %v", err)
	}

	user := domain.User{ID: "user-change-actor-default", PasswordHash: currentHash}
	userRepo := &passwordResetUserRepoMock{
		byID: map[string]domain.User{user.ID: user},
	}
	tokenRepo := &passwordResetTokenRepoMock{}
	svc := NewPasswordResetService(&config.AppConfig{}, userRepo, tokenRepo, nil, nil, nil, nil, nil, nil)

	newPassword := "Valid#Passphrase123!"
	result, err := svc.ChangePassword(context.Background(), PasswordChangeInput{
		ActorID:         user.ID,
		CurrentPassword: "Curr3nt#Passw0rd",
		NewPassword:     newPassword,
	})
	if err != nil {
		t.Fatalf("ChangePassword returned error: %v", err)
	}
	if result == nil {
		t.Fatalf("expected result, got nil")
	}
	if result.UserID != user.ID {
		t.Fatalf("expected user id %s, got %s", user.ID, result.UserID)
	}
	if userRepo.updatedID != user.ID {
		t.Fatalf("expected update for user %s, got %s", user.ID, userRepo.updatedID)
	}
	if ok, verErr := security.VerifyPassword(newPassword, userRepo.updatedHash); verErr != nil || !ok {
		t.Fatalf("expected updated hash to validate new password")
	}
	if !tokenRepo.revokedRefreshTokensForUser || tokenRepo.revokedRefreshTokensUserID != user.ID {
		t.Fatalf("expected refresh tokens revoked for user")
	}
	if !tokenRepo.revokedJTIsForUser || tokenRepo.revokedJTIsUserID != user.ID {
		t.Fatalf("expected JTIs revoked for user")
	}
}

func newPasswordResetSessionRepoMock(now func() time.Time, sessions ...domain.Session) *passwordResetSessionRepoMock {
	repo := &passwordResetSessionRepoMock{
		sessions:    make(map[string]*domain.Session),
		tokenCounts: make(map[string]int),
		toFail:      make(map[string]error),
		now:         now,
	}
	for i := range sessions {
		s := sessions[i]
		sessionCopy := s
		repo.sessions[sessionCopy.ID] = &sessionCopy
	}
	return repo
}

func (m *passwordResetSessionRepoMock) Create(_ context.Context, _ domain.Session) error {
	return errors.New("unexpected call: Create session")
}

func (m *passwordResetSessionRepoMock) Get(_ context.Context, sessionID string) (*domain.Session, error) {
	session, ok := m.sessions[sessionID]
	if !ok {
		return nil, repository.ErrNotFound
	}
	copy := *session
	if session.RevokedAt != nil {
		revoked := session.RevokedAt.UTC()
		copy.RevokedAt = &revoked
	}
	if session.RevokeReason != nil {
		reason := *session.RevokeReason
		copy.RevokeReason = &reason
	}
	return &copy, nil
}

func (m *passwordResetSessionRepoMock) ListByUser(_ context.Context, userID string) ([]domain.Session, error) {
	result := []domain.Session{}
	for _, session := range m.sessions {
		if !strings.EqualFold(session.UserID, userID) {
			continue
		}
		copy := *session
		result = append(result, copy)
	}
	return result, nil
}

func (m *passwordResetSessionRepoMock) UpdateLastSeen(_ context.Context, _ string, _ *string, _ *string) error {
	return nil
}

func (m *passwordResetSessionRepoMock) Revoke(_ context.Context, sessionID, reason string) error {
	if err, exists := m.toFail[sessionID]; exists {
		return err
	}
	session, ok := m.sessions[sessionID]
	if !ok {
		return repository.ErrNotFound
	}
	revokedAt := time.Now().UTC()
	if m.now != nil {
		revokedAt = m.now().UTC()
	}
	session.RevokedAt = &revokedAt
	reasonCopy := strings.TrimSpace(reason)
	if reasonCopy != "" {
		session.RevokeReason = &reasonCopy
	} else {
		session.RevokeReason = nil
	}
	m.revokedIDs = append(m.revokedIDs, sessionID)
	return nil
}

func (m *passwordResetSessionRepoMock) RevokeByFamily(_ context.Context, _ string, _ string) (int, error) {
	return 0, errors.New("unexpected call: RevokeByFamily")
}

func (m *passwordResetSessionRepoMock) RevokeAllForUser(_ context.Context, _ string, _ string) (int, error) {
	return 0, errors.New("unexpected call: RevokeAllForUser")
}

func (m *passwordResetSessionRepoMock) StoreEvent(_ context.Context, event domain.SessionEvent) error {
	m.events = append(m.events, event)
	return nil
}

func (m *passwordResetSessionRepoMock) RevokeSessionAccessTokens(_ context.Context, sessionID, _ string) (int, error) {
	return m.tokenCounts[sessionID], nil
}

type passwordResetEventPublisherMock struct {
	passwordChanged        []domain.PasswordChangedEvent
	passwordResetRequested []domain.PasswordResetRequestedEvent
	sessionRevoked         []domain.SessionRevokedEvent
}

func (m *passwordResetEventPublisherMock) PublishUserRegistered(_ context.Context, _ domain.UserRegisteredEvent) error {
	return nil
}

func (m *passwordResetEventPublisherMock) PublishPasswordChanged(_ context.Context, event domain.PasswordChangedEvent) error {
	m.passwordChanged = append(m.passwordChanged, event)
	return nil
}

func (m *passwordResetEventPublisherMock) PublishPasswordResetRequested(_ context.Context, event domain.PasswordResetRequestedEvent) error {
	m.passwordResetRequested = append(m.passwordResetRequested, event)
	return nil
}

func (m *passwordResetEventPublisherMock) PublishRolesAssigned(_ context.Context, _ domain.RolesAssignedEvent) error {
	return nil
}

func (m *passwordResetEventPublisherMock) PublishRolesRevoked(_ context.Context, _ domain.RolesRevokedEvent) error {
	return nil
}

func (m *passwordResetEventPublisherMock) PublishSessionRevoked(_ context.Context, event domain.SessionRevokedEvent) error {
	m.sessionRevoked = append(m.sessionRevoked, event)
	return nil
}

func TestPasswordResetServiceChangePasswordRevokesSessionsAndTokens(t *testing.T) {
	currentHash, err := security.HashPassword("Curr3nt#Passw0rd")
	if err != nil {
		t.Fatalf("hash current password: %v", err)
	}

	user := domain.User{ID: "user-change-1", Username: "change-user", PasswordHash: currentHash}

	oldHash, err := security.HashPassword("SomeOldPass#1")
	if err != nil {
		t.Fatalf("hash old password: %v", err)
	}
	userRepo := &passwordResetUserRepoMock{
		byID: map[string]domain.User{user.ID: user},
		history: []domain.UserPasswordHistory{{
			UserID:       user.ID,
			PasswordHash: oldHash,
			SetAt:        time.Now().Add(-24 * time.Hour),
		}},
	}

	tokenRepo := &passwordResetTokenRepoMock{jtiRevokeCount: 3}
	events := &passwordResetEventPublisherMock{}

	fixedNow := time.Date(2025, 10, 24, 9, 30, 0, 0, time.UTC)
	session := domain.Session{
		ID:        "sess-123",
		UserID:    user.ID,
		CreatedAt: fixedNow.Add(-4 * time.Hour),
		LastSeen:  fixedNow.Add(-10 * time.Minute),
		ExpiresAt: fixedNow.Add(6 * time.Hour),
	}
	sessionRepo := newPasswordResetSessionRepoMock(func() time.Time { return fixedNow }, session)
	sessionRepo.tokenCounts[session.ID] = 2
	sessionService := NewSessionService(sessionRepo, nil, events, nil)
	sessionService.WithClock(func() time.Time { return fixedNow })

	svc := NewPasswordResetService(&config.AppConfig{}, userRepo, tokenRepo, nil, events, sessionService, nil, nil, nil)
	svc.WithClock(func() time.Time { return fixedNow })

	newPassword := "Aurora#Sunset*Galaxy2025!"
	result, err := svc.ChangePassword(context.Background(), PasswordChangeInput{
		UserID:          user.ID,
		ActorID:         user.ID,
		CurrentPassword: "Curr3nt#Passw0rd",
		NewPassword:     newPassword,
		IP:              "203.0.113.10",
		UserAgent:       "Mozilla/5.0",
	})
	if err != nil {
		t.Fatalf("ChangePassword returned error: %v", err)
	}
	if result == nil {
		t.Fatalf("expected result, got nil")
	}
	if result.UserID != user.ID {
		t.Fatalf("expected user id %s, got %s", user.ID, result.UserID)
	}
	if got := result.SessionsRevoked; got != 1 {
		t.Fatalf("expected sessions revoked 1, got %d", got)
	}
	if got := result.TokensRevoked; got != 2 {
		t.Fatalf("expected tokens revoked 2, got %d", got)
	}
	if !tokenRepo.revokedRefreshTokensForUser || tokenRepo.revokedRefreshTokensUserID != user.ID {
		t.Fatalf("expected refresh tokens revoked for user")
	}
	if !tokenRepo.revokedJTIsForUser || tokenRepo.revokedJTIsUserID != user.ID {
		t.Fatalf("expected JTIs revoked for user")
	}
	if tokenRepo.revokedJTIsReason != passwordChangeReason {
		t.Fatalf("expected revoke reason %s, got %s", passwordChangeReason, tokenRepo.revokedJTIsReason)
	}
	if ok, err := security.VerifyPassword(newPassword, userRepo.updatedHash); err != nil || !ok {
		t.Fatalf("expected updated hash to validate new password")
	}
	if userRepo.addHistoryCalls != 1 {
		t.Fatalf("expected add history to be called once, got %d", userRepo.addHistoryCalls)
	}
	if userRepo.trimHistoryCalls != 1 {
		t.Fatalf("expected trim history to be called once, got %d", userRepo.trimHistoryCalls)
	}
	if len(events.passwordChanged) != 1 {
		t.Fatalf("expected password changed event, got %d", len(events.passwordChanged))
	}
	if len(sessionRepo.events) != 1 {
		t.Fatalf("expected session event stored, got %d", len(sessionRepo.events))
	}
}

func TestPasswordResetServiceChangePasswordInvalidCurrentPassword(t *testing.T) {
	currentHash, err := security.HashPassword("Curr3nt#Passw0rd")
	if err != nil {
		t.Fatalf("hash current password: %v", err)
	}
	user := domain.User{ID: "user-change-invalid", PasswordHash: currentHash}
	userRepo := &passwordResetUserRepoMock{
		byID: map[string]domain.User{user.ID: user},
	}
	tokenRepo := &passwordResetTokenRepoMock{}
	svc := NewPasswordResetService(&config.AppConfig{}, userRepo, tokenRepo, nil, nil, nil, nil, nil, nil)

	_, err = svc.ChangePassword(context.Background(), PasswordChangeInput{
		UserID:          user.ID,
		ActorID:         user.ID,
		CurrentPassword: "Incorrect#123",
		NewPassword:     "Valid#Passw0rd123",
	})
	if !errors.Is(err, ErrCurrentPasswordInvalid) {
		t.Fatalf("expected ErrCurrentPasswordInvalid, got %v", err)
	}
	if tokenRepo.revokedRefreshTokensForUser {
		t.Fatalf("expected no refresh token revocation on failure")
	}
}

func TestPasswordResetServiceChangePasswordRejectsReusedPassword(t *testing.T) {
	currentHash, err := security.HashPassword("Curr3nt#Passw0rd")
	if err != nil {
		t.Fatalf("hash current password: %v", err)
	}
	reusedHash, err := security.HashPassword("Aurora#Sunset*Galaxy2025!")
	if err != nil {
		t.Fatalf("hash reused password: %v", err)
	}
	user := domain.User{ID: "user-change-reuse", PasswordHash: currentHash}
	userRepo := &passwordResetUserRepoMock{
		byID: map[string]domain.User{user.ID: user},
		history: []domain.UserPasswordHistory{{
			UserID:       user.ID,
			PasswordHash: reusedHash,
			SetAt:        time.Now().Add(-2 * time.Hour),
		}},
	}
	svc := NewPasswordResetService(&config.AppConfig{}, userRepo, &passwordResetTokenRepoMock{}, nil, nil, nil, nil, nil, nil)

	_, err = svc.ChangePassword(context.Background(), PasswordChangeInput{
		UserID:          user.ID,
		ActorID:         user.ID,
		CurrentPassword: "Curr3nt#Passw0rd",
		NewPassword:     "Aurora#Sunset*Galaxy2025!",
	})
	if !errors.Is(err, ErrNewPasswordInvalid) {
		t.Fatalf("expected ErrNewPasswordInvalid, got %v", err)
	}
}
