package usecase

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/arklim/social-platform-iam/internal/core/domain"
	"github.com/arklim/social-platform-iam/internal/infra/config"
	"github.com/arklim/social-platform-iam/internal/infra/security"
)

type passwordResetRateLimitStoreMock struct {
	count       int
	limit       int
	oldest      time.Time
	hasOldest   bool
	trimCalls   int
	recordCalls int
}

func (m *passwordResetRateLimitStoreMock) CountAttempts(context.Context, string, time.Duration, time.Time) (int, error) {
	return m.count, nil
}

func (m *passwordResetRateLimitStoreMock) RecordAttempt(context.Context, string, time.Time) error {
	m.recordCalls++
	return nil
}

func (m *passwordResetRateLimitStoreMock) TrimWindow(context.Context, string, time.Duration, time.Time) error {
	m.trimCalls++
	return nil
}

func (m *passwordResetRateLimitStoreMock) OldestAttempt(context.Context, string, time.Duration, time.Time) (time.Time, bool, error) {
	return m.oldest, m.hasOldest, nil
}

func TestPasswordResetService_RequestPasswordReset_EnforcesRateLimit(t *testing.T) {
	cfg := &config.AppConfig{
		RateLimit: config.RateLimitSettings{
			PasswordResetMaxAttempts: 3,
			WindowDuration:           30 * time.Minute,
		},
	}
	rateLimits := &passwordResetRateLimitStoreMock{
		count:     3,
		limit:     3,
		hasOldest: true,
		oldest:    time.Now().Add(-5 * time.Minute),
	}
	svc := NewPasswordResetService(cfg, &passwordResetUserRepoMock{}, &passwordResetTokenRepoMock{}, rateLimits, nil, nil, nil, nil, nil)
	fixed := time.Date(2025, 10, 24, 10, 0, 0, 0, time.UTC)
	svc.WithClock(func() time.Time { return fixed })

	input := PasswordResetRequestInput{Identifier: "throttle@example.com"}
	_, err := svc.RequestPasswordReset(context.Background(), input)
	if err == nil {
		t.Fatalf("expected rate limit error")
	}
	var rateErr *RateLimitExceededError
	if !errors.As(err, &rateErr) {
		t.Fatalf("expected RateLimitExceededError, got %v", err)
	}
	if rateErr.Scope != passwordResetRateLimitScope {
		t.Fatalf("expected scope %s, got %s", passwordResetRateLimitScope, rateErr.Scope)
	}
	if rateErr.RetryAfter <= 0 {
		t.Fatalf("expected positive retry after, got %v", rateErr.RetryAfter)
	}
	if rateLimits.recordCalls != 0 {
		t.Fatalf("expected RecordAttempt not called when rate limited")
	}
}

func TestPasswordResetService_RequestPasswordReset_GeneratesArtifacts(t *testing.T) {
	fixed := time.Date(2025, 10, 24, 11, 0, 0, 0, time.UTC)
	phone := "+12065550123"
	user := domain.User{ID: "user-reset-otp", Username: "otp-user", Phone: &phone}
	userRepo := &passwordResetUserRepoMock{
		byIdentifier: map[string]domain.User{
			"otp-user": user,
		},
		byID: map[string]domain.User{
			user.ID: user,
		},
	}
	rateLimits := &passwordResetRateLimitStoreMock{}
	tokenRepo := &passwordResetTokenRepoMock{}
	events := &passwordResetEventPublisherMock{}
	svc := NewPasswordResetService(&config.AppConfig{RateLimit: config.RateLimitSettings{PasswordResetMaxAttempts: 5, WindowDuration: time.Hour}}, userRepo, tokenRepo, rateLimits, events, nil, nil, nil, nil)
	svc.WithClock(func() time.Time { return fixed })
	svc.WithTTL(45 * time.Minute)

	input := PasswordResetRequestInput{
		Identifier: "otp-user",
		IP:         "198.51.100.10",
		UserAgent:  "CLI",
	}

	result, err := svc.RequestPasswordReset(context.Background(), input)
	if err != nil {
		t.Fatalf("RequestPasswordReset returned error: %v", err)
	}
	if result == nil {
		t.Fatalf("expected result")
	}
	if result.Delivery != resetDeliveryPhone {
		t.Fatalf("expected sms delivery, got %s", result.Delivery)
	}
	if result.Code == "" {
		t.Fatalf("expected verification code")
	}
	if result.ExpiresAt != fixed.Add(45*time.Minute) {
		t.Fatalf("expected expires at %v, got %v", fixed.Add(45*time.Minute), result.ExpiresAt)
	}
	if tokenRepo.storedToken == nil {
		t.Fatalf("expected token persisted")
	}
	if tokenRepo.storedToken.Metadata["delivery"] != resetDeliveryPhone {
		t.Fatalf("expected metadata delivery sms")
	}
	if len(events.passwordResetRequested) != 1 {
		t.Fatalf("expected password reset requested event")
	}
	if rateLimits.recordCalls != 1 {
		t.Fatalf("expected record attempt invoked once, got %d", rateLimits.recordCalls)
	}
	if rateLimits.trimCalls != 1 {
		t.Fatalf("expected trim window invoked once, got %d", rateLimits.trimCalls)
	}
}

func TestPasswordResetService_ConfirmPasswordReset_CompletesFlow(t *testing.T) {
	fixed := time.Date(2025, 10, 24, 12, 0, 0, 0, time.UTC)
	currentHash, err := security.HashPassword("Curr3nt#Passw0rd")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	phone := "+12065550123"
	user := domain.User{ID: "user-confirm-reset", Username: "confirm-user", PasswordHash: currentHash, Phone: &phone}
	userRepo := &passwordResetUserRepoMock{
		byID: map[string]domain.User{
			user.ID: user,
		},
	}
	tokenRepo := &passwordResetTokenRepoMock{}
	rateLimits := &passwordResetRateLimitStoreMock{}
	sessions := newPasswordResetSessionRepoMock(func() time.Time { return fixed }, domain.Session{
		ID:        "sess-otp-1",
		UserID:    user.ID,
		CreatedAt: fixed.Add(-2 * time.Hour),
		ExpiresAt: fixed.Add(10 * time.Hour),
	})
	sessions.tokenCounts["sess-otp-1"] = 1
	events := &passwordResetEventPublisherMock{}
	sessionService := NewSessionService(sessions, nil, events, nil)
	sessionService.WithClock(func() time.Time { return fixed })
	svc := NewPasswordResetService(&config.AppConfig{}, userRepo, tokenRepo, rateLimits, events, sessionService, nil, nil, nil)
	svc.WithClock(func() time.Time { return fixed })

	code := "123456"
	tokenRepo.storedToken = &domain.PasswordResetToken{
		ID:        "reset-otp-1",
		UserID:    user.ID,
		TokenHash: security.HashToken(code),
		CreatedAt: fixed.Add(-5 * time.Minute),
		ExpiresAt: fixed.Add(30 * time.Minute),
		Metadata: map[string]any{
			"delivery":   resetDeliveryPhone,
			"request_id": "req-otp-1",
		},
	}

	result, err := svc.ConfirmPasswordReset(context.Background(), PasswordResetConfirmInput{
		Code:        code,
		NewPassword: "Nightfall#Orion*Cascade2025!",
		IP:          "198.51.100.20",
		UserAgent:   "CLI",
	})
	if err != nil {
		t.Fatalf("ConfirmPasswordReset returned error: %v", err)
	}
	if result == nil {
		t.Fatalf("expected result")
	}
	if result.UserID != user.ID {
		t.Fatalf("expected user id %s, got %s", user.ID, result.UserID)
	}
	if result.SessionsRevoked != 1 {
		t.Fatalf("expected 1 session revoked, got %d", result.SessionsRevoked)
	}
	if result.TokensRevoked != 1 {
		t.Fatalf("expected 1 access token revoked, got %d", result.TokensRevoked)
	}
	if tokenRepo.consumedID != "reset-otp-1" {
		t.Fatalf("expected token reset-otp-1 consumed")
	}
	if tokenRepo.storedToken != nil {
		t.Fatalf("expected token cleared after consumption")
	}
	if !tokenRepo.revokedRefreshTokensForUser || !tokenRepo.revokedJTIsForUser {
		t.Fatalf("expected token revocations triggered")
	}
	if tokenRepo.revokedJTIsReason != passwordResetReason {
		t.Fatalf("expected revoke reason %s, got %s", passwordResetReason, tokenRepo.revokedJTIsReason)
	}
	if userRepo.updatedID != user.ID {
		t.Fatalf("expected password update for %s, got %s", user.ID, userRepo.updatedID)
	}
	if userRepo.updatedHash == "" {
		t.Fatalf("expected updated hash to be recorded")
	}
	if ok, err := security.VerifyPassword("Nightfall#Orion*Cascade2025!", userRepo.updatedHash); err != nil {
		t.Fatalf("verify new password: %v", err)
	} else if !ok {
		t.Fatalf("verify new password returned false for hash %q", userRepo.updatedHash)
	}
	if len(events.passwordChanged) != 1 {
		t.Fatalf("expected password changed event published")
	}

	_, err = svc.ConfirmPasswordReset(context.Background(), PasswordResetConfirmInput{Code: code, NewPassword: "Nebula#Horizon*Fjord2026!"})
	if !errors.Is(err, ErrPasswordResetTokenInvalid) {
		t.Fatalf("expected token invalid on reuse, got %v", err)
	}
}

func TestPasswordResetService_ConfirmPasswordReset_Expired(t *testing.T) {
	fixed := time.Date(2025, 10, 24, 13, 0, 0, 0, time.UTC)
	currentHash, err := security.HashPassword("Curr3nt#Passw0rd")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	user := domain.User{ID: "user-confirm-expired", PasswordHash: currentHash}
	userRepo := &passwordResetUserRepoMock{
		byID: map[string]domain.User{
			user.ID: user,
		},
	}
	tokenRepo := &passwordResetTokenRepoMock{}
	svc := NewPasswordResetService(&config.AppConfig{}, userRepo, tokenRepo, nil, nil, nil, nil, nil, nil)
	svc.WithClock(func() time.Time { return fixed })

	code := "999999"
	tokenRepo.storedToken = &domain.PasswordResetToken{
		ID:        "reset-expired-1",
		UserID:    user.ID,
		TokenHash: security.HashToken(code),
		CreatedAt: fixed.Add(-2 * time.Hour),
		ExpiresAt: fixed.Add(-time.Minute),
	}

	_, err = svc.ConfirmPasswordReset(context.Background(), PasswordResetConfirmInput{
		Code:        code,
		NewPassword: "Starlight#Cascade*Temple2025!",
	})
	if !errors.Is(err, ErrPasswordResetTokenExpired) {
		t.Fatalf("expected expired error, got %v", err)
	}
}
