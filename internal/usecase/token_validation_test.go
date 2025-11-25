package usecase

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/arklim/social-platform-iam/internal/core/domain"
	"github.com/arklim/social-platform-iam/internal/infra/config"
	"github.com/arklim/social-platform-iam/internal/infra/security"
	"github.com/arklim/social-platform-iam/internal/repository"
)

type staticKeyProvider struct {
	private *rsa.PrivateKey
	kid     string
}

func (s *staticKeyProvider) GetSigningKey() (*rsa.PrivateKey, error) {
	return s.private, nil
}

func (s *staticKeyProvider) GetVerificationKey(kid string) (*rsa.PublicKey, error) {
	if kid != s.kid {
		return nil, security.ErrKeyNotFound
	}
	return &s.private.PublicKey, nil
}

type stubSessionRepo struct {
	getFn                func(ctx context.Context, sessionID string) (*domain.Session, error)
	revokeByFamilyFn     func(ctx context.Context, familyID, reason string) (int, error)
	revokeAccessTokensFn func(ctx context.Context, sessionID, reason string) (int, error)
}

func (s *stubSessionRepo) Create(context.Context, domain.Session) error {
	panic("unexpected call to Create")
}
func (s *stubSessionRepo) Get(ctx context.Context, sessionID string) (*domain.Session, error) {
	if s.getFn != nil {
		return s.getFn(ctx, sessionID)
	}
	return nil, repository.ErrNotFound
}
func (s *stubSessionRepo) ListByUser(context.Context, string) ([]domain.Session, error) {
	panic("unexpected call to ListByUser")
}
func (s *stubSessionRepo) UpdateLastSeen(context.Context, string, *string, *string) error { return nil }
func (s *stubSessionRepo) Revoke(context.Context, string, string) error                   { return nil }
func (s *stubSessionRepo) RevokeByFamily(ctx context.Context, familyID, reason string) (int, error) {
	if s.revokeByFamilyFn != nil {
		return s.revokeByFamilyFn(ctx, familyID, reason)
	}
	return 0, nil
}
func (s *stubSessionRepo) RevokeAllForUser(context.Context, string, string) (int, error) {
	return 0, nil
}
func (s *stubSessionRepo) StoreEvent(context.Context, domain.SessionEvent) error { return nil }
func (s *stubSessionRepo) RevokeSessionAccessTokens(ctx context.Context, sessionID, reason string) (int, error) {
	if s.revokeAccessTokensFn != nil {
		return s.revokeAccessTokensFn(ctx, sessionID, reason)
	}
	return 0, nil
}
func (s *stubSessionRepo) GetVersion(context.Context, string) (int64, error) {
	return 0, repository.ErrNotFound
}
func (s *stubSessionRepo) IncrementVersion(context.Context, string, string) (int64, error) {
	return 0, nil
}
func (s *stubSessionRepo) SetVersion(context.Context, string, int64) error { return nil }

type stubTokenRepo struct {
	revoked        map[string]bool
	revokeFamilyFn func(ctx context.Context, familyID, reason string) (int, error)
}

func (s *stubTokenRepo) CreateVerification(context.Context, domain.VerificationToken) error {
	panic("unexpected call to CreateVerification")
}
func (s *stubTokenRepo) GetVerificationByHash(context.Context, string) (*domain.VerificationToken, error) {
	panic("unexpected call to GetVerificationByHash")
}
func (s *stubTokenRepo) ConsumeVerification(context.Context, string) error {
	panic("unexpected call to ConsumeVerification")
}
func (s *stubTokenRepo) CreatePasswordReset(context.Context, domain.PasswordResetToken) error {
	panic("unexpected call")
}
func (s *stubTokenRepo) GetPasswordResetByHash(context.Context, string) (*domain.PasswordResetToken, error) {
	panic("unexpected call")
}
func (s *stubTokenRepo) ConsumePasswordReset(context.Context, string) error { panic("unexpected call") }
func (s *stubTokenRepo) CreateRefreshToken(context.Context, domain.RefreshToken) error {
	panic("unexpected call")
}
func (s *stubTokenRepo) GetRefreshTokenByHash(context.Context, string) (*domain.RefreshToken, error) {
	panic("unexpected call")
}
func (s *stubTokenRepo) RevokeRefreshToken(context.Context, string) error              { return nil }
func (s *stubTokenRepo) MarkRefreshTokenUsed(context.Context, string, time.Time) error { return nil }
func (s *stubTokenRepo) RevokeRefreshTokensByFamily(ctx context.Context, familyID, reason string) (int, error) {
	if s.revokeFamilyFn != nil {
		return s.revokeFamilyFn(ctx, familyID, reason)
	}
	return 0, nil
}
func (s *stubTokenRepo) RevokeRefreshTokensForUser(context.Context, string) error { return nil }
func (s *stubTokenRepo) UpdateRefreshTokenIssuedVersion(context.Context, string, int64) error {
	return nil
}
func (s *stubTokenRepo) TrackJTI(context.Context, domain.AccessTokenJTI) error         { return nil }
func (s *stubTokenRepo) RevokeJTI(context.Context, domain.RevokedAccessTokenJTI) error { return nil }
func (s *stubTokenRepo) RevokeJTIsBySession(context.Context, string, string) (int, error) {
	return 0, nil
}
func (s *stubTokenRepo) RevokeJTIsForUser(context.Context, string, string) (int, error) {
	return 0, nil
}
func (s *stubTokenRepo) IsJTIRevoked(_ context.Context, jti string) (bool, error) {
	if s.revoked == nil {
		return false, nil
	}
	return s.revoked[jti], nil
}
func (s *stubTokenRepo) CleanupExpiredJTIs(context.Context, time.Time) (int, error) { return 0, nil }

func TestTokenServiceValidateTokenActive(t *testing.T) {
	provider := generateKeyProvider(t)
	cfg := &config.AppConfig{App: config.AppSettings{Name: "iam-service"}}
	cfg.Redis.SessionVersionTTL = time.Minute

	now := time.Now().UTC()

	repo := &stubSessionRepo{
		getFn: func(_ context.Context, sessionID string) (*domain.Session, error) {
			return &domain.Session{
				ID:        sessionID,
				FamilyID:  "fam-123",
				UserID:    "user-1",
				Version:   3,
				CreatedAt: now.Add(-time.Hour),
				LastSeen:  now.Add(-5 * time.Minute),
				ExpiresAt: now.Add(time.Hour),
			}, nil
		},
	}

	tokenRepo := &stubTokenRepo{}
	cache := &stubSessionVersionCache{}

	service := NewTokenService(cfg, repo, tokenRepo, cache, provider, nil).WithClock(func() time.Time { return now })

	token := signToken(t, provider, "test-kid", security.AccessTokenOptions{
		UserID:         "user-1",
		SessionID:      "session-1",
		SessionVersion: 3,
		Issuer:         cfg.App.Name,
		Audience:       []string{cfg.App.Name},
		TTL:            time.Hour,
		IssuedAt:       now,
		NotBefore:      now,
	})

	result, err := service.ValidateToken(context.Background(), token)
	if err != nil {
		t.Fatalf("ValidateToken returned error: %v", err)
	}
	if result.Status != TokenValidationStatusActive {
		t.Fatalf("expected status active, got %v", result.Status)
	}
	if result.SessionVersion != 3 {
		t.Fatalf("expected session version 3, got %d", result.SessionVersion)
	}
}

func TestTokenServiceValidateTokenStale(t *testing.T) {
	provider := generateKeyProvider(t)
	cfg := &config.AppConfig{App: config.AppSettings{Name: "iam-service"}}
	cfg.Redis.SessionVersionTTL = time.Minute

	revokedSessions := 0
	revokedTokens := 0

	now := time.Now().UTC()

	repo := &stubSessionRepo{
		getFn: func(_ context.Context, sessionID string) (*domain.Session, error) {
			return &domain.Session{
				ID:        sessionID,
				FamilyID:  "fam-789",
				UserID:    "user-2",
				Version:   5,
				CreatedAt: now.Add(-2 * time.Hour),
				LastSeen:  now.Add(-time.Minute),
				ExpiresAt: now.Add(time.Hour),
			}, nil
		},
		revokeByFamilyFn: func(_ context.Context, familyID, reason string) (int, error) {
			if familyID != "fam-789" {
				t.Fatalf("unexpected family id %s", familyID)
			}
			revokedSessions++
			if reason != "session_version_mismatch" {
				t.Fatalf("unexpected revoke reason %s", reason)
			}
			return 1, nil
		},
	}

	tokenRepo := &stubTokenRepo{
		revokeFamilyFn: func(_ context.Context, familyID, reason string) (int, error) {
			if familyID != "fam-789" {
				t.Fatalf("unexpected family id %s", familyID)
			}
			if reason != "session_version_mismatch" {
				t.Fatalf("unexpected revoke reason %s", reason)
			}
			revokedTokens++
			return 1, nil
		},
	}

	cache := &stubSessionVersionCache{}
	service := NewTokenService(cfg, repo, tokenRepo, cache, provider, nil).WithClock(func() time.Time { return now })

	token := signToken(t, provider, "test-kid", security.AccessTokenOptions{
		UserID:         "user-2",
		SessionID:      "session-2",
		SessionVersion: 2,
		Issuer:         cfg.App.Name,
		Audience:       []string{cfg.App.Name},
		TTL:            time.Hour,
		IssuedAt:       now,
		NotBefore:      now,
	})

	result, err := service.ValidateToken(context.Background(), token)
	if err != nil {
		t.Fatalf("ValidateToken returned error: %v", err)
	}
	if result.Status != TokenValidationStatusStale {
		t.Fatalf("expected status stale, got %v", result.Status)
	}
	if result.SessionVersion != 5 {
		t.Fatalf("expected current version 5, got %d", result.SessionVersion)
	}
	if revokedSessions == 0 || revokedTokens == 0 {
		t.Fatalf("expected family revocation to be triggered")
	}
}

func TestTokenServiceValidateTokenAllowsRepositoryFailureWhenLenient(t *testing.T) {
	provider := generateKeyProvider(t)
	cfg := &config.AppConfig{App: config.AppSettings{Name: "iam-service"}}
	cfg.Redis.SessionVersionTTL = time.Minute

	now := time.Now().UTC()

	repo := &stubSessionRepo{
		getFn: func(_ context.Context, _ string) (*domain.Session, error) {
			return nil, fmt.Errorf("database offline")
		},
	}

	tokenRepo := &stubTokenRepo{}

	service := NewTokenService(cfg, repo, tokenRepo, nil, provider, nil).WithClock(func() time.Time { return now })

	token := signToken(t, provider, "test-kid", security.AccessTokenOptions{
		UserID:         "user-allow",
		SessionID:      "session-allow",
		SessionVersion: 1,
		Issuer:         cfg.App.Name,
		Audience:       []string{cfg.App.Name},
		TTL:            time.Hour,
		IssuedAt:       now,
		NotBefore:      now,
	})

	result, err := service.ValidateToken(context.Background(), token)
	if err != nil {
		t.Fatalf("ValidateToken returned error: %v", err)
	}
	if result.Status != TokenValidationStatusActive {
		t.Fatalf("expected status active, got %v", result.Status)
	}
}

func TestTokenServiceValidateTokenDeniesRepositoryFailureWhenStrict(t *testing.T) {
	provider := generateKeyProvider(t)
	cfg := &config.AppConfig{
		App:        config.AppSettings{Name: "iam-service"},
		Revocation: config.RevocationSettings{DegradationPolicy: "strict"},
	}
	cfg.Redis.SessionVersionTTL = time.Minute

	now := time.Now().UTC()

	repo := &stubSessionRepo{
		getFn: func(_ context.Context, _ string) (*domain.Session, error) {
			return nil, fmt.Errorf("database offline")
		},
	}

	tokenRepo := &stubTokenRepo{}

	service := NewTokenService(cfg, repo, tokenRepo, nil, provider, nil).WithClock(func() time.Time { return now })

	token := signToken(t, provider, "test-kid", security.AccessTokenOptions{
		UserID:         "user-deny",
		SessionID:      "session-deny",
		SessionVersion: 1,
		Issuer:         cfg.App.Name,
		Audience:       []string{cfg.App.Name},
		TTL:            time.Hour,
		IssuedAt:       now,
		NotBefore:      now,
	})

	result, err := service.ValidateToken(context.Background(), token)
	if err == nil {
		t.Fatalf("expected strict policy to return error")
	}
	if result != nil {
		t.Fatalf("expected nil result when strict policy errors")
	}
}

func TestTokenServiceValidateTokenInvalidWithoutSessionVersion(t *testing.T) {
	provider := generateKeyProvider(t)
	cfg := &config.AppConfig{App: config.AppSettings{Name: "iam-service"}}
	cfg.Redis.SessionVersionTTL = time.Minute

	now := time.Now().UTC()

	repo := &stubSessionRepo{
		getFn: func(_ context.Context, sessionID string) (*domain.Session, error) {
			return &domain.Session{
				ID:        sessionID,
				FamilyID:  "fam-999",
				UserID:    "user-7",
				Version:   3,
				CreatedAt: now.Add(-time.Hour),
				LastSeen:  now.Add(-5 * time.Minute),
				ExpiresAt: now.Add(time.Hour),
			}, nil
		},
	}

	tokenRepo := &stubTokenRepo{}
	cache := &stubSessionVersionCache{}

	service := NewTokenService(cfg, repo, tokenRepo, cache, provider, nil).WithClock(func() time.Time { return now })

	token := signToken(t, provider, "test-kid", security.AccessTokenOptions{
		UserID:         "user-7",
		SessionID:      "session-7",
		SessionVersion: 0,
		Issuer:         cfg.App.Name,
		Audience:       []string{cfg.App.Name},
		TTL:            time.Hour,
		IssuedAt:       now,
		NotBefore:      now,
	})

	result, err := service.ValidateToken(context.Background(), token)
	if err != nil {
		t.Fatalf("ValidateToken returned error: %v", err)
	}
	if result.Status != TokenValidationStatusInvalid {
		t.Fatalf("expected status invalid, got %v", result.Status)
	}
	if result.SessionVersion != 3 {
		t.Fatalf("expected authoritative version 3, got %d", result.SessionVersion)
	}
}

func TestTokenServiceValidateTokenSessionRevoked(t *testing.T) {
	provider := generateKeyProvider(t)
	cfg := &config.AppConfig{App: config.AppSettings{Name: "iam-service"}}
	cfg.Redis.SessionVersionTTL = time.Minute

	now := time.Now().UTC()
	revocationTime := now.Add(-time.Minute)
	revokeReason := "manual"

	repo := &stubSessionRepo{
		getFn: func(_ context.Context, sessionID string) (*domain.Session, error) {
			return &domain.Session{
				ID:           sessionID,
				FamilyID:     "fam-321",
				UserID:       "user-3",
				Version:      4,
				CreatedAt:    now.Add(-time.Hour),
				LastSeen:     now.Add(-5 * time.Minute),
				ExpiresAt:    now.Add(time.Hour),
				RevokedAt:    &revocationTime,
				RevokeReason: &revokeReason,
			}, nil
		},
	}

	tokenRepo := &stubTokenRepo{}
	cache := &stubSessionVersionCache{}

	service := NewTokenService(cfg, repo, tokenRepo, cache, provider, nil).WithClock(func() time.Time { return now })

	token := signToken(t, provider, "test-kid", security.AccessTokenOptions{
		UserID:         "user-3",
		SessionID:      "session-3",
		SessionVersion: 4,
		Issuer:         cfg.App.Name,
		Audience:       []string{cfg.App.Name},
		TTL:            time.Hour,
		IssuedAt:       now,
		NotBefore:      now,
	})

	result, err := service.ValidateToken(context.Background(), token)
	if err != nil {
		t.Fatalf("ValidateToken returned error: %v", err)
	}
	if result.Status != TokenValidationStatusRevoked {
		t.Fatalf("expected status revoked, got %v", result.Status)
	}
	if result.RevokedReason == "" {
		t.Fatalf("expected revoked reason to be populated")
	}
}

func TestTokenServiceValidateTokenExpired(t *testing.T) {
	provider := generateKeyProvider(t)
	cfg := &config.AppConfig{App: config.AppSettings{Name: "iam-service"}}
	cfg.Redis.SessionVersionTTL = time.Minute

	now := time.Now().UTC()

	repo := &stubSessionRepo{
		getFn: func(_ context.Context, sessionID string) (*domain.Session, error) {
			return &domain.Session{
				ID:        sessionID,
				FamilyID:  "fam-222",
				UserID:    "user-4",
				Version:   1,
				CreatedAt: now.Add(-time.Hour),
				LastSeen:  now.Add(-time.Minute),
				ExpiresAt: now.Add(time.Hour),
			}, nil
		},
	}

	tokenRepo := &stubTokenRepo{}
	cache := &stubSessionVersionCache{}

	service := NewTokenService(cfg, repo, tokenRepo, cache, provider, nil).WithClock(func() time.Time { return now })

	token := signToken(t, provider, "test-kid", security.AccessTokenOptions{
		UserID:         "user-4",
		SessionID:      "session-4",
		SessionVersion: 1,
		Issuer:         cfg.App.Name,
		Audience:       []string{cfg.App.Name},
		TTL:            time.Hour,
		IssuedAt:       now.Add(-2 * time.Hour),
		NotBefore:      now.Add(-2 * time.Hour),
	})

	result, err := service.ValidateToken(context.Background(), token)
	if err != nil {
		t.Fatalf("ValidateToken returned error: %v", err)
	}
	if result.Status != TokenValidationStatusExpired {
		t.Fatalf("expected status expired, got %v", result.Status)
	}
}

func TestTokenServiceValidateTokenRevokedByJTI(t *testing.T) {
	provider := generateKeyProvider(t)
	cfg := &config.AppConfig{App: config.AppSettings{Name: "iam-service"}}
	cfg.Redis.SessionVersionTTL = time.Minute

	now := time.Now().UTC()

	repo := &stubSessionRepo{
		getFn: func(_ context.Context, sessionID string) (*domain.Session, error) {
			return &domain.Session{
				ID:        sessionID,
				FamilyID:  "fam-555",
				UserID:    "user-5",
				Version:   1,
				CreatedAt: now.Add(-time.Hour),
				LastSeen:  now.Add(-time.Minute),
				ExpiresAt: now.Add(time.Hour),
			}, nil
		},
	}

	tokenRepo := &stubTokenRepo{revoked: map[string]bool{"jti-1": true}}
	cache := &stubSessionVersionCache{}

	service := NewTokenService(cfg, repo, tokenRepo, cache, provider, nil).WithClock(func() time.Time { return now })

	claims := mustClaims(t, security.AccessTokenOptions{
		UserID:         "user-5",
		SessionID:      "session-5",
		SessionVersion: 1,
		Issuer:         cfg.App.Name,
		Audience:       []string{cfg.App.Name},
		TTL:            time.Hour,
		IssuedAt:       now,
		NotBefore:      now,
		JTI:            "jti-1",
	})
	token := signClaims(t, provider, "test-kid", claims)

	result, err := service.ValidateToken(context.Background(), token)
	if err != nil {
		t.Fatalf("ValidateToken returned error: %v", err)
	}
	if result.Status != TokenValidationStatusRevoked {
		t.Fatalf("expected status revoked, got %v", result.Status)
	}
}

func TestTokenServiceValidateTokenRevokedByJTICache(t *testing.T) {
	provider := generateKeyProvider(t)
	cfg := &config.AppConfig{App: config.AppSettings{Name: "iam-service"}}
	cfg.Redis.SessionVersionTTL = time.Minute

	now := time.Now().UTC()

	repo := &stubSessionRepo{
		getFn: func(_ context.Context, sessionID string) (*domain.Session, error) {
			return &domain.Session{
				ID:        sessionID,
				FamilyID:  "fam-cache",
				UserID:    "user-cache",
				Version:   1,
				CreatedAt: now.Add(-time.Hour),
				LastSeen:  now.Add(-time.Minute),
				ExpiresAt: now.Add(time.Hour),
			}, nil
		},
	}

	jtiCache := &stubJTIDenylistCache{entries: map[string]bool{"jti-cache": true}}
	jtiMetrics := &stubJTIDenylistMetrics{}

	service := NewTokenService(cfg, repo, &stubTokenRepo{}, nil, provider, nil).
		WithClock(func() time.Time { return now }).
		WithJTIDenylist(jtiCache, jtiMetrics, 0, time.Minute)

	claims := mustClaims(t, security.AccessTokenOptions{
		UserID:         "user-cache",
		SessionID:      "session-cache",
		SessionVersion: 1,
		Issuer:         cfg.App.Name,
		Audience:       []string{cfg.App.Name},
		TTL:            time.Hour,
		IssuedAt:       now,
		NotBefore:      now,
		JTI:            "jti-cache",
	})
	token := signClaims(t, provider, "test-kid", claims)

	result, err := service.ValidateToken(context.Background(), token)
	if err != nil {
		t.Fatalf("ValidateToken returned error: %v", err)
	}
	if result.Status != TokenValidationStatusRevoked {
		t.Fatalf("expected revoked status, got %v", result.Status)
	}
	if result.RevokedReason != "token_revoked" {
		t.Fatalf("expected revoked reason token_revoked, got %s", result.RevokedReason)
	}
	if jtiMetrics.hits != 1 || jtiMetrics.denies != 1 {
		t.Fatalf("expected denylist metrics to increment, got hits=%d denies=%d", jtiMetrics.hits, jtiMetrics.denies)
	}
}

func TestTokenServiceValidateTokenAllowsFallbackOnCacheErrorLenient(t *testing.T) {
	provider := generateKeyProvider(t)
	cfg := &config.AppConfig{App: config.AppSettings{Name: "iam-service"}}
	cfg.Redis.SessionVersionTTL = time.Minute

	now := time.Now().UTC()

	repo := &stubSessionRepo{
		getFn: func(_ context.Context, sessionID string) (*domain.Session, error) {
			return &domain.Session{
				ID:        sessionID,
				FamilyID:  "fam-fallback",
				UserID:    "user-fallback",
				Version:   1,
				CreatedAt: now.Add(-time.Hour),
				LastSeen:  now.Add(-time.Minute),
				ExpiresAt: now.Add(time.Hour),
			}, nil
		},
	}

	jtiCache := &stubJTIDenylistCache{err: fmt.Errorf("cache offline")}
	jtiMetrics := &stubJTIDenylistMetrics{}
	tokenRepo := &stubTokenRepo{}

	service := NewTokenService(cfg, repo, tokenRepo, nil, provider, nil).
		WithClock(func() time.Time { return now }).
		WithJTIDenylist(jtiCache, jtiMetrics, 0, time.Minute)

	claims := mustClaims(t, security.AccessTokenOptions{
		UserID:         "user-fallback",
		SessionID:      "session-fallback",
		SessionVersion: 1,
		Issuer:         cfg.App.Name,
		Audience:       []string{cfg.App.Name},
		TTL:            time.Hour,
		IssuedAt:       now,
		NotBefore:      now,
		JTI:            "jti-fallback",
	})
	token := signClaims(t, provider, "test-kid", claims)

	result, err := service.ValidateToken(context.Background(), token)
	if err != nil {
		t.Fatalf("ValidateToken returned error: %v", err)
	}
	if result.Status != TokenValidationStatusActive {
		t.Fatalf("expected token to remain active, got %v", result.Status)
	}
	if jtiMetrics.misses != 0 {
		t.Fatalf("expected cache miss counter to remain zero, got %d", jtiMetrics.misses)
	}
}

func TestTokenServiceValidateTokenStrictDeniesOnCacheUnavailable(t *testing.T) {
	provider := generateKeyProvider(t)
	cfg := &config.AppConfig{
		App:        config.AppSettings{Name: "iam-service"},
		Revocation: config.RevocationSettings{DegradationPolicy: "strict"},
	}
	cfg.Redis.SessionVersionTTL = time.Minute

	now := time.Now().UTC()

	repo := &stubSessionRepo{
		getFn: func(_ context.Context, sessionID string) (*domain.Session, error) {
			return &domain.Session{
				ID:        sessionID,
				FamilyID:  "fam-strict",
				UserID:    "user-strict",
				Version:   1,
				CreatedAt: now.Add(-time.Hour),
				LastSeen:  now.Add(-time.Minute),
				ExpiresAt: now.Add(time.Hour),
			}, nil
		},
	}

	jtiCache := &stubJTIDenylistCache{err: fmt.Errorf("cache error")}
	jtiMetrics := &stubJTIDenylistMetrics{}

	service := NewTokenService(cfg, repo, nil, nil, provider, nil).
		WithClock(func() time.Time { return now }).
		WithJTIDenylist(jtiCache, jtiMetrics, 0, time.Minute)

	claims := mustClaims(t, security.AccessTokenOptions{
		UserID:         "user-strict",
		SessionID:      "session-strict",
		SessionVersion: 1,
		Issuer:         cfg.App.Name,
		Audience:       []string{cfg.App.Name},
		TTL:            time.Hour,
		IssuedAt:       now,
		NotBefore:      now,
		JTI:            "jti-strict",
	})
	token := signClaims(t, provider, "test-kid", claims)

	result, err := service.ValidateToken(context.Background(), token)
	if err != nil {
		t.Fatalf("expected validation to return result, got error: %v", err)
	}
	if result == nil {
		t.Fatalf("expected validation result when denylist unavailable")
	}
	if result.Status != TokenValidationStatusInvalid {
		t.Fatalf("expected status invalid when strict policy blocks fallback, got %v", result.Status)
	}
}

func TestTokenServiceValidateTokenCacheUsage(t *testing.T) {
	provider := generateKeyProvider(t)
	cfg := &config.AppConfig{App: config.AppSettings{Name: "iam-service"}}
	cfg.Redis.SessionVersionTTL = 2 * time.Minute

	now := time.Now().UTC()

	cache := &stubSessionVersionCache{values: map[string]int64{"session-6": 4}}
	repo := &stubSessionRepo{
		getFn: func(_ context.Context, sessionID string) (*domain.Session, error) {
			return &domain.Session{
				ID:        sessionID,
				FamilyID:  "fam-600",
				UserID:    "user-6",
				Version:   4,
				CreatedAt: now.Add(-time.Hour),
				LastSeen:  now.Add(-time.Minute),
				ExpiresAt: now.Add(time.Hour),
			}, nil
		},
	}
	tokenRepo := &stubTokenRepo{}

	service := NewTokenService(cfg, repo, tokenRepo, cache, provider, nil).WithClock(func() time.Time { return now })

	token := signToken(t, provider, "test-kid", security.AccessTokenOptions{
		UserID:         "user-6",
		SessionID:      "session-6",
		SessionVersion: 4,
		Issuer:         cfg.App.Name,
		Audience:       []string{cfg.App.Name},
		TTL:            time.Hour,
		IssuedAt:       now,
		NotBefore:      now,
	})

	result, err := service.ValidateToken(context.Background(), token)
	if err != nil {
		t.Fatalf("ValidateToken returned error: %v", err)
	}
	if result.Status != TokenValidationStatusActive {
		t.Fatalf("expected status active, got %v", result.Status)
	}
	if cache.getCalls == 0 {
		t.Fatalf("expected cache get to be recorded")
	}
	if len(cache.setCalls) == 0 {
		t.Fatalf("expected cache set to refresh ttl")
	}
	if cache.setCalls[0].ttl != cfg.Redis.SessionVersionTTL {
		t.Fatalf("expected ttl %v, got %v", cfg.Redis.SessionVersionTTL, cache.setCalls[0].ttl)
	}
}

func generateKeyProvider(t *testing.T) *staticKeyProvider {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}

	return &staticKeyProvider{private: key, kid: "test-kid"}
}

func signToken(t *testing.T, provider *staticKeyProvider, kid string, opts security.AccessTokenOptions) string {
	t.Helper()

	claims := mustClaims(t, opts)
	return signClaims(t, provider, kid, claims)
}

func mustClaims(t *testing.T, opts security.AccessTokenOptions) *security.AccessTokenClaims {
	t.Helper()

	claims, err := security.NewAccessTokenClaims(opts)
	if err != nil {
		t.Fatalf("build claims: %v", err)
	}
	return claims
}

func signClaims(t *testing.T, provider *staticKeyProvider, kid string, claims *security.AccessTokenClaims) string {
	t.Helper()

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	key, err := provider.GetSigningKey()
	if err != nil {
		t.Fatalf("get signing key: %v", err)
	}
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return signed
}
