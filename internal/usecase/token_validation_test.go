package usecase

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/arklim/social-platform-iam/internal/infra/config"
	"github.com/arklim/social-platform-iam/internal/infra/security"
)

const testSigningKID = "private"

func newTestTokenService(t *testing.T) (*TokenService, security.KeyProvider, *config.AppConfig) {
	t.Helper()

	keyProvider, keyDir := createTestKeyProvider(t)

	cfg := &config.AppConfig{
		App: config.AppSettings{
			Name: "iam-test",
			Env:  "test",
		},
		JWT: config.JWTSettings{
			KeyDirectory:   keyDir,
			AccessTokenTTL: time.Minute,
		},
	}

	service := NewTokenService(cfg, keyProvider, nil, nil, nil, nil, nil)
	service.WithClock(func() time.Time { return time.Date(2025, 10, 21, 12, 0, 0, 0, time.UTC) })

	return service, keyProvider, cfg
}

func signTestToken(t *testing.T, provider security.KeyProvider, claims *security.AccessTokenClaims, kid string) string {
	t.Helper()

	signer, err := provider.GetSigningKey()
	if err != nil {
		t.Fatalf("GetSigningKey failed: %v", err)
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid

	signed, err := token.SignedString(signer)
	if err != nil {
		t.Fatalf("SignedString failed: %v", err)
	}

	return signed
}

func TestTokenService_ValidateToken_Success(t *testing.T) {
	t.Helper()

	service, keyProvider, cfg := newTestTokenService(t)

	now := time.Date(2025, 10, 21, 11, 0, 0, 0, time.UTC)
	claims, err := security.NewAccessTokenClaims(security.AccessTokenOptions{
		UserID:    "user-123",
		Issuer:    cfg.App.Name,
		Audience:  []string{"service-a"},
		Roles:     []string{"admin", "editor"},
		TTL:       24 * time.Hour,
		IssuedAt:  now,
		NotBefore: now,
		JTI:       "jti-success",
		SessionID: "sess-123",
	})
	if err != nil {
		t.Fatalf("NewAccessTokenClaims failed: %v", err)
	}

	token := signTestToken(t, keyProvider, claims, testSigningKID)

	parsed, err := service.ValidateToken(context.Background(), token, []string{"service-a"})
	if err != nil {
		t.Fatalf("ValidateToken returned error: %v", err)
	}

	if parsed.UserID != claims.UserID {
		t.Fatalf("expected user id %q, got %q", claims.UserID, parsed.UserID)
	}

	if parsed.SessionID != claims.SessionID {
		t.Fatalf("expected session id %q, got %q", claims.SessionID, parsed.SessionID)
	}

	if len(parsed.Roles) != len(claims.Roles) {
		t.Fatalf("expected %d roles, got %d", len(claims.Roles), len(parsed.Roles))
	}
}

func TestTokenService_ValidateToken_Errors(t *testing.T) {
	t.Helper()

	service, keyProvider, cfg := newTestTokenService(t)

	baseTime := time.Date(2025, 10, 21, 10, 0, 0, 0, time.UTC)
	baseClaims, err := security.NewAccessTokenClaims(security.AccessTokenOptions{
		UserID:    "user-456",
		Issuer:    cfg.App.Name,
		Audience:  []string{"service-a"},
		TTL:       24 * time.Hour,
		IssuedAt:  baseTime,
		NotBefore: baseTime,
		JTI:       "jti-base",
		SessionID: "sess-456",
	})
	if err != nil {
		t.Fatalf("NewAccessTokenClaims failed: %v", err)
	}

	validToken := signTestToken(t, keyProvider, baseClaims, testSigningKID)

	expiredClaims := *baseClaims
	expiredClaims.RegisteredClaims.ExpiresAt = jwt.NewNumericDate(baseTime.Add(-time.Minute))
	expiredToken := signTestToken(t, keyProvider, &expiredClaims, testSigningKID)

	wrongAudienceToken := signTestToken(t, keyProvider, baseClaims, testSigningKID)

	tamperedToken := validToken[:len(validToken)-1] + "x"

	tests := []struct {
		name         string
		token        string
		audience     []string
		wantError    error
		wantContains string
	}{
		{
			name:         "empty token",
			token:        "",
			audience:     []string{"service-a"},
			wantContains: "token is required",
		},
		{
			name:      "expired token",
			token:     expiredToken,
			audience:  []string{"service-a"},
			wantError: ErrExpiredAccessToken,
		},
		{
			name:      "audience mismatch",
			token:     wrongAudienceToken,
			audience:  []string{"service-b"},
			wantError: ErrInvalidAccessToken,
		},
		{
			name:      "tampered signature",
			token:     tamperedToken,
			audience:  []string{"service-a"},
			wantError: ErrInvalidAccessToken,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Helper()

			_, err := service.ValidateToken(context.Background(), tc.token, tc.audience)
			if err == nil {
				t.Fatalf("expected error, got nil for case %s", tc.name)
			}

			if tc.wantError != nil && !errors.Is(err, tc.wantError) {
				t.Fatalf("expected error %v, got %v", tc.wantError, err)
			}

			if tc.wantContains != "" && !strings.Contains(err.Error(), tc.wantContains) {
				t.Fatalf("expected error to contain %q, got %v", tc.wantContains, err)
			}
		})
	}
}
