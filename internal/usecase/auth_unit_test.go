package usecase

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	uuid "github.com/google/uuid"

	"github.com/arklim/social-platform-iam/internal/core/domain"
	"github.com/arklim/social-platform-iam/internal/core/port"
	"github.com/arklim/social-platform-iam/internal/infra/config"
	"github.com/arklim/social-platform-iam/internal/infra/security"
	"github.com/arklim/social-platform-iam/internal/repository"
)

// createTestKeyProvider creates a temporary RSA key pair and key provider for tests
func createTestKeyProvider(t *testing.T) (security.KeyProvider, string) {
	t.Helper()

	tmpDir := t.TempDir()

	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	// Write private key
	privateKeyPath := filepath.Join(tmpDir, "private.pem")
	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}
	privateKeyFile, err := os.Create(privateKeyPath)
	if err != nil {
		t.Fatalf("failed to create private key file: %v", err)
	}
	if err := pem.Encode(privateKeyFile, privateKeyPEM); err != nil {
		t.Fatalf("failed to encode private key: %v", err)
	}
	privateKeyFile.Close()

	// Write public key
	publicKeyPath := filepath.Join(tmpDir, "public.pem")
	publicKeyPEM := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(&privateKey.PublicKey),
	}
	publicKeyFile, err := os.Create(publicKeyPath)
	if err != nil {
		t.Fatalf("failed to create public key file: %v", err)
	}
	if err := pem.Encode(publicKeyFile, publicKeyPEM); err != nil {
		t.Fatalf("failed to encode public key: %v", err)
	}
	publicKeyFile.Close()

	// Create key provider
	keyProvider, err := security.NewDevKeyProvider(tmpDir)
	if err != nil {
		t.Fatalf("failed to create key provider: %v", err)
	}

	return keyProvider, tmpDir
}

type testUserRepo struct {
	users map[string]domain.User
}

func (r *testUserRepo) Create(context.Context, domain.User) error {
	return errors.New("unexpected call")
}

func (r *testUserRepo) GetByID(_ context.Context, id string) (*domain.User, error) {
	if user, ok := r.users[id]; ok {
		copy := user
		return &copy, nil
	}
	return nil, repository.ErrNotFound
}

func (r *testUserRepo) GetByIdentifier(context.Context, string) (*domain.User, error) {
	return nil, errors.New("unexpected call")
}

func (r *testUserRepo) UpdateStatus(context.Context, string, domain.UserStatus) error {
	return errors.New("unexpected call")
}

func (r *testUserRepo) UpdatePassword(context.Context, string, string, string, time.Time) error {
	return errors.New("unexpected call")
}

func (r *testUserRepo) AssignRoles(context.Context, string, []string) error {
	return errors.New("unexpected call")
}

func (r *testUserRepo) RevokeRoles(context.Context, string, []string) error {
	return errors.New("unexpected call")
}

func (r *testUserRepo) GetUserRoles(context.Context, string) ([]domain.UserRole, error) {
	return nil, errors.New("unexpected call")
}

func (r *testUserRepo) ListPasswordHistory(context.Context, string, int) ([]domain.UserPasswordHistory, error) {
	return nil, errors.New("unexpected call")
}

func (r *testUserRepo) AddPasswordHistory(context.Context, domain.UserPasswordHistory) error {
	return errors.New("unexpected call")
}

func (r *testUserRepo) TrimPasswordHistory(context.Context, string, int) error {
	return errors.New("unexpected call")
}

func (r *testUserRepo) Update(context.Context, domain.User) error {
	return errors.New("unexpected call")
}

func (r *testUserRepo) SoftDelete(context.Context, string) error {
	return errors.New("unexpected call")
}

func (r *testUserRepo) List(context.Context, port.UserFilter) ([]domain.User, error) {
	return nil, errors.New("unexpected call")
}

func (r *testUserRepo) Count(context.Context, port.UserFilter) (int, error) {
	return 0, errors.New("unexpected call")
}

type testTokenRepo struct {
	stored      map[string]domain.RefreshToken
	storedByID  map[string]domain.RefreshToken
	lastCreated domain.RefreshToken
	revokedIDs  []string
	createErr   error
	getErr      error
	revokeErr   error
	markedUsed  []string
}

func (r *testTokenRepo) CreateVerification(context.Context, domain.VerificationToken) error {
	return errors.New("unexpected call")
}

func (r *testTokenRepo) GetVerificationByHash(context.Context, string) (*domain.VerificationToken, error) {
	return nil, errors.New("unexpected call")
}

func (r *testTokenRepo) ConsumeVerification(context.Context, string) error {
	return errors.New("unexpected call")
}

func (r *testTokenRepo) CreatePasswordReset(context.Context, domain.PasswordResetToken) error {
	return errors.New("unexpected call")
}

func (r *testTokenRepo) GetPasswordResetByHash(context.Context, string) (*domain.PasswordResetToken, error) {
	return nil, errors.New("unexpected call")
}

func (r *testTokenRepo) ConsumePasswordReset(context.Context, string) error {
	return errors.New("unexpected call")
}

func (r *testTokenRepo) CreateRefreshToken(_ context.Context, token domain.RefreshToken) error {
	if r.createErr != nil {
		return r.createErr
	}
	if r.stored == nil {
		r.stored = make(map[string]domain.RefreshToken)
	}
	if r.storedByID == nil {
		r.storedByID = make(map[string]domain.RefreshToken)
	}
	r.lastCreated = token
	r.stored[token.TokenHash] = token
	r.storedByID[token.ID] = token
	return nil
}

func (r *testTokenRepo) GetRefreshTokenByHash(_ context.Context, hash string) (*domain.RefreshToken, error) {
	if r.getErr != nil {
		return nil, r.getErr
	}
	if token, ok := r.stored[hash]; ok {
		copy := token
		return &copy, nil
	}
	return nil, repository.ErrNotFound
}

func (r *testTokenRepo) RevokeRefreshToken(_ context.Context, id string) error {
	if r.revokeErr != nil {
		return r.revokeErr
	}
	r.revokedIDs = append(r.revokedIDs, id)
	if r.storedByID != nil {
		delete(r.storedByID, id)
	}
	if r.stored != nil {
		for hash, token := range r.stored {
			if token.ID == id {
				delete(r.stored, hash)
				break
			}
		}
	}
	return nil
}

func (r *testTokenRepo) MarkRefreshTokenUsed(_ context.Context, refreshTokenID string, usedAt time.Time) error {
	if r.storedByID == nil {
		r.storedByID = make(map[string]domain.RefreshToken)
		for _, token := range r.stored {
			r.storedByID[token.ID] = token
		}
	}

	token, ok := r.storedByID[refreshTokenID]
	if !ok {
		return repository.ErrNotFound
	}
	token.UsedAt = &usedAt
	r.storedByID[refreshTokenID] = token
	r.markedUsed = append(r.markedUsed, refreshTokenID)
	return nil
}

func (r *testTokenRepo) RevokeRefreshTokensByFamily(_ context.Context, familyID string, _ string) (int, error) {
	if r.storedByID == nil {
		return 0, nil
	}
	count := 0
	for id, token := range r.storedByID {
		if token.FamilyID == familyID {
			r.revokedIDs = append(r.revokedIDs, id)
			delete(r.storedByID, id)
			if r.stored != nil {
				for hash, storedToken := range r.stored {
					if storedToken.ID == id {
						delete(r.stored, hash)
						break
					}
				}
			}
			count++
		}
	}
	return count, nil
}

func (r *testTokenRepo) RevokeRefreshTokensForUser(context.Context, string) error {
	return errors.New("unexpected call")
}

func (r *testTokenRepo) UpdateRefreshTokenIssuedVersion(context.Context, string, int64) error {
	return nil
}

func TestAuthService_IssueRefreshToken(t *testing.T) {
	keyProvider, keyDir := createTestKeyProvider(t)

	cfg := &config.AppConfig{
		App: config.AppSettings{Name: "test-app", Env: "development"},
		JWT: config.JWTSettings{
			KeyDirectory:    keyDir,
			AccessTokenTTL:  time.Minute,
			RefreshTokenTTL: time.Hour,
		},
	}

	tokenGenerator, err := security.NewTokenGenerator(keyProvider, "private")
	if err != nil {
		t.Fatalf("NewTokenGenerator failed: %v", err)
	}

	tokens := &testTokenRepo{}
	service, err := NewAuthService(cfg, &testUserRepo{}, nil, nil, nil, tokens, tokenGenerator, keyProvider, nil, nil)
	if err != nil {
		t.Fatalf("NewAuthService failed: %v", err)
	}

	user := domain.User{ID: "user-1"}
	raw, record, err := service.IssueRefreshToken(context.Background(), user, map[string]any{"source": "login"})
	if err != nil {
		t.Fatalf("IssueRefreshToken returned error: %v", err)
	}

	if raw == "" {
		t.Fatalf("expected non-empty refresh token")
	}

	expectedHash := security.HashToken(raw)
	if record.TokenHash != expectedHash {
		t.Fatalf("expected stored hash %s, got %s", expectedHash, record.TokenHash)
	}

	if tokens.lastCreated.ID == "" {
		t.Fatalf("expected stored refresh token to have ID")
	}

	if tokens.lastCreated.Metadata["source"] != "login" {
		t.Fatalf("expected metadata source to be login, got %v", tokens.lastCreated.Metadata["source"])
	}

	if _, ok := tokens.stored[expectedHash]; !ok {
		t.Fatalf("expected refresh token to be stored by hash")
	}

	if record.ExpiresAt.Before(record.CreatedAt) {
		t.Fatalf("expected expires_at to be after created_at")
	}
}

func TestAuthService_RefreshAccessToken_Success(t *testing.T) {
	keyProvider, keyDir := createTestKeyProvider(t)

	cfg := &config.AppConfig{
		App: config.AppSettings{Name: "test-app", Env: "development"},
		JWT: config.JWTSettings{
			KeyDirectory:    keyDir,
			AccessTokenTTL:  time.Minute,
			RefreshTokenTTL: time.Hour,
		},
	}

	tokenGenerator, err := security.NewTokenGenerator(keyProvider, "private")
	if err != nil {
		t.Fatalf("NewTokenGenerator failed: %v", err)
	}

	user := domain.User{
		ID:           "user-1",
		Username:     "alice",
		Email:        "alice@example.com",
		IsActive:     true,
		Status:       domain.UserStatusActive,
		PasswordHash: "secret",
	}

	userRepo := &testUserRepo{users: map[string]domain.User{user.ID: user}}

	rawOld := "legacy-refresh"
	oldHash := security.HashToken(rawOld)
	tokens := &testTokenRepo{stored: map[string]domain.RefreshToken{
		oldHash: {
			ID:        "token-1",
			UserID:    user.ID,
			TokenHash: oldHash,
			CreatedAt: time.Now().Add(-30 * time.Minute),
			ExpiresAt: time.Now().Add(30 * time.Minute),
		},
	}}

	service, err := NewAuthService(cfg, userRepo, nil, nil, nil, tokens, tokenGenerator, keyProvider, nil, nil)
	if err != nil {
		t.Fatalf("NewAuthService failed: %v", err)
	}

	accessToken, newRefresh, refreshedUser, roles, err := service.RefreshAccessToken(context.Background(), rawOld)
	if err != nil {
		t.Fatalf("RefreshAccessToken returned error: %v", err)
	}

	if accessToken == "" {
		t.Fatalf("expected access token")
	}

	if newRefresh == rawOld {
		t.Fatalf("expected new refresh token to differ from old token")
	}

	if len(tokens.revokedIDs) != 1 || tokens.revokedIDs[0] != "token-1" {
		t.Fatalf("expected old refresh token to be revoked")
	}

	if tokens.lastCreated.Metadata["rotated_from"] != "token-1" {
		t.Fatalf("expected metadata to include rotated_from token-1")
	}

	if tokens.lastCreated.TokenHash != security.HashToken(newRefresh) {
		t.Fatalf("expected stored hash to match new refresh token")
	}

	if refreshedUser.PasswordHash != "" {
		t.Fatalf("expected sanitized user without password hash")
	}

	if len(roles) != 0 {
		t.Fatalf("expected no roles, got %v", roles)
	}
}

func TestAuthService_RefreshAccessToken_Invalid(t *testing.T) {
	keyProvider, keyDir := createTestKeyProvider(t)

	cfg := &config.AppConfig{
		App: config.AppSettings{Name: "test-app", Env: "development"},
		JWT: config.JWTSettings{
			KeyDirectory:    keyDir,
			AccessTokenTTL:  time.Minute,
			RefreshTokenTTL: time.Hour,
		},
	}

	tokenGenerator, err := security.NewTokenGenerator(keyProvider, "private")
	if err != nil {
		t.Fatalf("NewTokenGenerator failed: %v", err)
	}

	tokens := &testTokenRepo{}
	service, err := NewAuthService(cfg, &testUserRepo{users: map[string]domain.User{}}, nil, nil, nil, tokens, tokenGenerator, keyProvider, nil, nil)
	if err != nil {
		t.Fatalf("NewAuthService failed: %v", err)
	}

	if _, _, _, _, err := service.RefreshAccessToken(context.Background(), "missing"); !errors.Is(err, ErrInvalidRefreshToken) {
		t.Fatalf("expected ErrInvalidRefreshToken, got %v", err)
	}
}

func TestAuthService_ParseAccessToken_Success(t *testing.T) {
	keyProvider, keyDir := createTestKeyProvider(t)

	cfg := &config.AppConfig{
		App: config.AppSettings{Name: "test-app", Env: "development"},
		JWT: config.JWTSettings{
			KeyDirectory:    keyDir,
			AccessTokenTTL:  time.Minute,
			RefreshTokenTTL: time.Hour,
		},
	}

	tokenGenerator, err := security.NewTokenGenerator(keyProvider, "private")
	if err != nil {
		t.Fatalf("NewTokenGenerator failed: %v", err)
	}

	service, err := NewAuthService(cfg, nil, nil, nil, nil, nil, tokenGenerator, keyProvider, nil, nil)
	if err != nil {
		t.Fatalf("NewAuthService failed: %v", err)
	}

	user := domain.User{ID: "user-1", Username: "alice", Email: "alice@example.com"}
	token, err := service.IssueToken(context.Background(), user, []string{"admin"})
	if err != nil {
		t.Fatalf("IssueToken returned error: %v", err)
	}

	parsedClaims := jwt.MapClaims{}
	parsed, err := jwt.ParseWithClaims(token, parsedClaims, func(t *jwt.Token) (interface{}, error) {
		kid, ok := t.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("kid header not found")
		}
		return keyProvider.GetVerificationKey(kid)
	}, jwt.WithIssuer(cfg.App.Name), jwt.WithAudience(cfg.App.Name))
	if err != nil {
		t.Fatalf("failed to parse raw token: %v", err)
	}
	if !parsed.Valid {
		t.Fatalf("expected parsed token to be valid")
	}
	if _, ok := parsedClaims["username"]; ok {
		t.Fatalf("expected username claim to be absent")
	}
	if _, ok := parsedClaims["email"]; ok {
		t.Fatalf("expected email claim to be absent")
	}

	claims, err := service.ParseAccessToken(context.Background(), token)
	if err != nil {
		t.Fatalf("ParseAccessToken returned error: %v", err)
	}

	expectedSubject := security.HashToken(user.ID + ":" + cfg.App.Name)
	if claims.Subject != expectedSubject {
		t.Fatalf("expected subject %s, got %s", expectedSubject, claims.Subject)
	}
	if claims.UserID != user.ID {
		t.Fatalf("expected user id %s, got %s", user.ID, claims.UserID)
	}
	if len(claims.Roles) != 1 || claims.Roles[0] != "admin" {
		t.Fatalf("expected roles [admin], got %v", claims.Roles)
	}
	if len(claims.Audience) != 1 || claims.Audience[0] != cfg.App.Name {
		t.Fatalf("expected audience %s, got %v", cfg.App.Name, claims.Audience)
	}
	if claims.ID == "" {
		t.Fatalf("expected jti to be set")
	}
}

func TestAuthService_ParseAccessToken_Errors(t *testing.T) {
	keyProvider, keyDir := createTestKeyProvider(t)

	cfg := &config.AppConfig{
		App: config.AppSettings{Name: "test-app", Env: "development"},
		JWT: config.JWTSettings{
			KeyDirectory:    keyDir,
			AccessTokenTTL:  time.Minute,
			RefreshTokenTTL: time.Hour,
		},
	}

	tokenGenerator, err := security.NewTokenGenerator(keyProvider, "private")
	if err != nil {
		t.Fatalf("NewTokenGenerator failed: %v", err)
	}

	service, err := NewAuthService(cfg, nil, nil, nil, nil, nil, tokenGenerator, keyProvider, nil, nil)
	if err != nil {
		t.Fatalf("NewAuthService failed: %v", err)
	}

	if _, err := service.ParseAccessToken(context.Background(), " "); err == nil {
		t.Fatalf("expected error for empty token")
	}

	if _, err := service.ParseAccessToken(context.Background(), "not-a-jwt"); !errors.Is(err, ErrInvalidAccessToken) {
		t.Fatalf("expected ErrInvalidAccessToken, got %v", err)
	}

	userID := "user-1"
	signingKey, err := keyProvider.GetSigningKey()
	if err != nil {
		t.Fatalf("failed to get signing key: %v", err)
	}

	expiredClaims := security.AccessTokenClaims{
		Roles:  []string{"user"},
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   security.HashToken(userID + ":" + cfg.App.Name),
			Issuer:    cfg.App.Name,
			Audience:  jwt.ClaimStrings{cfg.App.Name},
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
			NotBefore: jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-time.Hour)),
			ID:        uuid.NewString(),
		},
	}
	expiredTokenObj := jwt.NewWithClaims(jwt.SigningMethodRS256, expiredClaims)
	expiredTokenObj.Header["kid"] = "private"
	expiredToken, err := expiredTokenObj.SignedString(signingKey)
	if err != nil {
		t.Fatalf("failed to sign expired token: %v", err)
	}

	if _, err := service.ParseAccessToken(context.Background(), expiredToken); !errors.Is(err, ErrExpiredAccessToken) {
		t.Fatalf("expected ErrExpiredAccessToken, got %v", err)
	}

	otherKeyProvider, otherKeyDir := createTestKeyProvider(t)
	otherTokenGenerator, err := security.NewTokenGenerator(otherKeyProvider, "private")
	if err != nil {
		t.Fatalf("NewTokenGenerator for otherService failed: %v", err)
	}

	otherService, err := NewAuthService(&config.AppConfig{
		App: config.AppSettings{Name: "other", Env: "development"},
		JWT: config.JWTSettings{KeyDirectory: otherKeyDir},
	}, nil, nil, nil, nil, nil, otherTokenGenerator, otherKeyProvider, nil, nil)
	if err != nil {
		t.Fatalf("NewAuthService for otherService failed: %v", err)
	}

	otherSigningKey, err := otherKeyProvider.GetSigningKey()
	if err != nil {
		t.Fatalf("failed to get other signing key: %v", err)
	}

	foreignClaims := security.AccessTokenClaims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   security.HashToken(userID + ":" + otherService.cfg.App.Name),
			Issuer:    otherService.cfg.App.Name,
			Audience:  jwt.ClaimStrings{otherService.cfg.App.Name},
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			ID:        uuid.NewString(),
		},
	}
	foreignTokenObj := jwt.NewWithClaims(jwt.SigningMethodRS256, foreignClaims)
	foreignTokenObj.Header["kid"] = "private"
	foreignToken, err := foreignTokenObj.SignedString(otherSigningKey)
	if err != nil {
		t.Fatalf("failed to sign foreign token: %v", err)
	}

	if _, err := service.ParseAccessToken(context.Background(), foreignToken); !errors.Is(err, ErrInvalidAccessToken) {
		t.Fatalf("expected ErrInvalidAccessToken for foreign token, got %v", err)
	}
}

func TestAuthService_ParseAccessToken_AllowsMissingSessionRepositoryInLenientMode(t *testing.T) {
	keyProvider, keyDir := createTestKeyProvider(t)

	cfg := &config.AppConfig{
		App: config.AppSettings{Name: "test-app", Env: "development"},
		JWT: config.JWTSettings{KeyDirectory: keyDir},
	}

	tokenGenerator, err := security.NewTokenGenerator(keyProvider, "private")
	if err != nil {
		t.Fatalf("NewTokenGenerator failed: %v", err)
	}

	service, err := NewAuthService(cfg, nil, nil, nil, nil, nil, tokenGenerator, keyProvider, nil, nil)
	if err != nil {
		t.Fatalf("NewAuthService failed: %v", err)
	}

	now := time.Now().UTC()
	signingKey, err := keyProvider.GetSigningKey()
	if err != nil {
		t.Fatalf("failed to get signing key: %v", err)
	}

	claims := security.AccessTokenClaims{
		UserID:         "user-1",
		SessionID:      "session-123",
		SessionVersion: 1,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   security.HashToken("user-1:" + cfg.App.Name),
			Issuer:    cfg.App.Name,
			Audience:  jwt.ClaimStrings{cfg.App.Name},
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			ID:        uuid.NewString(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "private"
	signed, err := token.SignedString(signingKey)
	if err != nil {
		t.Fatalf("failed to sign access token: %v", err)
	}

	if _, err := service.ParseAccessToken(context.Background(), signed); err != nil {
		t.Fatalf("expected lenient policy to accept token, got %v", err)
	}
}

func TestAuthService_ParseAccessToken_RejectsWhenSessionRepositoryMissingInStrictMode(t *testing.T) {
	keyProvider, keyDir := createTestKeyProvider(t)

	cfg := &config.AppConfig{
		App:        config.AppSettings{Name: "test-app", Env: "development"},
		JWT:        config.JWTSettings{KeyDirectory: keyDir},
		Revocation: config.RevocationSettings{DegradationPolicy: "strict"},
	}

	tokenGenerator, err := security.NewTokenGenerator(keyProvider, "private")
	if err != nil {
		t.Fatalf("NewTokenGenerator failed: %v", err)
	}

	service, err := NewAuthService(cfg, nil, nil, nil, nil, nil, tokenGenerator, keyProvider, nil, nil)
	if err != nil {
		t.Fatalf("NewAuthService failed: %v", err)
	}

	now := time.Now().UTC()
	signingKey, err := keyProvider.GetSigningKey()
	if err != nil {
		t.Fatalf("failed to get signing key: %v", err)
	}

	claims := security.AccessTokenClaims{
		UserID:         "user-1",
		SessionID:      "session-123",
		SessionVersion: 1,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   security.HashToken("user-1:" + cfg.App.Name),
			Issuer:    cfg.App.Name,
			Audience:  jwt.ClaimStrings{cfg.App.Name},
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			ID:        uuid.NewString(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "private"
	signed, err := token.SignedString(signingKey)
	if err != nil {
		t.Fatalf("failed to sign access token: %v", err)
	}

	if _, err := service.ParseAccessToken(context.Background(), signed); !errors.Is(err, ErrInvalidAccessToken) {
		t.Fatalf("expected strict policy to reject token, got %v", err)
	}
}

func TestAuthService_ParseAccessToken_RejectsStaleSessionVersion(t *testing.T) {
	keyProvider, keyDir := createTestKeyProvider(t)

	cfg := &config.AppConfig{
		App: config.AppSettings{Name: "test-app", Env: "development"},
		JWT: config.JWTSettings{KeyDirectory: keyDir},
	}

	tokenGenerator, err := security.NewTokenGenerator(keyProvider, "private")
	if err != nil {
		t.Fatalf("NewTokenGenerator failed: %v", err)
	}

	sessionID := uuid.NewString()
	userID := "user-123"
	now := time.Now().UTC()
	sessionRepo := newFakeSessionRepository(domain.Session{
		ID:        sessionID,
		UserID:    userID,
		Version:   2,
		ExpiresAt: now.Add(time.Hour),
	})

	service, err := NewAuthService(cfg, nil, nil, nil, sessionRepo, nil, tokenGenerator, keyProvider, nil, nil)
	if err != nil {
		t.Fatalf("NewAuthService failed: %v", err)
	}

	cache := &stubSessionVersionCache{values: map[string]int64{sessionID: 2}}
	service.WithSessionVersionCache(cache, time.Minute)

	claims := security.AccessTokenClaims{
		Roles:          []string{"user"},
		UserID:         userID,
		SessionID:      sessionID,
		SessionVersion: 1,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   security.HashToken(userID + ":" + cfg.App.Name),
			Issuer:    cfg.App.Name,
			Audience:  jwt.ClaimStrings{cfg.App.Name},
			IssuedAt:  jwt.NewNumericDate(now.Add(-time.Minute)),
			NotBefore: jwt.NewNumericDate(now.Add(-time.Minute)),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			ID:        uuid.NewString(),
		},
	}

	signingKey, err := keyProvider.GetSigningKey()
	if err != nil {
		t.Fatalf("failed to get signing key: %v", err)
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "private"
	signed, err := token.SignedString(signingKey)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	if _, err := service.ParseAccessToken(context.Background(), signed); !errors.Is(err, ErrInvalidAccessToken) {
		t.Fatalf("expected ErrInvalidAccessToken for stale session version, got %v", err)
	}
}

func TestAuthService_ParseAccessToken_RejectsRevokedSession(t *testing.T) {
	keyProvider, keyDir := createTestKeyProvider(t)

	cfg := &config.AppConfig{
		App: config.AppSettings{Name: "test-app", Env: "development"},
		JWT: config.JWTSettings{KeyDirectory: keyDir},
	}

	tokenGenerator, err := security.NewTokenGenerator(keyProvider, "private")
	if err != nil {
		t.Fatalf("NewTokenGenerator failed: %v", err)
	}

	sessionID := uuid.NewString()
	userID := "user-456"
	now := time.Now().UTC()
	revokedAt := now.Add(-5 * time.Minute)
	sessionRepo := newFakeSessionRepository(domain.Session{
		ID:        sessionID,
		UserID:    userID,
		Version:   3,
		ExpiresAt: now.Add(time.Hour),
		RevokedAt: &revokedAt,
		RevokeReason: func() *string {
			reason := "user_action"
			return &reason
		}(),
	})

	service, err := NewAuthService(cfg, nil, nil, nil, sessionRepo, nil, tokenGenerator, keyProvider, nil, nil)
	if err != nil {
		t.Fatalf("NewAuthService failed: %v", err)
	}

	cache := &stubSessionVersionCache{}
	service.WithSessionVersionCache(cache, time.Minute)

	claims := security.AccessTokenClaims{
		UserID:         userID,
		SessionID:      sessionID,
		SessionVersion: 3,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   security.HashToken(userID + ":" + cfg.App.Name),
			Issuer:    cfg.App.Name,
			Audience:  jwt.ClaimStrings{cfg.App.Name},
			IssuedAt:  jwt.NewNumericDate(now.Add(-time.Minute)),
			NotBefore: jwt.NewNumericDate(now.Add(-time.Minute)),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			ID:        uuid.NewString(),
		},
	}

	signingKey, err := keyProvider.GetSigningKey()
	if err != nil {
		t.Fatalf("failed to get signing key: %v", err)
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "private"
	signed, err := token.SignedString(signingKey)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	if _, err := service.ParseAccessToken(context.Background(), signed); !errors.Is(err, ErrInvalidAccessToken) {
		t.Fatalf("expected ErrInvalidAccessToken for revoked session, got %v", err)
	}

	// ensure the revocation path cached the terminal version for future lookups
	if version, cacheErr := cache.GetSessionVersion(context.Background(), sessionID); cacheErr != nil || version != 3 {
		t.Fatalf("expected cached session version 3, got version=%d err=%v", version, cacheErr)
	}
}

func TestAuthService_ParseAccessToken_RejectsRevokedSessionViaCacheOnly(t *testing.T) {
	keyProvider, keyDir := createTestKeyProvider(t)

	cfg := &config.AppConfig{
		App: config.AppSettings{Name: "test-app", Env: "development"},
		JWT: config.JWTSettings{KeyDirectory: keyDir},
	}

	tokenGenerator, err := security.NewTokenGenerator(keyProvider, "private")
	if err != nil {
		t.Fatalf("NewTokenGenerator failed: %v", err)
	}

	sessionID := uuid.NewString()
	userID := "user-cache"
	now := time.Now().UTC()

	service, err := NewAuthService(cfg, nil, nil, nil, nil, nil, tokenGenerator, keyProvider, nil, nil)
	if err != nil {
		t.Fatalf("NewAuthService failed: %v", err)
	}

	cache := &stubSessionVersionCache{}
	service.WithSessionVersionCache(cache, time.Minute)
	revocationStore := &stubSessionRevocationStore{
		entries: map[string]struct {
			revoked bool
			reason  string
		}{
			sessionID: {revoked: true, reason: "logout_all"},
		},
	}
	service.WithSessionRevocationStore(revocationStore, time.Hour)

	claims := security.AccessTokenClaims{
		UserID:         userID,
		SessionID:      sessionID,
		SessionVersion: 1,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   security.HashToken(userID + ":" + cfg.App.Name),
			Issuer:    cfg.App.Name,
			Audience:  jwt.ClaimStrings{cfg.App.Name},
			IssuedAt:  jwt.NewNumericDate(now.Add(-time.Minute)),
			NotBefore: jwt.NewNumericDate(now.Add(-time.Minute)),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			ID:        uuid.NewString(),
		},
	}

	signingKey, err := keyProvider.GetSigningKey()
	if err != nil {
		t.Fatalf("failed to get signing key: %v", err)
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "private"
	signed, err := token.SignedString(signingKey)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	if _, err := service.ParseAccessToken(context.Background(), signed); !errors.Is(err, ErrInvalidAccessToken) {
		t.Fatalf("expected ErrInvalidAccessToken for redis-revoked session, got %v", err)
	}
}
