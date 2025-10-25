package usecase

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/arklim/social-platform-iam/internal/core/domain"
	"github.com/arklim/social-platform-iam/internal/infra/config"
	"github.com/arklim/social-platform-iam/internal/infra/security"
	"github.com/arklim/social-platform-iam/internal/repository"
)

type refreshUserRepository struct {
	users map[string]domain.User
}

func (r *refreshUserRepository) Create(context.Context, domain.User) error {
	return errors.New("unexpected call: Create")
}
func (r *refreshUserRepository) GetByID(_ context.Context, id string) (*domain.User, error) {
	if user, ok := r.users[id]; ok {
		copy := user
		return &copy, nil
	}
	return nil, repository.ErrNotFound
}
func (r *refreshUserRepository) GetByIdentifier(context.Context, string) (*domain.User, error) {
	return nil, errors.New("unexpected call: GetByIdentifier")
}
func (r *refreshUserRepository) UpdateStatus(context.Context, string, domain.UserStatus) error {
	return errors.New("unexpected call: UpdateStatus")
}
func (r *refreshUserRepository) UpdatePassword(context.Context, string, string, string, time.Time) error {
	return errors.New("unexpected call: UpdatePassword")
}
func (r *refreshUserRepository) AssignRoles(context.Context, string, []string) error {
	return errors.New("unexpected call: AssignRoles")
}
func (r *refreshUserRepository) RevokeRoles(context.Context, string, []string) error {
	return errors.New("unexpected call: RevokeRoles")
}
func (r *refreshUserRepository) GetUserRoles(context.Context, string) ([]domain.UserRole, error) {
	return nil, errors.New("unexpected call: GetUserRoles")
}
func (r *refreshUserRepository) ListPasswordHistory(context.Context, string, int) ([]domain.UserPasswordHistory, error) {
	return nil, errors.New("unexpected call: ListPasswordHistory")
}
func (r *refreshUserRepository) AddPasswordHistory(context.Context, domain.UserPasswordHistory) error {
	return errors.New("unexpected call: AddPasswordHistory")
}
func (r *refreshUserRepository) TrimPasswordHistory(context.Context, string, int) error {
	return errors.New("unexpected call: TrimPasswordHistory")
}

//

type refreshSessionRepository struct {
	sessions            map[string]domain.Session
	updateLastSeenCalls []struct {
		sessionID string
		ip        *string
		ua        *string
	}
	revokedFamilies []string
	revokeReasons   []string
	storeEventCalls []domain.SessionEvent
}

func (r *refreshSessionRepository) Create(context.Context, domain.Session) error {
	return errors.New("unexpected call: Create")
}
func (r *refreshSessionRepository) Get(_ context.Context, id string) (*domain.Session, error) {
	if session, ok := r.sessions[id]; ok {
		copy := session
		return &copy, nil
	}
	return nil, repository.ErrNotFound
}
func (r *refreshSessionRepository) ListByUser(context.Context, string) ([]domain.Session, error) {
	return nil, errors.New("unexpected call: ListByUser")
}
func (r *refreshSessionRepository) UpdateLastSeen(_ context.Context, sessionID string, ip *string, ua *string) error {
	r.updateLastSeenCalls = append(r.updateLastSeenCalls, struct {
		sessionID string
		ip        *string
		ua        *string
	}{sessionID: sessionID, ip: ip, ua: ua})
	return nil
}
func (r *refreshSessionRepository) Revoke(context.Context, string, string) error {
	return errors.New("unexpected call: Revoke")
}
func (r *refreshSessionRepository) RevokeByFamily(_ context.Context, familyID string, reason string) (int, error) {
	r.revokedFamilies = append(r.revokedFamilies, familyID)
	r.revokeReasons = append(r.revokeReasons, reason)
	return 1, nil
}
func (r *refreshSessionRepository) RevokeAllForUser(context.Context, string, string) (int, error) {
	return 0, errors.New("unexpected call: RevokeAllForUser")
}
func (r *refreshSessionRepository) StoreEvent(_ context.Context, event domain.SessionEvent) error {
	r.storeEventCalls = append(r.storeEventCalls, event)
	return nil
}
func (r *refreshSessionRepository) RevokeSessionAccessTokens(context.Context, string, string) (int, error) {
	return 0, errors.New("unexpected call: RevokeSessionAccessTokens")
}

//

type refreshTokenRepository struct {
	records             map[string]domain.RefreshToken
	createdTokens       []domain.RefreshToken
	revokedIDs          []string
	revokedFamilies     []string
	markedUsed          []string
	trackedJTIs         []domain.AccessTokenJTI
	markUsedShouldError bool
}

func (r *refreshTokenRepository) CreateVerification(context.Context, domain.VerificationToken) error {
	return errors.New("unexpected call: CreateVerification")
}
func (r *refreshTokenRepository) GetVerificationByHash(context.Context, string) (*domain.VerificationToken, error) {
	return nil, errors.New("unexpected call: GetVerificationByHash")
}
func (r *refreshTokenRepository) ConsumeVerification(context.Context, string) error {
	return errors.New("unexpected call: ConsumeVerification")
}
func (r *refreshTokenRepository) CreatePasswordReset(context.Context, domain.PasswordResetToken) error {
	return errors.New("unexpected call: CreatePasswordReset")
}
func (r *refreshTokenRepository) GetPasswordResetByHash(context.Context, string) (*domain.PasswordResetToken, error) {
	return nil, errors.New("unexpected call: GetPasswordResetByHash")
}
func (r *refreshTokenRepository) ConsumePasswordReset(context.Context, string) error {
	return errors.New("unexpected call: ConsumePasswordReset")
}
func (r *refreshTokenRepository) CreateRefreshToken(_ context.Context, token domain.RefreshToken) error {
	r.createdTokens = append(r.createdTokens, token)
	return nil
}
func (r *refreshTokenRepository) GetRefreshTokenByHash(_ context.Context, hash string) (*domain.RefreshToken, error) {
	if r.records == nil {
		return nil, repository.ErrNotFound
	}
	record, ok := r.records[hash]
	if !ok {
		return nil, repository.ErrNotFound
	}
	copy := record
	return &copy, nil
}
func (r *refreshTokenRepository) RevokeRefreshToken(_ context.Context, id string) error {
	r.revokedIDs = append(r.revokedIDs, id)
	return nil
}
func (r *refreshTokenRepository) MarkRefreshTokenUsed(_ context.Context, id string, _ time.Time) error {
	if r.markUsedShouldError {
		return repository.ErrNotFound
	}
	r.markedUsed = append(r.markedUsed, id)
	if r.records != nil {
		for hash, token := range r.records {
			if token.ID == id {
				token.UsedAt = pointerToTime(time.Now())
				r.records[hash] = token
				break
			}
		}
	}
	return nil
}
func (r *refreshTokenRepository) RevokeRefreshTokensByFamily(_ context.Context, familyID string, _ string) (int, error) {
	r.revokedFamilies = append(r.revokedFamilies, familyID)
	return 1, nil
}
func (r *refreshTokenRepository) RevokeRefreshTokensForUser(context.Context, string) error {
	return nil
}
func (r *refreshTokenRepository) TrackJTI(_ context.Context, record domain.AccessTokenJTI) error {
	r.trackedJTIs = append(r.trackedJTIs, record)
	return nil
}
func (r *refreshTokenRepository) RevokeJTI(context.Context, domain.RevokedAccessTokenJTI) error {
	return nil
}
func (r *refreshTokenRepository) RevokeJTIsBySession(context.Context, string, string) (int, error) {
	return 0, nil
}
func (r *refreshTokenRepository) RevokeJTIsForUser(context.Context, string, string) (int, error) {
	return 0, nil
}
func (r *refreshTokenRepository) IsJTIRevoked(context.Context, string) (bool, error) {
	return false, nil
}
func (r *refreshTokenRepository) CleanupExpiredJTIs(context.Context, time.Time) (int, error) {
	return 0, nil
}

func pointerToTime(t time.Time) *time.Time {
	return &t
}

func TestAuthService_RefreshAccessToken_RotatesWithinFamily(t *testing.T) {
	keyProvider, keyDir := createTestKeyProvider(t)
	tokenGenerator, err := security.NewTokenGenerator(keyProvider, "private")
	if err != nil {
		t.Fatalf("token generator: %v", err)
	}

	user := domain.User{ID: "user-1", Username: "sam", Email: "sam@example.com", Status: domain.UserStatusActive, IsActive: true, PasswordHash: "hashed"}
	userRepo := &refreshUserRepository{users: map[string]domain.User{user.ID: user}}

	familyID := "family-1"
	sessionID := "session-1"
	rawRefresh := "legacy-refresh-token"
	hash := security.HashToken(rawRefresh)
	expiresAt := time.Now().Add(time.Hour)

	session := domain.Session{ID: sessionID, UserID: user.ID, ExpiresAt: expiresAt.Add(time.Hour)}
	sessionRepo := &refreshSessionRepository{sessions: map[string]domain.Session{sessionID: session}}

	tokenRecord := domain.RefreshToken{
		ID:        "token-1",
		UserID:    user.ID,
		SessionID: &sessionID,
		TokenHash: hash,
		FamilyID:  familyID,
		CreatedAt: time.Now().Add(-time.Minute),
		ExpiresAt: expiresAt,
		IP:        stringPtr("192.0.2.50"),
		UserAgent: stringPtr("GoTest/1.0"),
	}

	tokenRepo := &refreshTokenRepository{records: map[string]domain.RefreshToken{hash: tokenRecord}}

	cfg := &config.AppConfig{
		App: config.AppSettings{Name: "iam-service", Env: "test"},
		JWT: config.JWTSettings{KeyDirectory: keyDir, AccessTokenTTL: time.Minute, RefreshTokenTTL: time.Hour},
	}

	authService, err := NewAuthService(cfg, userRepo, nil, nil, sessionRepo, tokenRepo, tokenGenerator, keyProvider, nil, nil)
	if err != nil {
		t.Fatalf("NewAuthService: %v", err)
	}

	accessToken, newRefresh, refreshedUser, roles, err := authService.RefreshAccessToken(context.Background(), rawRefresh)
	if err != nil {
		t.Fatalf("RefreshAccessToken returned error: %v", err)
	}

	if accessToken == "" {
		t.Fatalf("expected new access token")
	}
	if newRefresh == rawRefresh {
		t.Fatalf("expected refresh token rotation")
	}
	if refreshedUser.ID != user.ID {
		t.Fatalf("expected refreshed user to match original")
	}
	if roles != nil {
		t.Fatalf("expected no roles from nil repository")
	}
	if len(tokenRepo.createdTokens) != 1 {
		t.Fatalf("expected a new refresh token to be stored")
	}
	created := tokenRepo.createdTokens[0]
	if created.FamilyID != familyID {
		t.Fatalf("expected family id %s to be reused, got %s", familyID, created.FamilyID)
	}
	if created.SessionID == nil || *created.SessionID != sessionID {
		t.Fatalf("expected refresh token to remain associated with session")
	}
	if tokenRepo.revokedIDs == nil || tokenRepo.revokedIDs[0] != tokenRecord.ID {
		t.Fatalf("expected original refresh token to be revoked")
	}
	if len(tokenRepo.markedUsed) != 1 || tokenRepo.markedUsed[0] != tokenRecord.ID {
		t.Fatalf("expected mark used to be called for original token")
	}

	if len(sessionRepo.updateLastSeenCalls) != 1 {
		t.Fatalf("expected session last seen to be updated")
	}
	if sessionRepo.updateLastSeenCalls[0].sessionID != sessionID {
		t.Fatalf("expected UpdateLastSeen to target session %s", sessionID)
	}

	claims := &security.AccessTokenClaims{}
	parsed, err := jwt.ParseWithClaims(accessToken, claims, func(t *jwt.Token) (interface{}, error) {
		return keyProvider.GetVerificationKey(t.Header["kid"].(string))
	})
	if err != nil || !parsed.Valid {
		t.Fatalf("expected access token to be valid: %v", err)
	}
	if claims.SessionID != sessionID {
		t.Fatalf("expected claims session id to remain %s, got %s", sessionID, claims.SessionID)
	}
}

func TestAuthService_RefreshAccessToken_DetectsReplayAndRevokesFamily(t *testing.T) {
	keyProvider, keyDir := createTestKeyProvider(t)
	tokenGenerator, err := security.NewTokenGenerator(keyProvider, "private")
	if err != nil {
		t.Fatalf("token generator: %v", err)
	}

	user := domain.User{ID: "user-2", Username: "replay", Email: "replay@example.com", Status: domain.UserStatusActive, IsActive: true, PasswordHash: "hashed"}
	userRepo := &refreshUserRepository{users: map[string]domain.User{user.ID: user}}

	familyID := "family-replay"
	sessionID := "session-replay"
	rawRefresh := "used-refresh-token"
	hash := security.HashToken(rawRefresh)
	usedTime := time.Now().Add(-time.Minute)

	sessionRepo := &refreshSessionRepository{sessions: map[string]domain.Session{sessionID: {ID: sessionID, UserID: user.ID, ExpiresAt: time.Now().Add(time.Hour)}}}

	tokenRepo := &refreshTokenRepository{records: map[string]domain.RefreshToken{hash: {
		ID:        "token-used",
		UserID:    user.ID,
		SessionID: &sessionID,
		TokenHash: hash,
		FamilyID:  familyID,
		CreatedAt: time.Now().Add(-2 * time.Hour),
		ExpiresAt: time.Now().Add(time.Hour),
		UsedAt:    &usedTime,
	}}}

	cfg := &config.AppConfig{
		App: config.AppSettings{Name: "iam-service", Env: "test"},
		JWT: config.JWTSettings{KeyDirectory: keyDir, AccessTokenTTL: time.Minute, RefreshTokenTTL: time.Hour},
	}

	authService, err := NewAuthService(cfg, userRepo, nil, nil, sessionRepo, tokenRepo, tokenGenerator, keyProvider, nil, nil)
	if err != nil {
		t.Fatalf("NewAuthService: %v", err)
	}

	if _, _, _, _, err := authService.RefreshAccessToken(context.Background(), rawRefresh); !errors.Is(err, ErrRefreshTokenReplay) {
		t.Fatalf("expected ErrRefreshTokenReplay, got %v", err)
	}

	if len(sessionRepo.revokedFamilies) != 1 || sessionRepo.revokedFamilies[0] != familyID {
		t.Fatalf("expected session family %s to be revoked", familyID)
	}
	if len(tokenRepo.revokedFamilies) != 1 || tokenRepo.revokedFamilies[0] != familyID {
		t.Fatalf("expected refresh token family %s to be revoked", familyID)
	}
}
