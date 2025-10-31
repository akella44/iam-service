package usecase

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/arklim/social-platform-iam/internal/core/domain"
	"github.com/arklim/social-platform-iam/internal/core/port"
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
func (r *refreshUserRepository) Update(context.Context, domain.User) error {
	return errors.New("unexpected call: Update")
}
func (r *refreshUserRepository) SoftDelete(context.Context, string) error {
	return errors.New("unexpected call: SoftDelete")
}
func (r *refreshUserRepository) List(context.Context, port.UserFilter) ([]domain.User, error) {
	return nil, errors.New("unexpected call: List")
}
func (r *refreshUserRepository) Count(context.Context, port.UserFilter) (int, error) {
	return 0, errors.New("unexpected call: Count")
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
	versionCalls    []struct {
		sessionID string
		reason    string
	}
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

func (r *refreshSessionRepository) GetVersion(_ context.Context, sessionID string) (int64, error) {
	session, ok := r.sessions[sessionID]
	if !ok {
		return 0, repository.ErrNotFound
	}
	return session.Version, nil
}

func (r *refreshSessionRepository) IncrementVersion(_ context.Context, sessionID string, reason string) (int64, error) {
	session, ok := r.sessions[sessionID]
	if !ok {
		return 0, repository.ErrNotFound
	}
	if session.Version <= 0 {
		session.Version = 1
	} else {
		session.Version++
	}
	r.versionCalls = append(r.versionCalls, struct {
		sessionID string
		reason    string
	}{sessionID: sessionID, reason: reason})
	r.sessions[sessionID] = session
	return session.Version, nil
}

func (r *refreshSessionRepository) SetVersion(_ context.Context, sessionID string, version int64) error {
	session, ok := r.sessions[sessionID]
	if !ok {
		return repository.ErrNotFound
	}
	if version <= 0 {
		session.Version = 1
	} else {
		session.Version = version
	}
	r.sessions[sessionID] = session
	return nil
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

func (r *refreshTokenRepository) UpdateRefreshTokenIssuedVersion(context.Context, string, int64) error {
	return nil
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

	session := domain.Session{ID: sessionID, UserID: user.ID, Version: 1, ExpiresAt: expiresAt.Add(time.Hour)}
	sessionRepo := &refreshSessionRepository{sessions: map[string]domain.Session{sessionID: session}}

	tokenRecord := domain.RefreshToken{
		ID:            "token-1",
		UserID:        user.ID,
		SessionID:     &sessionID,
		TokenHash:     hash,
		FamilyID:      familyID,
		IssuedVersion: 1,
		CreatedAt:     time.Now().Add(-time.Minute),
		ExpiresAt:     expiresAt,
		IP:            stringPtr("192.0.2.50"),
		UserAgent:     stringPtr("GoTest/1.0"),
	}

	tokenRepo := &refreshTokenRepository{records: map[string]domain.RefreshToken{hash: tokenRecord}}
	cache := &stubSessionVersionCache{}

	cfg := &config.AppConfig{
		App: config.AppSettings{Name: "iam-service", Env: "test"},
		JWT: config.JWTSettings{KeyDirectory: keyDir, AccessTokenTTL: time.Minute, RefreshTokenTTL: time.Hour},
	}

	authService, err := NewAuthService(cfg, userRepo, nil, nil, sessionRepo, tokenRepo, tokenGenerator, keyProvider, nil, nil)
	if err != nil {
		t.Fatalf("NewAuthService: %v", err)
	}
	authService.WithSessionVersionCache(cache, time.Minute)

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
	if len(sessionRepo.versionCalls) != 1 {
		t.Fatalf("expected session version to be bumped once")
	}
	bump := sessionRepo.versionCalls[0]
	if bump.sessionID != sessionID {
		t.Fatalf("expected version bump for session %s", sessionID)
	}
	if bump.reason != "refresh_rotation" {
		t.Fatalf("expected version bump reason refresh_rotation, got %s", bump.reason)
	}
	updatedSession := sessionRepo.sessions[sessionID]
	if updatedSession.Version != 2 {
		t.Fatalf("expected session version to increment to 2, got %d", updatedSession.Version)
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
	if claims.SessionVersion != 2 {
		t.Fatalf("expected claims session version 2, got %d", claims.SessionVersion)
	}
	if len(tokenRepo.createdTokens) == 0 || tokenRepo.createdTokens[0].IssuedVersion != 2 {
		t.Fatalf("expected new refresh token issued version 2, got %+v", tokenRepo.createdTokens)
	}
	foundCache := false
	for _, call := range cache.setCalls {
		if call.sessionID == sessionID && call.version == 2 {
			foundCache = true
			break
		}
	}
	if !foundCache {
		t.Fatalf("expected session version cache to record bumped version for session %s", sessionID)
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

	sessionRepo := &refreshSessionRepository{sessions: map[string]domain.Session{sessionID: {ID: sessionID, UserID: user.ID, Version: 1, ExpiresAt: time.Now().Add(time.Hour)}}}

	tokenRepo := &refreshTokenRepository{records: map[string]domain.RefreshToken{hash: {
		ID:            "token-used",
		UserID:        user.ID,
		SessionID:     &sessionID,
		TokenHash:     hash,
		FamilyID:      familyID,
		IssuedVersion: 1,
		CreatedAt:     time.Now().Add(-2 * time.Hour),
		ExpiresAt:     time.Now().Add(time.Hour),
		UsedAt:        &usedTime,
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

func TestAuthService_RefreshAccessToken_DetectsStaleVersion(t *testing.T) {
	keyProvider, keyDir := createTestKeyProvider(t)
	tokenGenerator, err := security.NewTokenGenerator(keyProvider, "private")
	if err != nil {
		t.Fatalf("token generator: %v", err)
	}

	user := domain.User{ID: "user-stale", Username: "stale", Email: "stale@example.com", Status: domain.UserStatusActive, IsActive: true, PasswordHash: "hashed"}
	userRepo := &refreshUserRepository{users: map[string]domain.User{user.ID: user}}

	familyID := "family-stale"
	sessionID := "session-stale"
	rawRefresh := "stale-refresh-token"
	hash := security.HashToken(rawRefresh)

	session := domain.Session{ID: sessionID, UserID: user.ID, Version: 5, ExpiresAt: time.Now().Add(time.Hour)}
	sessionRepo := &refreshSessionRepository{sessions: map[string]domain.Session{sessionID: session}}

	issuedAt := time.Now().Add(-time.Minute)
	tokenRecord := domain.RefreshToken{
		ID:            "token-stale",
		UserID:        user.ID,
		SessionID:     &sessionID,
		TokenHash:     hash,
		FamilyID:      familyID,
		IssuedVersion: 2,
		CreatedAt:     issuedAt,
		ExpiresAt:     time.Now().Add(time.Hour),
	}

	tokenRepo := &refreshTokenRepository{records: map[string]domain.RefreshToken{hash: tokenRecord}}
	cache := &stubSessionVersionCache{}

	cfg := &config.AppConfig{
		App: config.AppSettings{Name: "iam-service", Env: "test"},
		JWT: config.JWTSettings{KeyDirectory: keyDir, AccessTokenTTL: time.Minute, RefreshTokenTTL: time.Hour},
	}

	authService, err := NewAuthService(cfg, userRepo, nil, nil, sessionRepo, tokenRepo, tokenGenerator, keyProvider, nil, nil)
	if err != nil {
		t.Fatalf("NewAuthService: %v", err)
	}
	authService.WithSessionVersionCache(cache, time.Minute)

	_, _, _, _, err = authService.RefreshAccessToken(context.Background(), rawRefresh)
	if !errors.Is(err, ErrStaleRefreshToken) {
		t.Fatalf("expected ErrStaleRefreshToken, got %v", err)
	}
	if len(tokenRepo.markedUsed) != 0 {
		t.Fatalf("expected stale token to short-circuit before marking used")
	}
	if len(tokenRepo.revokedIDs) != 0 {
		t.Fatalf("expected stale token to short-circuit before revocation")
	}
	if len(sessionRepo.versionCalls) != 0 {
		t.Fatalf("expected no session version bumps when stale detected")
	}
	foundCache := false
	for _, call := range cache.setCalls {
		if call.sessionID == sessionID && call.version == session.Version {
			foundCache = true
			break
		}
	}
	if !foundCache {
		t.Fatalf("expected session version to be cached even on stale detection")
	}
}
