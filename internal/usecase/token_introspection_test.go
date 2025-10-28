package usecase

import (
	"context"
	"testing"
	"time"

	"github.com/arklim/social-platform-iam/internal/core/domain"
	"github.com/arklim/social-platform-iam/internal/core/port"
	"github.com/arklim/social-platform-iam/internal/infra/security"
	"github.com/arklim/social-platform-iam/internal/repository"
)

type revocationStoreStub struct {
	revoked   map[string]string
	markCalls []revocationMarkCall
	markErr   error
}

type revocationMarkCall struct {
	jti    string
	reason string
	ttl    time.Duration
}

func newRevocationStoreStub(initial map[string]string) *revocationStoreStub {
	store := &revocationStoreStub{revoked: make(map[string]string)}
	for k, v := range initial {
		store.revoked[k] = v
	}
	return store
}

func (s *revocationStoreStub) MarkRevoked(_ context.Context, jti string, reason string, ttl time.Duration) error {
	if s.markErr != nil {
		return s.markErr
	}
	if s.revoked == nil {
		s.revoked = make(map[string]string)
	}
	s.revoked[jti] = reason
	s.markCalls = append(s.markCalls, revocationMarkCall{jti: jti, reason: reason, ttl: ttl})
	return nil
}

func (s *revocationStoreStub) IsRevoked(_ context.Context, jti string) (bool, string, error) {
	if s.revoked == nil {
		return false, "", nil
	}
	reason, ok := s.revoked[jti]
	if !ok {
		return false, "", nil
	}
	return true, reason, nil
}

type tokenRepositoryStub struct {
	revoked map[string]bool
}

func (t *tokenRepositoryStub) CreateVerification(context.Context, domain.VerificationToken) error {
	return nil
}
func (t *tokenRepositoryStub) GetVerificationByHash(context.Context, string) (*domain.VerificationToken, error) {
	return nil, repository.ErrNotFound
}
func (t *tokenRepositoryStub) ConsumeVerification(context.Context, string) error { return nil }
func (t *tokenRepositoryStub) CreatePasswordReset(context.Context, domain.PasswordResetToken) error {
	return nil
}
func (t *tokenRepositoryStub) GetPasswordResetByHash(context.Context, string) (*domain.PasswordResetToken, error) {
	return nil, repository.ErrNotFound
}
func (t *tokenRepositoryStub) ConsumePasswordReset(context.Context, string) error { return nil }
func (t *tokenRepositoryStub) CreateRefreshToken(context.Context, domain.RefreshToken) error {
	return nil
}
func (t *tokenRepositoryStub) GetRefreshTokenByHash(context.Context, string) (*domain.RefreshToken, error) {
	return nil, repository.ErrNotFound
}
func (t *tokenRepositoryStub) RevokeRefreshToken(context.Context, string) error { return nil }
func (t *tokenRepositoryStub) MarkRefreshTokenUsed(context.Context, string, time.Time) error {
	return nil
}
func (t *tokenRepositoryStub) RevokeRefreshTokensByFamily(context.Context, string, string) (int, error) {
	return 0, nil
}
func (t *tokenRepositoryStub) RevokeRefreshTokensForUser(context.Context, string) error { return nil }
func (t *tokenRepositoryStub) TrackJTI(context.Context, domain.AccessTokenJTI) error    { return nil }
func (t *tokenRepositoryStub) RevokeJTI(context.Context, domain.RevokedAccessTokenJTI) error {
	return nil
}
func (t *tokenRepositoryStub) RevokeJTIsBySession(context.Context, string, string) (int, error) {
	return 0, nil
}
func (t *tokenRepositoryStub) RevokeJTIsForUser(context.Context, string, string) (int, error) {
	return 0, nil
}
func (t *tokenRepositoryStub) IsJTIRevoked(_ context.Context, jti string) (bool, error) {
	if t.revoked == nil {
		return false, nil
	}
	return t.revoked[jti], nil
}
func (t *tokenRepositoryStub) CleanupExpiredJTIs(context.Context, time.Time) (int, error) {
	return 0, nil
}

type sessionRepositoryStub struct {
	session *domain.Session
	err     error
}

func (s *sessionRepositoryStub) Create(context.Context, domain.Session) error { return nil }
func (s *sessionRepositoryStub) Get(context.Context, string) (*domain.Session, error) {
	if s.err != nil {
		return nil, s.err
	}
	if s.session == nil {
		return nil, repository.ErrNotFound
	}
	copy := *s.session
	if s.session.RevokedAt != nil {
		revokedAt := s.session.RevokedAt.UTC()
		copy.RevokedAt = &revokedAt
	}
	if s.session.RevokeReason != nil {
		reason := *s.session.RevokeReason
		copy.RevokeReason = &reason
	}
	if s.session.DeviceLabel != nil {
		label := *s.session.DeviceLabel
		copy.DeviceLabel = &label
	}
	if s.session.DeviceID != nil {
		device := *s.session.DeviceID
		copy.DeviceID = &device
	}
	if s.session.IPLast != nil {
		ip := *s.session.IPLast
		copy.IPLast = &ip
	}
	if s.session.IPFirst != nil {
		ip := *s.session.IPFirst
		copy.IPFirst = &ip
	}
	if s.session.UserAgent != nil {
		ua := *s.session.UserAgent
		copy.UserAgent = &ua
	}
	if s.session.RefreshTokenID != nil {
		tokenID := *s.session.RefreshTokenID
		copy.RefreshTokenID = &tokenID
	}
	return &copy, nil
}
func (s *sessionRepositoryStub) ListByUser(context.Context, string) ([]domain.Session, error) {
	return nil, nil
}
func (s *sessionRepositoryStub) UpdateLastSeen(context.Context, string, *string, *string) error {
	return nil
}
func (s *sessionRepositoryStub) Revoke(context.Context, string, string) error { return nil }
func (s *sessionRepositoryStub) RevokeByFamily(context.Context, string, string) (int, error) {
	return 0, nil
}
func (s *sessionRepositoryStub) RevokeAllForUser(context.Context, string, string) (int, error) {
	return 0, nil
}
func (s *sessionRepositoryStub) StoreEvent(context.Context, domain.SessionEvent) error { return nil }
func (s *sessionRepositoryStub) RevokeSessionAccessTokens(context.Context, string, string) (int, error) {
	return 0, nil
}

type userRepositoryStub struct {
	user *domain.User
	err  error
}

func (u *userRepositoryStub) Create(context.Context, domain.User) error { return nil }
func (u *userRepositoryStub) GetByID(context.Context, string) (*domain.User, error) {
	if u.err != nil {
		return nil, u.err
	}
	if u.user == nil {
		return nil, repository.ErrNotFound
	}
	copy := *u.user
	return &copy, nil
}
func (u *userRepositoryStub) GetByIdentifier(context.Context, string) (*domain.User, error) {
	return nil, repository.ErrNotFound
}
func (u *userRepositoryStub) UpdateStatus(context.Context, string, domain.UserStatus) error {
	return nil
}
func (u *userRepositoryStub) UpdatePassword(context.Context, string, string, string, time.Time) error {
	return nil
}
func (u *userRepositoryStub) AssignRoles(context.Context, string, []string) error { return nil }
func (u *userRepositoryStub) RevokeRoles(context.Context, string, []string) error { return nil }
func (u *userRepositoryStub) GetUserRoles(context.Context, string) ([]domain.UserRole, error) {
	return nil, nil
}
func (u *userRepositoryStub) ListPasswordHistory(context.Context, string, int) ([]domain.UserPasswordHistory, error) {
	return nil, nil
}
func (u *userRepositoryStub) AddPasswordHistory(context.Context, domain.UserPasswordHistory) error {
	return nil
}
func (u *userRepositoryStub) TrimPasswordHistory(context.Context, string, int) error { return nil }
func (u *userRepositoryStub) Update(context.Context, domain.User) error              { return nil }
func (u *userRepositoryStub) SoftDelete(context.Context, string) error               { return nil }
func (u *userRepositoryStub) List(context.Context, port.UserFilter) ([]domain.User, error) {
	return nil, nil
}
func (u *userRepositoryStub) Count(context.Context, port.UserFilter) (int, error) { return 0, nil }

var _ RevocationStore = (*revocationStoreStub)(nil)
var _ port.TokenRepository = (*tokenRepositoryStub)(nil)
var _ port.SessionRepository = (*sessionRepositoryStub)(nil)
var _ port.UserRepository = (*userRepositoryStub)(nil)

func TestTokenService_Introspect_Success(t *testing.T) {
	t.Helper()

	service, keyProvider, cfg := newTestTokenService(t)

	now := service.now()
	issuedAt := now.Add(-5 * time.Minute)

	claims, err := security.NewAccessTokenClaims(security.AccessTokenOptions{
		UserID:    "user-123",
		Issuer:    cfg.App.Name,
		Audience:  []string{"service-a"},
		Roles:     []string{"admin"},
		TTL:       24 * time.Hour,
		IssuedAt:  issuedAt,
		NotBefore: issuedAt,
		JTI:       "jti-success",
		SessionID: "sess-123",
	})
	if err != nil {
		t.Fatalf("NewAccessTokenClaims failed: %v", err)
	}

	token := signTestToken(t, keyProvider, claims, testSigningKID)

	session := domain.Session{
		ID:        "sess-123",
		UserID:    "user-123",
		CreatedAt: issuedAt,
		LastSeen:  now.Add(-5 * time.Minute),
		ExpiresAt: now.Add(8 * time.Hour),
	}

	user := &domain.User{ID: "user-123", Username: "alice"}

	service.revocations = newRevocationStoreStub(nil)
	service.tokens = &tokenRepositoryStub{revoked: map[string]bool{}}
	service.sessions = &sessionRepositoryStub{session: &session}
	service.users = &userRepositoryStub{user: user}

	result, err := service.Introspect(context.Background(), token, true, []string{"service-a"})
	if err != nil {
		t.Fatalf("Introspect returned error: %v", err)
	}

	if !result.Active {
		t.Fatalf("expected token to be active")
	}
	if result.Session == nil || result.Session.ID != "sess-123" {
		t.Fatalf("expected session sess-123, got %+v", result.Session)
	}
	if result.Username != "alice" {
		t.Fatalf("expected username alice, got %s", result.Username)
	}
	if !result.IssuedAt.Equal(claims.RegisteredClaims.IssuedAt.Time) {
		t.Fatalf("expected issued at to match claims")
	}
}

func TestTokenService_Introspect_RevokedInCache(t *testing.T) {
	t.Helper()

	service, keyProvider, cfg := newTestTokenService(t)

	now := service.now()
	issuedAt := now.Add(-15 * time.Minute)
	claims, err := security.NewAccessTokenClaims(security.AccessTokenOptions{
		UserID:    "user-456",
		Issuer:    cfg.App.Name,
		Audience:  []string{"service-a"},
		TTL:       24 * time.Hour,
		IssuedAt:  issuedAt,
		NotBefore: issuedAt,
		JTI:       "jti-cache",
		SessionID: "sess-456",
	})
	if err != nil {
		t.Fatalf("NewAccessTokenClaims failed: %v", err)
	}

	token := signTestToken(t, keyProvider, claims, testSigningKID)

	service.revocations = newRevocationStoreStub(map[string]string{"jti-cache": "session_revoked"})
	service.tokens = &tokenRepositoryStub{revoked: map[string]bool{}}
	service.sessions = &sessionRepositoryStub{session: &domain.Session{
		ID:        "sess-456",
		UserID:    "user-456",
		CreatedAt: issuedAt,
		LastSeen:  issuedAt,
		ExpiresAt: service.now().Add(2 * time.Hour),
	}}
	service.users = &userRepositoryStub{user: &domain.User{ID: "user-456", Username: "bob"}}

	result, err := service.Introspect(context.Background(), token, true, []string{"service-a"})
	if err != nil {
		t.Fatalf("Introspect returned error: %v", err)
	}

	if !result.Revoked || result.Active {
		t.Fatalf("expected token to be revoked and inactive")
	}
	if result.RevocationReason != "session_revoked" {
		t.Fatalf("expected revocation reason session_revoked, got %s", result.RevocationReason)
	}
}

func TestTokenService_Introspect_RevokedInRepositoryCachesResult(t *testing.T) {
	t.Helper()

	service, keyProvider, cfg := newTestTokenService(t)

	now := service.now()
	issuedAt := now.Add(-20 * time.Minute)
	claims, err := security.NewAccessTokenClaims(security.AccessTokenOptions{
		UserID:    "user-789",
		Issuer:    cfg.App.Name,
		Audience:  []string{"service-a"},
		TTL:       24 * time.Hour,
		IssuedAt:  issuedAt,
		NotBefore: issuedAt,
		JTI:       "jti-db",
		SessionID: "sess-789",
	})
	if err != nil {
		t.Fatalf("NewAccessTokenClaims failed: %v", err)
	}

	token := signTestToken(t, keyProvider, claims, testSigningKID)

	revocations := newRevocationStoreStub(nil)
	tokens := &tokenRepositoryStub{revoked: map[string]bool{"jti-db": true}}

	service.revocations = revocations
	service.tokens = tokens
	service.sessions = &sessionRepositoryStub{err: repository.ErrNotFound}
	service.users = &userRepositoryStub{err: repository.ErrNotFound}

	result, err := service.Introspect(context.Background(), token, true, []string{"service-a"})
	if err != nil {
		t.Fatalf("Introspect returned error: %v", err)
	}

	if !result.Revoked || result.Active {
		t.Fatalf("expected token to be revoked and inactive")
	}
	if len(revocations.markCalls) != 1 {
		t.Fatalf("expected MarkRevoked to be called once, got %d", len(revocations.markCalls))
	}
	if revocations.markCalls[0].jti != "jti-db" {
		t.Fatalf("expected cached jti jti-db, got %s", revocations.markCalls[0].jti)
	}
	if revocations.markCalls[0].ttl <= 0 {
		t.Fatalf("expected positive ttl, got %v", revocations.markCalls[0].ttl)
	}
}
