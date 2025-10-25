package usecase

import (
	"context"
	"errors"
	"testing"
	"time"

	uuid "github.com/google/uuid"

	"github.com/arklim/social-platform-iam/internal/core/domain"
	"github.com/arklim/social-platform-iam/internal/infra/config"
	"github.com/arklim/social-platform-iam/internal/infra/security"
)

type loginUserRepository struct {
	user domain.User
}

func (r *loginUserRepository) Create(context.Context, domain.User) error {
	return errors.New("unexpected call: Create")
}

func (r *loginUserRepository) GetByID(context.Context, string) (*domain.User, error) {
	return nil, errors.New("unexpected call: GetByID")
}

func (r *loginUserRepository) GetByIdentifier(_ context.Context, identifier string) (*domain.User, error) {
	if identifier != r.user.Username && identifier != r.user.Email {
		return nil, errors.New("user not found")
	}
	copy := r.user
	return &copy, nil
}

func (r *loginUserRepository) UpdateStatus(context.Context, string, domain.UserStatus) error {
	return errors.New("unexpected call: UpdateStatus")
}

func (r *loginUserRepository) UpdatePassword(context.Context, string, string, string, time.Time) error {
	return errors.New("unexpected call: UpdatePassword")
}

func (r *loginUserRepository) AssignRoles(context.Context, string, []string) error {
	return errors.New("unexpected call: AssignRoles")
}

func (r *loginUserRepository) RevokeRoles(context.Context, string, []string) error {
	return errors.New("unexpected call: RevokeRoles")
}

func (r *loginUserRepository) GetUserRoles(context.Context, string) ([]domain.UserRole, error) {
	return nil, errors.New("unexpected call: GetUserRoles")
}

func (r *loginUserRepository) ListPasswordHistory(context.Context, string, int) ([]domain.UserPasswordHistory, error) {
	return nil, errors.New("unexpected call: ListPasswordHistory")
}

func (r *loginUserRepository) AddPasswordHistory(context.Context, domain.UserPasswordHistory) error {
	return errors.New("unexpected call: AddPasswordHistory")
}

func (r *loginUserRepository) TrimPasswordHistory(context.Context, string, int) error {
	return errors.New("unexpected call: TrimPasswordHistory")
}

//

type loginRoleRepository struct {
	roles []domain.Role
}

func (r *loginRoleRepository) Create(context.Context, domain.Role) error {
	return errors.New("unexpected call: CreateRole")
}
func (r *loginRoleRepository) List(context.Context) ([]domain.Role, error) {
	return nil, errors.New("unexpected call: List")
}
func (r *loginRoleRepository) GetByName(context.Context, string) (*domain.Role, error) {
	return nil, errors.New("unexpected call: GetByName")
}
func (r *loginRoleRepository) AssignPermissions(context.Context, string, []string) (int, error) {
	return 0, errors.New("unexpected call: AssignPermissions")
}
func (r *loginRoleRepository) RevokePermissions(context.Context, string, []string) (int, error) {
	return 0, errors.New("unexpected call: RevokePermissions")
}
func (r *loginRoleRepository) GetRolePermissions(context.Context, string) ([]domain.Permission, error) {
	return nil, errors.New("unexpected call: GetRolePermissions")
}
func (r *loginRoleRepository) AssignToUsers(context.Context, string, []string) error {
	return errors.New("unexpected call: AssignToUsers")
}
func (r *loginRoleRepository) ListByUser(context.Context, string) ([]domain.Role, error) {
	copy := make([]domain.Role, len(r.roles))
	copy = append(copy[:0], r.roles...)
	return copy, nil
}

//

type loginSessionRepository struct {
	createdSessions []domain.Session
	storedEvents    []domain.SessionEvent
}

func (r *loginSessionRepository) Create(_ context.Context, session domain.Session) error {
	r.createdSessions = append(r.createdSessions, session)
	return nil
}

func (r *loginSessionRepository) Get(context.Context, string) (*domain.Session, error) {
	return nil, errors.New("unexpected call: Get")
}

func (r *loginSessionRepository) ListByUser(context.Context, string) ([]domain.Session, error) {
	return nil, errors.New("unexpected call: ListByUser")
}

func (r *loginSessionRepository) UpdateLastSeen(context.Context, string, *string, *string) error {
	return errors.New("unexpected call: UpdateLastSeen")
}

func (r *loginSessionRepository) Revoke(context.Context, string, string) error {
	return errors.New("unexpected call: Revoke")
}

func (r *loginSessionRepository) RevokeByFamily(context.Context, string, string) (int, error) {
	return 0, errors.New("unexpected call: RevokeByFamily")
}

func (r *loginSessionRepository) RevokeAllForUser(context.Context, string, string) (int, error) {
	return 0, errors.New("unexpected call: RevokeAllForUser")
}

func (r *loginSessionRepository) StoreEvent(_ context.Context, event domain.SessionEvent) error {
	r.storedEvents = append(r.storedEvents, event)
	return nil
}

func (r *loginSessionRepository) RevokeSessionAccessTokens(context.Context, string, string) (int, error) {
	return 0, errors.New("unexpected call: RevokeSessionAccessTokens")
}

//

type loginTokenRepository struct {
	lastRefresh domain.RefreshToken
	trackedJTIs []domain.AccessTokenJTI
}

func (r *loginTokenRepository) CreateVerification(context.Context, domain.VerificationToken) error {
	return errors.New("unexpected call: CreateVerification")
}
func (r *loginTokenRepository) GetVerificationByHash(context.Context, string) (*domain.VerificationToken, error) {
	return nil, errors.New("unexpected call: GetVerificationByHash")
}
func (r *loginTokenRepository) ConsumeVerification(context.Context, string) error {
	return errors.New("unexpected call: ConsumeVerification")
}
func (r *loginTokenRepository) CreatePasswordReset(context.Context, domain.PasswordResetToken) error {
	return errors.New("unexpected call: CreatePasswordReset")
}
func (r *loginTokenRepository) GetPasswordResetByHash(context.Context, string) (*domain.PasswordResetToken, error) {
	return nil, errors.New("unexpected call: GetPasswordResetByHash")
}
func (r *loginTokenRepository) ConsumePasswordReset(context.Context, string) error {
	return errors.New("unexpected call: ConsumePasswordReset")
}
func (r *loginTokenRepository) CreateRefreshToken(_ context.Context, token domain.RefreshToken) error {
	r.lastRefresh = token
	return nil
}
func (r *loginTokenRepository) GetRefreshTokenByHash(context.Context, string) (*domain.RefreshToken, error) {
	return nil, errors.New("unexpected call: GetRefreshTokenByHash")
}
func (r *loginTokenRepository) RevokeRefreshToken(context.Context, string) error { return nil }
func (r *loginTokenRepository) MarkRefreshTokenUsed(context.Context, string, time.Time) error {
	return nil
}
func (r *loginTokenRepository) RevokeRefreshTokensByFamily(context.Context, string, string) (int, error) {
	return 0, nil
}
func (r *loginTokenRepository) RevokeRefreshTokensForUser(context.Context, string) error { return nil }
func (r *loginTokenRepository) TrackJTI(_ context.Context, record domain.AccessTokenJTI) error {
	r.trackedJTIs = append(r.trackedJTIs, record)
	return nil
}
func (r *loginTokenRepository) RevokeJTI(context.Context, domain.RevokedAccessTokenJTI) error {
	return nil
}
func (r *loginTokenRepository) RevokeJTIsBySession(context.Context, string, string) (int, error) {
	return 0, nil
}
func (r *loginTokenRepository) RevokeJTIsForUser(context.Context, string, string) (int, error) {
	return 0, nil
}
func (r *loginTokenRepository) IsJTIRevoked(context.Context, string) (bool, error) { return false, nil }
func (r *loginTokenRepository) CleanupExpiredJTIs(context.Context, time.Time) (int, error) {
	return 0, nil
}

//

type noopRateLimitStore struct {
	trimCalls   int
	countCalls  int
	recordCalls int
}

func (s *noopRateLimitStore) TrimWindow(context.Context, string, time.Duration, time.Time) error {
	s.trimCalls++
	return nil
}

func (s *noopRateLimitStore) CountAttempts(context.Context, string, time.Duration, time.Time) (int, error) {
	s.countCalls++
	return 0, nil
}

func (s *noopRateLimitStore) RecordAttempt(context.Context, string, time.Time) error {
	s.recordCalls++
	return nil
}

func (s *noopRateLimitStore) OldestAttempt(context.Context, string, time.Duration, time.Time) (time.Time, bool, error) {
	return time.Time{}, false, nil
}

func TestAuthService_Login_CreatesSessionWithMetadata(t *testing.T) {
	hashed, err := security.HashPassword("Sup3rStrong!1")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	user := domain.User{
		ID:           uuid.NewString(),
		Username:     "login-user",
		Email:        "login@example.com",
		PasswordHash: hashed,
		IsActive:     true,
		Status:       domain.UserStatusActive,
	}

	userRepo := &loginUserRepository{user: user}
	rolesRepo := &loginRoleRepository{roles: []domain.Role{{Name: "admin"}}}
	sessionRepo := &loginSessionRepository{}
	tokenRepo := &loginTokenRepository{}
	rateLimiter := &noopRateLimitStore{}

	keyProvider, keyDir := createTestKeyProvider(t)
	tokenGenerator, err := security.NewTokenGenerator(keyProvider, "private")
	if err != nil {
		t.Fatalf("token generator: %v", err)
	}

	cfg := &config.AppConfig{
		App:       config.AppSettings{Name: "iam-service", Env: "test"},
		JWT:       config.JWTSettings{KeyDirectory: keyDir, AccessTokenTTL: time.Minute, RefreshTokenTTL: time.Hour},
		RateLimit: config.RateLimitSettings{LoginMaxAttempts: 5, WindowDuration: time.Minute},
	}

	authService, err := NewAuthService(cfg, userRepo, rolesRepo, nil, sessionRepo, tokenRepo, tokenGenerator, keyProvider, rateLimiter, nil)
	if err != nil {
		t.Fatalf("NewAuthService: %v", err)
	}

	input := LoginInput{
		Identifier:  "login@example.com",
		Password:    "Sup3rStrong!1",
		DeviceID:    "device-123",
		DeviceLabel: "Chrome on Mac",
		IP:          "203.0.113.10",
		UserAgent:   "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
	}

	result, err := authService.Login(context.Background(), input)
	if err != nil {
		t.Fatalf("Login returned error: %v", err)
	}

	if result.Session.ID == "" {
		t.Fatalf("expected session ID to be set")
	}
	if result.Session.DeviceLabel == nil || *result.Session.DeviceLabel != "Chrome on Mac" {
		t.Fatalf("expected device label preserved in session")
	}
	if sessionRepo.createdSessions == nil || len(sessionRepo.createdSessions) != 1 {
		t.Fatalf("expected exactly one session to be created")
	}

	storedSession := sessionRepo.createdSessions[0]
	if storedSession.DeviceID == nil || *storedSession.DeviceID != "device-123" {
		t.Fatalf("expected device id persisted, got %+v", storedSession.DeviceID)
	}
	if storedSession.IPFirst == nil || *storedSession.IPFirst != "203.0.113.10" {
		t.Fatalf("expected ip metadata to be stored")
	}
	if storedSession.UserAgent == nil || *storedSession.UserAgent == "" {
		t.Fatalf("expected user agent to be stored")
	}

	if len(sessionRepo.storedEvents) != 1 {
		t.Fatalf("expected a session event to be recorded")
	}
	event := sessionRepo.storedEvents[0]
	if event.Kind != "login" {
		t.Fatalf("expected login event, got %s", event.Kind)
	}
	if event.SessionID != storedSession.ID {
		t.Fatalf("expected event session id to match session")
	}

	if tokenRepo.lastRefresh.Metadata["device_id"] != "device-123" {
		t.Fatalf("expected refresh token metadata to include device id")
	}
	if tokenRepo.lastRefresh.Metadata["device_label"] != "Chrome on Mac" {
		t.Fatalf("expected refresh token metadata to include device label")
	}
	if tokenRepo.lastRefresh.Metadata["ip"] != "203.0.113.10" {
		t.Fatalf("expected refresh token metadata to include ip")
	}
	if result.Session.RefreshTokenID == nil || *result.Session.RefreshTokenID == "" {
		t.Fatalf("expected session to link to refresh token id")
	}

	claims, err := authService.ParseAccessToken(result.AccessToken)
	if err != nil {
		t.Fatalf("ParseAccessToken returned error: %v", err)
	}
	if claims.SessionID != storedSession.ID {
		t.Fatalf("expected claims session id %s, got %s", storedSession.ID, claims.SessionID)
	}
	if len(claims.Roles) != 1 || claims.Roles[0] != "admin" {
		t.Fatalf("expected roles to include admin, got %+v", claims.Roles)
	}

	if result.User.PasswordHash != "" {
		t.Fatalf("expected password hash to be sanitized in response")
	}

	if rateLimiter.recordCalls != 2 {
		t.Fatalf("expected record attempts for both ip and identifier, got %d", rateLimiter.recordCalls)
	}
}
