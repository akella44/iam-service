package usecase

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	uuid "github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/arklim/social-platform-iam/internal/core/domain"
	"github.com/arklim/social-platform-iam/internal/core/port"
	"github.com/arklim/social-platform-iam/internal/infra/config"
	"github.com/arklim/social-platform-iam/internal/infra/security"
	"github.com/arklim/social-platform-iam/internal/repository"
)

var (
	// ErrInvalidCredentials indicates the provided identifier or password are incorrect.
	ErrInvalidCredentials = errors.New("invalid credentials")
	// ErrInactiveAccount indicates the account is disabled or locked.
	ErrInactiveAccount = errors.New("account is not active")
	// ErrSessionRevoked indicates the session was revoked ahead of validation.
	ErrSessionRevoked = errors.New("session revoked")
	// ErrSessionExpired indicates the session expired before validation.
	ErrSessionExpired = errors.New("session expired")
	// ErrAccountPending indicates the account requires verification before login.
	ErrAccountPending = errors.New("account pending verification")
	// ErrInvalidRefreshToken indicates the provided refresh token does not exist or was revoked.
	ErrInvalidRefreshToken = errors.New("invalid refresh token")
	// ErrExpiredRefreshToken indicates the provided refresh token has expired.
	ErrExpiredRefreshToken = errors.New("refresh token expired")
	// ErrStaleRefreshToken indicates the provided refresh token was issued against an out-of-date session version.
	ErrStaleRefreshToken = errors.New("refresh token stale")
	// ErrRefreshTokenUnavailable indicates refresh token issuance is not configured.
	ErrRefreshTokenUnavailable = errors.New("refresh token unavailable")
	// ErrInvalidAccessToken indicates the provided access token is malformed or signature validation failed.
	ErrInvalidAccessToken = errors.New("invalid access token")
	// ErrExpiredAccessToken indicates the provided access token has expired.
	ErrExpiredAccessToken = errors.New("access token expired")
	// ErrRateLimitExceeded indicates the login rate limit threshold has been reached.
	ErrRateLimitExceeded = errors.New("rate limit exceeded")
	// ErrRefreshTokenReplay indicates a refresh token replay attempt was detected.
	ErrRefreshTokenReplay = errors.New("refresh token replay detected")
)

// SessionVersionMismatchError conveys details about a stale refresh token where the session version has advanced.
type SessionVersionMismatchError struct {
	SessionID      string
	TokenVersion   int64
	CurrentVersion int64
}

// Error satisfies the error interface.
func (e *SessionVersionMismatchError) Error() string {
	if e == nil {
		return ErrStaleRefreshToken.Error()
	}
	return fmt.Sprintf("%s (session_id=%s token_version=%d current_version=%d)", ErrStaleRefreshToken.Error(), strings.TrimSpace(e.SessionID), e.TokenVersion, e.CurrentVersion)
}

// Unwrap exposes the sentinel ErrStaleRefreshToken for errors.Is/As comparisons.
func (e *SessionVersionMismatchError) Unwrap() error {
	return ErrStaleRefreshToken
}

const (
	rateLimitScopeIP      = "login:ip"
	rateLimitScopeAccount = "login:account"
)

// RateLimitExceededError conveys additional metadata for rate limit violations.
type RateLimitExceededError struct {
	Scope      string
	RetryAfter time.Duration
}

// Error implements the error interface.
func (e *RateLimitExceededError) Error() string {
	if e == nil {
		return ErrRateLimitExceeded.Error()
	}
	if e.Scope != "" && e.RetryAfter > 0 {
		return fmt.Sprintf("%s (%s, retry in %s)", ErrRateLimitExceeded.Error(), e.Scope, e.RetryAfter)
	}
	if e.Scope != "" {
		return fmt.Sprintf("%s (%s)", ErrRateLimitExceeded.Error(), e.Scope)
	}
	if e.RetryAfter > 0 {
		return fmt.Sprintf("%s (retry in %s)", ErrRateLimitExceeded.Error(), e.RetryAfter)
	}
	return ErrRateLimitExceeded.Error()
}

// Unwrap enables errors.Is comparisons against ErrRateLimitExceeded.
func (e *RateLimitExceededError) Unwrap() error {
	return ErrRateLimitExceeded
}

// AuthenticationError encapsulates authentication failures while preserving sanitized user context.
type AuthenticationError struct {
	Err   error
	User  *domain.User
	Roles []string
}

// Error implements the error interface.
func (e *AuthenticationError) Error() string {
	if e == nil || e.Err == nil {
		return "authentication failed"
	}
	return e.Err.Error()
}

// Unwrap returns the underlying error for errors.Is/As compatibility.
func (e *AuthenticationError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// LoginInput captures the required context for processing a login attempt.
type LoginInput struct {
	Identifier  string
	Password    string
	DeviceID    string
	DeviceLabel string
	IP          string
	UserAgent   string
}

// LoginResult aggregates artifacts produced by a successful login.
type LoginResult struct {
	AccessToken  string
	RefreshToken string
	User         domain.User
	Roles        []string
	Session      domain.Session
	ExpiresIn    int
}

type refreshTokenParams struct {
	user           domain.User
	sessionID      string
	sessionVersion int64
	familyID       string
	ip             string
	userAgent      string
	metadata       map[string]any
	issuedAt       time.Time
}

// AuthService coordinates authentication flows.
type AuthService struct {
	cfg               *config.AppConfig
	users             port.UserRepository
	roles             port.RoleRepository
	permissions       port.PermissionRepository
	sessions          port.SessionRepository
	tokens            port.TokenRepository
	tokenGenerator    *security.TokenGenerator
	keyProvider       security.KeyProvider
	rateLimits        port.RateLimitStore
	sessionVersions   port.SessionVersionCache
	sessionVersionTTL time.Duration
	logger            *zap.Logger
	now               func() time.Time
	sessionManager    *SessionService
	degradationPolicy domain.DegradationPolicy
}

// NewAuthService constructs an AuthService instance.
func NewAuthService(
	cfg *config.AppConfig,
	users port.UserRepository,
	roles port.RoleRepository,
	permissions port.PermissionRepository,
	sessions port.SessionRepository,
	tokens port.TokenRepository,
	tokenGenerator *security.TokenGenerator,
	keyProvider security.KeyProvider,
	rateLimits port.RateLimitStore,
	logger *zap.Logger,
) (*AuthService, error) {
	if logger == nil {
		logger = zap.NewNop()
	}

	service := &AuthService{
		cfg:               cfg,
		users:             users,
		roles:             roles,
		permissions:       permissions,
		sessions:          sessions,
		tokens:            tokens,
		tokenGenerator:    tokenGenerator,
		keyProvider:       keyProvider,
		rateLimits:        rateLimits,
		logger:            logger,
		degradationPolicy: domain.NewDegradationPolicy(domain.DegradationPolicyModeLenient),
	}
	service.now = func() time.Time { return time.Now().UTC() }
	if cfg != nil {
		service.sessionVersionTTL = cfg.Redis.SessionVersionTTL
		policyMode := domain.ParseDegradationPolicyMode(cfg.Revocation.DegradationPolicy)
		service.degradationPolicy = domain.NewDegradationPolicy(policyMode)
	}
	if service.sessionVersionTTL <= 0 {
		service.sessionVersionTTL = 10 * time.Minute
	}
	return service, nil
}

// WithClock overrides the service clock (primarily for testing).
func (s *AuthService) WithClock(now func() time.Time) *AuthService {
	if now != nil {
		s.now = now
	}
	return s
}

// WithSessionService injects the session management service for coordinated revocation workflows.
func (s *AuthService) WithSessionService(manager *SessionService) *AuthService {
	s.sessionManager = manager
	return s
}

// WithSessionVersionCache wires the session version cache dependencies into the auth service.
func (s *AuthService) WithSessionVersionCache(cache port.SessionVersionCache, ttl time.Duration) *AuthService {
	if cache != nil {
		s.sessionVersions = cache
		if ttl > 0 {
			s.sessionVersionTTL = ttl
		}
		if s.sessionVersionTTL <= 0 {
			s.sessionVersionTTL = 10 * time.Minute
		}
	}
	return s
}

// Login validates credentials, enforces login protections, and returns session context with tokens.
func (s *AuthService) Login(ctx context.Context, input LoginInput) (*LoginResult, error) {
	if err := s.validateLoginInput(input); err != nil {
		return nil, err
	}

	now := s.now()

	if err := s.enforceRateLimits(ctx, input, now); err != nil {
		return nil, err
	}

	user, roles, err := s.authenticateUser(ctx, input.Identifier, input.Password)
	if err != nil {
		if user != nil || len(roles) > 0 {
			return nil, &AuthenticationError{Err: err, User: user, Roles: roles}
		}
		return nil, err
	}

	if s.sessions == nil {
		return nil, fmt.Errorf("session repository not configured")
	}
	if s.tokens == nil {
		return nil, ErrRefreshTokenUnavailable
	}

	session, err := s.createSession(ctx, *user, input, now)
	if err != nil {
		return nil, err
	}

	accessToken, claims, err := s.issueAccessToken(ctx, *user, roles, session.ID, session.Version, now)
	if err != nil {
		s.safeRevokeSession(ctx, session.ID, "access_token_failure")
		return nil, err
	}

	if err := s.trackAccessToken(ctx, claims, user.ID, session.ID); err != nil {
		s.logger.Warn("track jwt jti failed", zap.String("session_id", session.ID), zap.Error(err))
	}

	expiresIn := 0
	if claims != nil && claims.ExpiresAt != nil {
		delta := int(claims.ExpiresAt.Time.Sub(now).Seconds())
		if delta > 0 {
			expiresIn = delta
		}
	}
	if expiresIn <= 0 && s.cfg != nil {
		ttl := s.cfg.JWT.AccessTokenTTL
		if ttl <= 0 {
			ttl = 15 * time.Minute
		}
		expiresIn = int(ttl.Seconds())
	}

	refreshRaw, refreshRecord, err := s.generateRefreshToken(ctx, refreshTokenParams{
		user:           *user,
		sessionID:      session.ID,
		sessionVersion: session.Version,
		familyID:       session.FamilyID,
		ip:             strings.TrimSpace(input.IP),
		userAgent:      strings.TrimSpace(input.UserAgent),
		metadata:       buildLoginMetadata(input),
		issuedAt:       now,
	})
	if err != nil {
		s.safeRevokeSession(ctx, session.ID, "refresh_token_failure")
		return nil, err
	}

	if refreshRecord != nil {
		session.RefreshTokenID = stringPtr(refreshRecord.ID)
	}

	sanitized := sanitizeUser(*user)

	result := &LoginResult{
		AccessToken:  accessToken,
		RefreshToken: refreshRaw,
		User:         sanitized,
		Roles:        roles,
		Session:      session,
		ExpiresIn:    expiresIn,
	}

	return result, nil
}

// Authenticate validates credentials and issues an access token.
func (s *AuthService) Authenticate(ctx context.Context, identifier, password string) (string, domain.User, []string, error) {
	user, roles, err := s.authenticateUser(ctx, identifier, password)
	if err != nil {
		if user != nil {
			return "", *user, roles, err
		}
		return "", domain.User{}, nil, err
	}

	now := s.now()
	token, claims, err := s.issueAccessToken(ctx, *user, roles, "", 0, now)
	if err != nil {
		return "", domain.User{}, nil, err
	}

	if err := s.trackAccessToken(ctx, claims, user.ID, ""); err != nil {
		s.logger.Warn("track access token jti failed", zap.Error(err))
	}

	return token, *user, roles, nil
}

// IssueToken issues a JWT access token for the authenticated user.
func (s *AuthService) IssueToken(ctx context.Context, user domain.User, roles []string) (string, error) {
	if strings.TrimSpace(user.ID) == "" {
		return "", fmt.Errorf("user id is required")
	}

	userCopy := sanitizeUser(user)
	token, claims, err := s.issueAccessToken(ctx, userCopy, roles, "", 0, s.now())
	if err != nil {
		return "", err
	}

	if err := s.trackAccessToken(ctx, claims, userCopy.ID, ""); err != nil {
		s.logger.Warn("track access token jti failed", zap.Error(err))
	}

	return token, nil
}

// ParseAccessToken validates the JWT access token, enforcing session revocation and version checks, and returns its claims.
func (s *AuthService) ParseAccessToken(ctx context.Context, token string) (*security.AccessTokenClaims, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, fmt.Errorf("access token is required")
	}

	claims := &security.AccessTokenClaims{}
	parsed, err := jwt.ParseWithClaims(token, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			s.logger.Error("unexpected signing method", zap.Any("method", t.Header["alg"]))
			return nil, fmt.Errorf("unexpected signing method %v", t.Header["alg"])
		}

		kid, ok := t.Header["kid"].(string)
		if !ok {
			s.logger.Error("kid header not found in token")
			return nil, fmt.Errorf("kid header not found")
		}

		s.logger.Info("attempting to verify token", zap.String("kid", kid))
		key, keyErr := s.keyProvider.GetVerificationKey(kid)
		if keyErr != nil {
			s.logger.Error("failed to get verification key", zap.String("kid", kid), zap.Error(keyErr))
		}
		return key, keyErr
	}, jwt.WithIssuer(s.cfg.App.Name), jwt.WithAudience(s.cfg.App.Name))
	if err != nil {
		s.logger.Error("token validation failed", zap.Error(err))
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrExpiredAccessToken
		}
		return nil, ErrInvalidAccessToken
	}

	if parsed == nil || !parsed.Valid {
		return nil, ErrInvalidAccessToken
	}
	if strings.TrimSpace(claims.UserID) == "" {
		return nil, ErrInvalidAccessToken
	}

	if err := s.validateSessionBinding(ctx, claims); err != nil {
		return nil, err
	}

	return claims, nil
}

func (s *AuthService) validateSessionBinding(ctx context.Context, claims *security.AccessTokenClaims) error {
	if claims == nil {
		return fmt.Errorf("access token claims required")
	}

	sessionID := strings.TrimSpace(claims.SessionID)
	if sessionID == "" {
		return nil
	}

	if s.sessions == nil {
		s.logger.Warn(
			"session repository missing for session-bound token",
			zap.String("session_id", sessionID),
			zap.String("degradation_policy", string(s.degradationPolicy.Mode())),
		)
		if s.degradationPolicy.AllowsFallback(domain.DegradationReasonSessionRepositoryUnavailable) {
			return nil
		}
		return ErrInvalidAccessToken
	}

	currentVersion, err := s.resolveSessionVersionForToken(ctx, sessionID)
	if err != nil {
		switch {
		case errors.Is(err, ErrSessionRevoked):
			s.logger.Warn("rejecting access token for revoked session", zap.String("session_id", sessionID))
			return ErrInvalidAccessToken
		case errors.Is(err, ErrSessionExpired):
			s.logger.Warn("rejecting access token for expired session", zap.String("session_id", sessionID))
			return ErrInvalidAccessToken
		case errors.Is(err, repository.ErrNotFound):
			s.logger.Warn("rejecting access token for missing session", zap.String("session_id", sessionID))
			return ErrInvalidAccessToken
		default:
			return err
		}
	}

	tokenVersion := claims.SessionVersion
	if tokenVersion <= 0 && currentVersion > 0 {
		s.logger.Warn("rejecting access token missing session version", zap.String("session_id", sessionID), zap.Int64("current_version", currentVersion))
		return ErrInvalidAccessToken
	}

	if tokenVersion > 0 && currentVersion > tokenVersion {
		s.logger.Warn("rejecting stale access token", zap.String("session_id", sessionID), zap.Int64("token_version", tokenVersion), zap.Int64("current_version", currentVersion))
		return ErrInvalidAccessToken
	}

	return nil
}

func (s *AuthService) resolveSessionVersionForToken(ctx context.Context, sessionID string) (int64, error) {
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return 0, fmt.Errorf("session id is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	if s.sessions == nil {
		if s.degradationPolicy.AllowsFallback(domain.DegradationReasonSessionRepositoryUnavailable) {
			s.logger.Warn(
				"session repository unavailable; allowing access token validation to proceed",
				zap.String("session_id", sessionID),
				zap.String("degradation_policy", string(s.degradationPolicy.Mode())),
			)
			return 0, nil
		}
		return 0, fmt.Errorf("session repository not configured")
	}

	if s.sessionVersions != nil {
		if cached, err := s.sessionVersions.GetSessionVersion(ctx, sessionID); err == nil {
			if cached > 0 {
				return cached, nil
			}
		} else if !errors.Is(err, repository.ErrNotFound) {
			s.logger.Warn("fetch cached session version failed", zap.String("session_id", sessionID), zap.Error(err))
		}
	}

	session, err := s.sessions.Get(ctx, sessionID)
	if err != nil {
		if !errors.Is(err, repository.ErrNotFound) && s.degradationPolicy.AllowsFallback(domain.DegradationReasonSessionLookupFailure) {
			s.logger.Warn(
				"fetch session failed; allowing due to degradation policy",
				zap.String("session_id", sessionID),
				zap.String("degradation_policy", string(s.degradationPolicy.Mode())),
				zap.Error(err),
			)
			return 0, nil
		}
		return 0, fmt.Errorf("fetch session: %w", err)
	}

	if session.RevokedAt != nil {
		if session.Version > 0 {
			s.cacheSessionVersion(ctx, sessionID, session.Version)
		}
		return session.Version, ErrSessionRevoked
	}

	if s.now().After(session.ExpiresAt) {
		if session.Version > 0 {
			s.cacheSessionVersion(ctx, sessionID, session.Version)
		}
		return session.Version, ErrSessionExpired
	}

	if session.Version > 0 {
		s.cacheSessionVersion(ctx, sessionID, session.Version)
	}

	return session.Version, nil
}

func (s *AuthService) collectRoles(ctx context.Context, userID string) ([]string, error) {
	if s.roles == nil {
		return nil, nil
	}
	assignedRoles, err := s.roles.ListByUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("list user roles: %w", err)
	}
	if len(assignedRoles) == 0 {
		return nil, nil
	}

	result := make([]string, 0, len(assignedRoles))
	for _, role := range assignedRoles {
		if role.Name != "" {
			result = append(result, role.Name)
		}
	}

	return result, nil
}

// ValidateSession returns the session if it is active and not revoked.
func (s *AuthService) ValidateSession(ctx context.Context, sessionID string) (*domain.Session, error) {
	if sessionID == "" {
		return nil, fmt.Errorf("session id is required")
	}
	if s.sessions == nil {
		return nil, fmt.Errorf("session repository not configured")
	}

	session, err := s.sessions.Get(ctx, sessionID)
	if err != nil {
		return nil, fmt.Errorf("fetch session: %w", err)
	}

	if session.RevokedAt != nil {
		return nil, ErrSessionRevoked
	}

	if s.now().After(session.ExpiresAt) {
		return nil, ErrSessionExpired
	}

	return session, nil
}

// ListActiveSessions returns all active sessions for the specified user.
func (s *AuthService) ListActiveSessions(ctx context.Context, userID string) ([]domain.Session, error) {
	if userID == "" {
		return nil, fmt.Errorf("user id is required")
	}
	if s.sessionManager != nil {
		return s.sessionManager.ListSessions(ctx, userID, true)
	}
	if s.sessions == nil {
		return nil, fmt.Errorf("session repository not configured")
	}

	sessions, err := s.sessions.ListByUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("list user sessions: %w", err)
	}

	now := s.now()
	active := make([]domain.Session, 0, len(sessions))
	for _, session := range sessions {
		if session.RevokedAt != nil {
			continue
		}
		if !session.ExpiresAt.After(now) {
			continue
		}
		active = append(active, session)
	}

	return active, nil
}

// RevokeSession revokes a session by identifier with an optional reason.
func (s *AuthService) RevokeSession(ctx context.Context, sessionID, reason string) error {
	if sessionID == "" {
		return fmt.Errorf("session id is required")
	}
	if s.sessionManager != nil {
		_, _, err := s.sessionManager.RevokeByID(ctx, sessionID, reason, "")
		if err != nil {
			switch {
			case errors.Is(err, ErrSessionNotFound):
				return repository.ErrNotFound
			case errors.Is(err, ErrSessionAlreadyRevoked):
				return nil
			default:
				return err
			}
		}
		return nil
	}
	if s.sessions == nil {
		return fmt.Errorf("session repository not configured")
	}

	if reason == "" {
		reason = "user requested"
	}

	if err := s.sessions.Revoke(ctx, sessionID, reason); err != nil {
		return fmt.Errorf("revoke session: %w", err)
	}

	return nil
}

// IssueRefreshToken creates and persists a new refresh token for the supplied user.
func (s *AuthService) IssueRefreshToken(ctx context.Context, user domain.User, metadata map[string]any) (string, *domain.RefreshToken, error) {
	params := refreshTokenParams{
		user:     sanitizeUser(user),
		metadata: metadata,
		issuedAt: s.now(),
	}
	return s.generateRefreshToken(ctx, params)
}

// RefreshAccessToken validates the provided refresh token, rotates it, and issues a new access token.
func (s *AuthService) RefreshAccessToken(ctx context.Context, refreshToken string) (string, string, domain.User, []string, error) {
	refreshToken = strings.TrimSpace(refreshToken)
	if refreshToken == "" {
		return "", "", domain.User{}, nil, fmt.Errorf("refresh token is required")
	}
	if s.tokens == nil {
		return "", "", domain.User{}, nil, ErrRefreshTokenUnavailable
	}

	hash := security.HashToken(refreshToken)
	record, err := s.tokens.GetRefreshTokenByHash(ctx, hash)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return "", "", domain.User{}, nil, ErrInvalidRefreshToken
		}
		return "", "", domain.User{}, nil, fmt.Errorf("lookup refresh token: %w", err)
	}

	now := s.now()

	if record.RevokedAt != nil {
		return "", "", domain.User{}, nil, ErrInvalidRefreshToken
	}
	if record.UsedAt != nil {
		s.handleRefreshReplay(ctx, record)
		return "", "", domain.User{}, nil, ErrRefreshTokenReplay
	}
	if now.After(record.ExpiresAt) {
		return "", "", domain.User{}, nil, ErrExpiredRefreshToken
	}

	user, err := s.users.GetByID(ctx, record.UserID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return "", "", domain.User{}, nil, ErrInvalidRefreshToken
		}
		return "", "", domain.User{}, nil, fmt.Errorf("lookup user: %w", err)
	}

	if !user.IsActive {
		return "", "", domain.User{}, nil, ErrInactiveAccount
	}
	if user.Status == domain.UserStatusPending {
		return "", "", domain.User{}, nil, ErrAccountPending
	}
	if user.Status != domain.UserStatusActive {
		return "", "", domain.User{}, nil, ErrInactiveAccount
	}

	sessionID := ""
	if record.SessionID != nil {
		sessionID = strings.TrimSpace(*record.SessionID)
	}

	var session *domain.Session
	if sessionID != "" && s.sessions != nil {
		sessionRecord, err := s.sessions.Get(ctx, sessionID)
		if err != nil {
			if errors.Is(err, repository.ErrNotFound) {
				return "", "", domain.User{}, nil, ErrInvalidRefreshToken
			}
			return "", "", domain.User{}, nil, fmt.Errorf("lookup session: %w", err)
		}
		session = sessionRecord
		if session.RevokedAt != nil {
			return "", "", domain.User{}, nil, ErrSessionRevoked
		}
		if now.After(session.ExpiresAt) {
			return "", "", domain.User{}, nil, ErrSessionExpired
		}

		s.cacheSessionVersion(ctx, sessionID, session.Version)
		if record.IsStale(session.Version) {
			return "", "", domain.User{}, nil, &SessionVersionMismatchError{
				SessionID:      session.ID,
				TokenVersion:   record.IssuedVersion,
				CurrentVersion: session.Version,
			}
		}
	}

	if err := s.tokens.MarkRefreshTokenUsed(ctx, record.ID, now); err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			s.handleRefreshReplay(ctx, record)
			return "", "", domain.User{}, nil, ErrRefreshTokenReplay
		}
		return "", "", domain.User{}, nil, fmt.Errorf("mark refresh token used: %w", err)
	}

	if err := s.tokens.RevokeRefreshToken(ctx, record.ID); err != nil && !errors.Is(err, repository.ErrNotFound) {
		return "", "", domain.User{}, nil, fmt.Errorf("revoke refresh token: %w", err)
	}

	roles, err := s.collectRoles(ctx, user.ID)
	if err != nil {
		return "", "", domain.User{}, nil, err
	}

	if session != nil {
		if err := s.sessions.UpdateLastSeen(ctx, sessionID, record.IP, record.UserAgent); err != nil && !errors.Is(err, repository.ErrNotFound) {
			s.logger.Warn("update session last seen failed", zap.String("session_id", sessionID), zap.Error(err))
		}
	}

	sanitizedUser := sanitizeUser(*user)

	sessionVersion := int64(0)
	if session != nil {
		bumpMetadata := map[string]any{
			"source": "refresh_rotation",
		}
		if record.ID != "" {
			bumpMetadata["rotated_from"] = record.ID
		}
		if record.FamilyID != "" {
			bumpMetadata["family_id"] = record.FamilyID
		}
		if record.IP != nil && strings.TrimSpace(*record.IP) != "" {
			bumpMetadata["ip"] = strings.TrimSpace(*record.IP)
		}
		if record.UserAgent != nil && strings.TrimSpace(*record.UserAgent) != "" {
			bumpMetadata["user_agent"] = strings.TrimSpace(*record.UserAgent)
		}

		bumpedVersion, bumpErr := s.incrementSessionVersion(ctx, session, "refresh_rotation", bumpMetadata)
		if bumpErr != nil {
			if errors.Is(bumpErr, repository.ErrNotFound) {
				return "", "", domain.User{}, nil, ErrInvalidRefreshToken
			}
			return "", "", domain.User{}, nil, fmt.Errorf("increment session version: %w", bumpErr)
		}
		if bumpedVersion > 0 {
			sessionVersion = bumpedVersion
		} else {
			sessionVersion = session.Version
		}
	}

	accessToken, claims, err := s.issueAccessToken(ctx, sanitizedUser, roles, sessionID, sessionVersion, now)
	if err != nil {
		return "", "", domain.User{}, nil, err
	}

	if err := s.trackAccessToken(ctx, claims, sanitizedUser.ID, sessionID); err != nil {
		s.logger.Warn("track jwt jti failed", zap.String("session_id", sessionID), zap.Error(err))
	}

	metadata := map[string]any{
		"source":       "refresh",
		"rotated_from": record.ID,
	}

	ip := ""
	if record.IP != nil {
		ip = *record.IP
	}
	userAgent := ""
	if record.UserAgent != nil {
		userAgent = *record.UserAgent
	}

	newRefreshToken, _, err := s.generateRefreshToken(ctx, refreshTokenParams{
		user:           sanitizedUser,
		sessionID:      sessionID,
		sessionVersion: sessionVersion,
		familyID:       record.FamilyID,
		ip:             ip,
		userAgent:      userAgent,
		metadata:       metadata,
		issuedAt:       now,
	})
	if err != nil {
		return "", "", domain.User{}, nil, err
	}

	return accessToken, newRefreshToken, sanitizedUser, roles, nil
}

func (s *AuthService) validateLoginInput(input LoginInput) error {
	if strings.TrimSpace(input.Identifier) == "" {
		return fmt.Errorf("identifier is required")
	}
	if strings.TrimSpace(input.Password) == "" {
		return fmt.Errorf("password is required")
	}
	return nil
}

func (s *AuthService) enforceRateLimits(ctx context.Context, input LoginInput, now time.Time) error {
	if s.rateLimits == nil || s.cfg == nil {
		return nil
	}

	limit := s.cfg.RateLimit.LoginMaxAttempts
	if limit <= 0 {
		return nil
	}

	window := s.cfg.RateLimit.WindowDuration
	if window <= 0 {
		window = time.Minute
	}

	candidates := []struct {
		scope string
		key   string
	}{}

	if ip := strings.TrimSpace(input.IP); ip != "" {
		candidates = append(candidates, struct {
			scope string
			key   string
		}{scope: rateLimitScopeIP, key: ip})
	}

	if identifierKey := normalizeIdentifierKey(input.Identifier); identifierKey != "" {
		candidates = append(candidates, struct {
			scope string
			key   string
		}{scope: rateLimitScopeAccount, key: identifierKey})
	}

	for _, candidate := range candidates {
		storageKey := fmt.Sprintf("%s:%s", candidate.scope, candidate.key)

		if err := s.rateLimits.TrimWindow(ctx, storageKey, window, now); err != nil {
			s.logger.Warn("rate limit trim failed", zap.String("scope", candidate.scope), zap.Error(err))
			continue
		}

		count, err := s.rateLimits.CountAttempts(ctx, storageKey, window, now)
		if err != nil {
			s.logger.Warn("rate limit count failed", zap.String("scope", candidate.scope), zap.Error(err))
			continue
		}

		if count >= limit {
			retryAfter := time.Duration(0)
			if oldest, ok, err := s.rateLimits.OldestAttempt(ctx, storageKey, window, now); err == nil && ok {
				reset := oldest.Add(window)
				if reset.After(now) {
					retryAfter = reset.Sub(now)
				}
			} else if err != nil {
				s.logger.Warn("rate limit oldest lookup failed", zap.String("scope", candidate.scope), zap.Error(err))
			}
			return &RateLimitExceededError{Scope: candidate.scope, RetryAfter: retryAfter}
		}

		if err := s.rateLimits.RecordAttempt(ctx, storageKey, now); err != nil {
			s.logger.Warn("rate limit record failed", zap.String("scope", candidate.scope), zap.Error(err))
		}
	}

	return nil
}

func (s *AuthService) authenticateUser(ctx context.Context, identifier, password string) (*domain.User, []string, error) {
	identifier = strings.TrimSpace(identifier)
	if identifier == "" {
		return nil, nil, fmt.Errorf("identifier is required")
	}
	if strings.TrimSpace(password) == "" {
		return nil, nil, fmt.Errorf("password is required")
	}

	user, err := s.users.GetByIdentifier(ctx, identifier)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, nil, ErrInvalidCredentials
		}
		return nil, nil, fmt.Errorf("lookup user: %w", err)
	}

	if !user.IsActive || user.Status == domain.UserStatusDisabled || user.Status == domain.UserStatusLocked {
		return nil, nil, ErrInactiveAccount
	}

	ok, err := security.VerifyPassword(password, user.PasswordHash)
	if err != nil {
		return nil, nil, fmt.Errorf("verify password: %w", err)
	}
	if !ok {
		return nil, nil, ErrInvalidCredentials
	}

	sanitized := sanitizeUser(*user)

	if user.Status == domain.UserStatusPending {
		return &sanitized, nil, ErrAccountPending
	}
	if user.Status != domain.UserStatusActive {
		return nil, nil, ErrInactiveAccount
	}

	roles, err := s.collectRoles(ctx, user.ID)
	if err != nil {
		return nil, nil, err
	}

	return &sanitized, roles, nil
}

func (s *AuthService) issueAccessToken(ctx context.Context, user domain.User, roles []string, sessionID string, sessionVersion int64, issuedAt time.Time) (string, *security.AccessTokenClaims, error) {
	if strings.TrimSpace(user.ID) == "" {
		return "", nil, fmt.Errorf("user id is required")
	}

	now := issuedAt
	if now.IsZero() {
		now = s.now()
	}

	ttl := s.cfg.JWT.AccessTokenTTL
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}

	subject := security.HashToken(user.ID + ":" + s.cfg.App.Name)
	if subject == "" {
		subject = user.ID
	}

	audience := jwt.ClaimStrings{}
	if s.cfg.App.Name != "" {
		audience = append(audience, s.cfg.App.Name)
	}

	jti := uuid.NewString()
	if jti == "" {
		jti = security.HashToken(user.ID + now.String())
	}

	if sessionVersion < 0 {
		sessionVersion = 0
	}

	claims, err := security.NewAccessTokenClaims(security.AccessTokenOptions{
		UserID:         user.ID,
		SessionID:      sessionID,
		SessionVersion: sessionVersion,
		Roles:          roles,
		Issuer:         s.cfg.App.Name,
		Audience:       []string(audience),
		Subject:        subject,
		TTL:            ttl,
		IssuedAt:       now,
		NotBefore:      now,
		JTI:            jti,
	})
	if err != nil {
		return "", nil, fmt.Errorf("build access token claims: %w", err)
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = s.tokenGenerator.GetKID()

	signingKey, err := s.keyProvider.GetSigningKey()
	if err != nil {
		return "", nil, fmt.Errorf("get signing key: %w", err)
	}

	signed, err := token.SignedString(signingKey)
	if err != nil {
		return "", nil, fmt.Errorf("sign token: %w", err)
	}

	return signed, claims, nil
}

func (s *AuthService) trackAccessToken(ctx context.Context, claims *security.AccessTokenClaims, userID, sessionID string) error {
	if s.tokens == nil || claims == nil {
		return nil
	}
	if strings.TrimSpace(claims.ID) == "" {
		return nil
	}

	issuedAt := s.now()
	if claims.IssuedAt != nil {
		issuedAt = claims.IssuedAt.Time
	}
	expiresAt := issuedAt
	if claims.ExpiresAt != nil {
		expiresAt = claims.ExpiresAt.Time
	}

	var sessionPtr *string
	if strings.TrimSpace(sessionID) != "" {
		sessionPtr = stringPtr(sessionID)
	}

	record := domain.AccessTokenJTI{
		JTI:       claims.ID,
		UserID:    userID,
		SessionID: sessionPtr,
		IssuedAt:  issuedAt,
		ExpiresAt: expiresAt,
	}

	return s.tokens.TrackJTI(ctx, record)
}

func (s *AuthService) createSession(ctx context.Context, user domain.User, input LoginInput, now time.Time) (domain.Session, error) {
	session := domain.Session{
		ID:        uuid.NewString(),
		FamilyID:  uuid.NewString(),
		UserID:    user.ID,
		CreatedAt: now,
		LastSeen:  now,
		ExpiresAt: now.Add(s.refreshTTL()),
	}

	if deviceID := strings.TrimSpace(input.DeviceID); deviceID != "" {
		session.DeviceID = stringPtr(deviceID)
	}
	if deviceLabel := strings.TrimSpace(input.DeviceLabel); deviceLabel != "" {
		session.DeviceLabel = stringPtr(deviceLabel)
	}
	if ip := strings.TrimSpace(input.IP); ip != "" {
		session.IPFirst = stringPtr(ip)
		session.IPLast = stringPtr(ip)
	}
	if ua := strings.TrimSpace(input.UserAgent); ua != "" {
		session.UserAgent = stringPtr(ua)
	}

	session.Version = 1

	if err := s.sessions.Create(ctx, session); err != nil {
		return domain.Session{}, fmt.Errorf("create session: %w", err)
	}

	s.cacheSessionVersion(ctx, session.ID, session.Version)

	details := map[string]any{
		"user_id": user.ID,
	}
	if input.DeviceID != "" {
		details["device_id"] = input.DeviceID
	}
	if input.DeviceLabel != "" {
		details["device_label"] = input.DeviceLabel
	}

	s.recordSessionEvent(ctx, session.ID, "login", input.IP, input.UserAgent, details)

	return session, nil
}

func (s *AuthService) recordSessionEvent(ctx context.Context, sessionID, kind, ip, userAgent string, details map[string]any) {
	if s.sessions == nil {
		return
	}

	event := domain.SessionEvent{
		ID:        uuid.NewString(),
		SessionID: sessionID,
		Kind:      kind,
		At:        s.now(),
		Details:   metadataCopy(details),
	}

	if ip = strings.TrimSpace(ip); ip != "" {
		event.IP = stringPtr(ip)
	}
	if ua := strings.TrimSpace(userAgent); ua != "" {
		event.UserAgent = stringPtr(ua)
	}

	if err := s.sessions.StoreEvent(ctx, event); err != nil {
		s.logger.Warn("store session event failed", zap.String("session_id", sessionID), zap.Error(err))
	}
}

func (s *AuthService) refreshTTL() time.Duration {
	if s.cfg == nil {
		return 7 * 24 * time.Hour
	}
	ttl := s.cfg.JWT.RefreshTokenTTL
	if ttl <= 0 {
		ttl = 7 * 24 * time.Hour
	}
	return ttl
}

func (s *AuthService) cacheSessionVersion(ctx context.Context, sessionID string, version int64) {
	if s.sessionVersions == nil {
		return
	}
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" || version <= 0 {
		return
	}
	if s.sessionVersionTTL <= 0 {
		s.sessionVersionTTL = 10 * time.Minute
	}
	if err := s.sessionVersions.SetSessionVersion(ctx, sessionID, version, s.sessionVersionTTL); err != nil {
		s.logger.Warn("cache session version failed", zap.String("session_id", sessionID), zap.Error(err))
	}
}

func (s *AuthService) incrementSessionVersion(ctx context.Context, session *domain.Session, reason string, metadata map[string]any) (int64, error) {
	if session == nil {
		return 0, nil
	}

	sessionID := strings.TrimSpace(session.ID)
	if sessionID == "" {
		return 0, nil
	}

	normalizedReason := strings.TrimSpace(reason)
	if normalizedReason == "" {
		normalizedReason = "session_version_bump"
	}

	if s.sessionManager != nil {
		version, err := s.sessionManager.BumpSessionVersion(ctx, session, normalizedReason, metadata)
		if err != nil {
			return 0, err
		}
		if version > 0 {
			session.Version = version
			s.cacheSessionVersion(ctx, sessionID, version)
		}
		return version, nil
	}

	if s.sessions == nil {
		return 0, fmt.Errorf("session repository not configured")
	}

	version, err := s.sessions.IncrementVersion(ctx, sessionID, normalizedReason)
	if err != nil {
		return 0, err
	}
	if version > 0 && session.Version < version {
		session.Version = version
	}
	s.cacheSessionVersion(ctx, sessionID, version)
	return version, nil
}

func (s *AuthService) generateRefreshToken(ctx context.Context, params refreshTokenParams) (string, *domain.RefreshToken, error) {
	if strings.TrimSpace(params.user.ID) == "" {
		return "", nil, fmt.Errorf("user id is required")
	}
	if s.tokens == nil {
		return "", nil, ErrRefreshTokenUnavailable
	}

	raw, err := security.GenerateSecureToken(32)
	if err != nil {
		return "", nil, fmt.Errorf("generate refresh token: %w", err)
	}

	issuedAt := params.issuedAt
	if issuedAt.IsZero() {
		issuedAt = s.now()
	}

	familyID := strings.TrimSpace(params.familyID)
	if familyID == "" {
		familyID = uuid.NewString()
	}

	sessionVersion := params.sessionVersion
	if sessionVersion < 0 {
		sessionVersion = 0
	}
	if params.sessionID != "" && sessionVersion <= 0 {
		sessionVersion = 1
	}

	record := domain.RefreshToken{
		ID:            uuid.NewString(),
		UserID:        params.user.ID,
		SessionID:     nil,
		TokenHash:     security.HashToken(raw),
		FamilyID:      familyID,
		IssuedVersion: sessionVersion,
		CreatedAt:     issuedAt,
		ExpiresAt:     issuedAt.Add(s.refreshTTL()),
		Metadata:      metadataCopy(params.metadata),
	}

	if params.sessionID != "" {
		record.SessionID = stringPtr(params.sessionID)
	}
	if params.ip != "" {
		record.IP = stringPtr(params.ip)
	}
	if params.userAgent != "" {
		record.UserAgent = stringPtr(params.userAgent)
	}

	if err := s.tokens.CreateRefreshToken(ctx, record); err != nil {
		return "", nil, fmt.Errorf("store refresh token: %w", err)
	}

	return raw, &record, nil
}

func (s *AuthService) safeRevokeSession(ctx context.Context, sessionID, reason string) {
	if sessionID == "" {
		return
	}
	if s.sessionManager != nil {
		if _, _, err := s.sessionManager.RevokeByID(ctx, sessionID, reason, ""); err != nil {
			if !errors.Is(err, ErrSessionNotFound) && !errors.Is(err, ErrSessionAlreadyRevoked) {
				s.logger.Warn("rollback session failed", zap.String("session_id", sessionID), zap.Error(err))
			}
		}
		return
	}
	if s.sessions == nil {
		return
	}
	if err := s.sessions.Revoke(ctx, sessionID, reason); err != nil && !errors.Is(err, repository.ErrNotFound) {
		s.logger.Warn("rollback session failed", zap.String("session_id", sessionID), zap.Error(err))
	}
}

func (s *AuthService) handleRefreshReplay(ctx context.Context, record *domain.RefreshToken) {
	if record == nil {
		return
	}

	reason := "refresh_replay_detected"

	if s.sessions != nil && record.FamilyID != "" {
		if _, err := s.sessions.RevokeByFamily(ctx, record.FamilyID, reason); err != nil && !errors.Is(err, repository.ErrNotFound) {
			s.logger.Warn("revoke family sessions failed", zap.String("family_id", record.FamilyID), zap.Error(err))
		}
	}

	if s.tokens != nil && record.FamilyID != "" {
		if _, err := s.tokens.RevokeRefreshTokensByFamily(ctx, record.FamilyID, reason); err != nil && !errors.Is(err, repository.ErrNotFound) {
			s.logger.Warn("revoke family refresh tokens failed", zap.String("family_id", record.FamilyID), zap.Error(err))
		}
	}
}

func normalizeIdentifierKey(identifier string) string {
	normalized := strings.ToLower(strings.TrimSpace(identifier))
	if normalized == "" {
		return ""
	}
	return security.HashToken(normalized)
}

func sanitizeUser(user domain.User) domain.User {
	user.PasswordHash = ""
	return user
}

func stringPtr(value string) *string {
	v := value
	return &v
}

func metadataCopy(src map[string]any) map[string]any {
	if len(src) == 0 {
		return nil
	}
	dst := make(map[string]any, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func buildLoginMetadata(input LoginInput) map[string]any {
	meta := map[string]any{
		"source": "login",
	}
	if input.DeviceID != "" {
		meta["device_id"] = input.DeviceID
	}
	if input.DeviceLabel != "" {
		meta["device_label"] = input.DeviceLabel
	}
	if input.IP != "" {
		meta["ip"] = input.IP
	}
	if input.UserAgent != "" {
		meta["user_agent"] = input.UserAgent
	}
	return meta
}
