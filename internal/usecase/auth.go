package usecase

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	uuid "github.com/google/uuid"

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
	// ErrRefreshTokenUnavailable indicates refresh token issuance is not configured.
	ErrRefreshTokenUnavailable = errors.New("refresh token unavailable")
	// ErrInvalidAccessToken indicates the provided access token is malformed or signature validation failed.
	ErrInvalidAccessToken = errors.New("invalid access token")
	// ErrExpiredAccessToken indicates the provided access token has expired.
	ErrExpiredAccessToken = errors.New("access token expired")
)

// AuthService coordinates authentication flows.
type AuthService struct {
	cfg            *config.AppConfig
	users          port.UserRepository
	roles          port.RoleRepository
	permissions    port.PermissionRepository
	sessions       port.SessionRepository
	tokens         port.TokenRepository
	tokenGenerator *security.TokenGenerator
	keyProvider    security.KeyProvider
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
) (*AuthService, error) {
	return &AuthService{
		cfg:            cfg,
		users:          users,
		roles:          roles,
		permissions:    permissions,
		sessions:       sessions,
		tokens:         tokens,
		tokenGenerator: tokenGenerator,
		keyProvider:    keyProvider,
	}, nil
}

// Authenticate validates credentials and issues an access token.
func (s *AuthService) Authenticate(ctx context.Context, identifier, password string) (string, domain.User, []string, error) {
	if identifier == "" {
		return "", domain.User{}, nil, fmt.Errorf("identifier is required")
	}
	if password == "" {
		return "", domain.User{}, nil, fmt.Errorf("password is required")
	}

	user, err := s.users.GetByIdentifier(ctx, identifier)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return "", domain.User{}, nil, ErrInvalidCredentials
		}
		return "", domain.User{}, nil, fmt.Errorf("lookup user: %w", err)
	}

	if !user.IsActive {
		return "", domain.User{}, nil, ErrInactiveAccount
	}
	if user.Status == domain.UserStatusDisabled || user.Status == domain.UserStatusLocked {
		return "", domain.User{}, nil, ErrInactiveAccount
	}

	ok, err := security.VerifyPassword(password, user.PasswordHash)
	if err != nil {
		return "", domain.User{}, nil, fmt.Errorf("verify password: %w", err)
	}
	if !ok {
		return "", domain.User{}, nil, ErrInvalidCredentials
	}

	if user.Status == domain.UserStatusPending {
		sanitized := *user
		sanitized.PasswordHash = ""
		return "", sanitized, nil, ErrAccountPending
	}

	if user.Status != domain.UserStatusActive {
		return "", domain.User{}, nil, ErrInactiveAccount
	}

	roles, err := s.collectRoles(ctx, user.ID)
	if err != nil {
		return "", domain.User{}, nil, err
	}

	token, err := s.IssueToken(ctx, *user, roles)
	if err != nil {
		return "", domain.User{}, nil, err
	}

	sanitized := *user
	sanitized.PasswordHash = ""

	return token, sanitized, roles, nil
}

// IssueToken issues a JWT access token for the authenticated user.
func (s *AuthService) IssueToken(_ context.Context, user domain.User, roles []string) (string, error) {
	if user.ID == "" {
		return "", fmt.Errorf("user id is required")
	}

	now := time.Now().UTC()
	ttl := s.cfg.JWT.AccessTokenTTL
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}

	subject := security.HashToken(user.ID + ":" + s.cfg.App.Name)
	if subject == "" {
		subject = user.ID
	}

	claimAudience := jwt.ClaimStrings{}
	if s.cfg.App.Name != "" {
		claimAudience = append(claimAudience, s.cfg.App.Name)
	}

	jti := uuid.NewString()
	if jti == "" {
		jti = security.HashToken(user.ID + now.String())
	}

	claims := AccessTokenClaims{
		Roles:  roles,
		UserID: user.ID,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   subject,
			Issuer:    s.cfg.App.Name,
			Audience:  claimAudience,
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			ID:        jti,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	// Use the kid from the token generator
	token.Header["kid"] = s.tokenGenerator.GetKID()

	signingKey, err := s.keyProvider.GetSigningKey()
	if err != nil {
		return "", fmt.Errorf("get signing key: %w", err)
	}

	signed, err := token.SignedString(signingKey)
	if err != nil {
		return "", fmt.Errorf("sign token: %w", err)
	}

	return signed, nil
}

// ParseAccessToken validates the JWT access token and returns its claims.
func (s *AuthService) ParseAccessToken(token string) (*AccessTokenClaims, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, fmt.Errorf("access token is required")
	}

	claims := &AccessTokenClaims{}
	parsed, err := jwt.ParseWithClaims(token, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method %v", t.Header["alg"])
		}

		kid, ok := t.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("kid header not found")
		}

		return s.keyProvider.GetVerificationKey(kid)
	}, jwt.WithIssuer(s.cfg.App.Name), jwt.WithAudience(s.cfg.App.Name))
	if err != nil {
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

	return claims, nil
}

// AccessTokenClaims augments registered claims with RBAC context.
type AccessTokenClaims struct {
	Roles  []string `json:"roles,omitempty"`
	UserID string   `json:"uid"`
	jwt.RegisteredClaims
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

	session, err := s.sessions.GetByID(ctx, sessionID)
	if err != nil {
		return nil, fmt.Errorf("fetch session: %w", err)
	}

	if session.RevokedAt != nil {
		return nil, ErrSessionRevoked
	}

	if time.Now().UTC().After(session.ExpiresAt) {
		return nil, ErrSessionExpired
	}

	return session, nil
}

// ListActiveSessions returns all active sessions for the specified user.
func (s *AuthService) ListActiveSessions(ctx context.Context, userID string) ([]domain.Session, error) {
	if userID == "" {
		return nil, fmt.Errorf("user id is required")
	}
	if s.sessions == nil {
		return nil, fmt.Errorf("session repository not configured")
	}

	sessions, err := s.sessions.ListActiveByUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("list user sessions: %w", err)
	}

	return sessions, nil
}

// RevokeSession revokes a session by identifier with an optional reason.
func (s *AuthService) RevokeSession(ctx context.Context, sessionID, reason string) error {
	if sessionID == "" {
		return fmt.Errorf("session id is required")
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
	if user.ID == "" {
		return "", nil, fmt.Errorf("user id is required")
	}
	if s.tokens == nil {
		return "", nil, ErrRefreshTokenUnavailable
	}

	raw, err := security.GenerateSecureToken(32)
	if err != nil {
		return "", nil, fmt.Errorf("generate refresh token: %w", err)
	}

	meta := metadataCopy(metadata)
	now := time.Now().UTC()
	ttl := s.cfg.JWT.RefreshTokenTTL
	if ttl <= 0 {
		ttl = 7 * 24 * time.Hour
	}

	record := domain.RefreshToken{
		ID:        uuid.NewString(),
		UserID:    user.ID,
		TokenHash: security.HashToken(raw),
		CreatedAt: now,
		ExpiresAt: now.Add(ttl),
		Metadata:  meta,
	}

	if err := s.tokens.CreateRefreshToken(ctx, record); err != nil {
		return "", nil, fmt.Errorf("store refresh token: %w", err)
	}

	return raw, &record, nil
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

	if record.RevokedAt != nil {
		return "", "", domain.User{}, nil, ErrInvalidRefreshToken
	}
	if time.Now().UTC().After(record.ExpiresAt) {
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

	roles, err := s.collectRoles(ctx, user.ID)
	if err != nil {
		return "", "", domain.User{}, nil, err
	}

	accessToken, err := s.IssueToken(ctx, *user, roles)
	if err != nil {
		return "", "", domain.User{}, nil, err
	}

	metadata := map[string]any{
		"source":       "refresh",
		"rotated_from": record.ID,
	}
	newRefreshToken, _, err := s.IssueRefreshToken(ctx, *user, metadata)
	if err != nil {
		return "", "", domain.User{}, nil, err
	}

	if err := s.tokens.RevokeRefreshToken(ctx, record.ID); err != nil && !errors.Is(err, repository.ErrNotFound) {
		return "", "", domain.User{}, nil, fmt.Errorf("revoke refresh token: %w", err)
	}

	sanitized := *user
	sanitized.PasswordHash = ""

	return accessToken, newRefreshToken, sanitized, roles, nil
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
