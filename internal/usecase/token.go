package usecase

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"

	"github.com/arklim/social-platform-iam/internal/core/domain"
	"github.com/arklim/social-platform-iam/internal/core/port"
	"github.com/arklim/social-platform-iam/internal/infra/config"
	"github.com/arklim/social-platform-iam/internal/infra/security"
	"github.com/arklim/social-platform-iam/internal/repository"
)

// RevocationStore captures the minimal operations required to cache token revocation state.
type RevocationStore interface {
	MarkRevoked(ctx context.Context, jti string, reason string, ttl time.Duration) error
	IsRevoked(ctx context.Context, jti string) (bool, string, error)
}

// TokenService provides JWT validation, introspection, and revocation orchestration.
type TokenService struct {
	cfg         *config.AppConfig
	keys        security.KeyProvider
	tokens      port.TokenRepository
	sessions    port.SessionRepository
	users       port.UserRepository
	revocations RevocationStore
	logger      *zap.Logger
	now         func() time.Time
}

// NewTokenService constructs a TokenService instance.
func NewTokenService(
	cfg *config.AppConfig,
	keyProvider security.KeyProvider,
	tokens port.TokenRepository,
	sessions port.SessionRepository,
	users port.UserRepository,
	revocations RevocationStore,
	logger *zap.Logger,
) *TokenService {
	if logger == nil {
		logger = zap.NewNop()
	}

	service := &TokenService{
		cfg:         cfg,
		keys:        keyProvider,
		tokens:      tokens,
		sessions:    sessions,
		users:       users,
		revocations: revocations,
		logger:      logger,
	}
	service.now = func() time.Time { return time.Now().UTC() }
	return service
}

// WithClock overrides the service clock for deterministic tests.
func (s *TokenService) WithClock(clock func() time.Time) {
	if clock != nil {
		s.now = clock
	}
}

// ValidateToken performs offline validation of a JWT access token and returns its claims when valid.
func (s *TokenService) ValidateToken(_ context.Context, token string, expectedAudience []string) (*security.AccessTokenClaims, error) {
	return s.parseAccessToken(token, expectedAudience)
}

// TokenIntrospectionResult aggregates token claims with revocation and session status.
type TokenIntrospectionResult struct {
	Claims           *security.AccessTokenClaims
	Active           bool
	Revoked          bool
	RevocationReason string
	UserID           string
	Username         string
	Roles            []string
	JTI              string
	SessionID        string
	IssuedAt         time.Time
	ExpiresAt        time.Time
	NotBefore        time.Time
	Session          *domain.Session
}

// Introspect validates a token and enriches the result with revocation and session state.
func (s *TokenService) Introspect(ctx context.Context, token string, checkRevocation bool, expectedAudience []string) (*TokenIntrospectionResult, error) {
	claims, err := s.parseAccessToken(token, expectedAudience)
	if err != nil {
		return nil, err
	}

	result := &TokenIntrospectionResult{
		Claims:    claims,
		Active:    true,
		UserID:    claims.UserID,
		Roles:     copyRoles(claims.Roles),
		SessionID: strings.TrimSpace(claims.SessionID),
		JTI:       strings.TrimSpace(claims.RegisteredClaims.ID),
	}

	if claims.RegisteredClaims.IssuedAt != nil {
		result.IssuedAt = claims.RegisteredClaims.IssuedAt.Time
	}
	if claims.RegisteredClaims.ExpiresAt != nil {
		result.ExpiresAt = claims.RegisteredClaims.ExpiresAt.Time
	}
	if claims.RegisteredClaims.NotBefore != nil {
		result.NotBefore = claims.RegisteredClaims.NotBefore.Time
	}

	ttl := s.ttlFromClaims(claims)

	if checkRevocation && result.JTI != "" {
		revoked, reason, revErr := s.checkRevocationStatus(ctx, result.JTI, ttl)
		if revErr != nil {
			return nil, revErr
		}
		if revoked {
			result.Revoked = true
			result.Active = false
			result.RevocationReason = reason
		}
	}

	if result.SessionID != "" && s.sessions != nil {
		session, sessErr := s.sessions.Get(ctx, result.SessionID)
		if sessErr != nil {
			if errors.Is(sessErr, repository.ErrNotFound) {
				result.Active = false
			} else {
				return nil, fmt.Errorf("get session: %w", sessErr)
			}
		} else if session != nil {
			copied := *session
			result.Session = &copied

			now := s.now()
			if copied.RevokedAt != nil {
				result.Active = false
				if result.RevocationReason == "" && copied.RevokeReason != nil {
					result.RevocationReason = *copied.RevokeReason
				}
			} else if !copied.ExpiresAt.After(now) {
				result.Active = false
			}
		}
	}

	if s.users != nil {
		user, userErr := s.users.GetByID(ctx, claims.UserID)
		if userErr == nil {
			result.Username = user.Username
		} else if userErr != nil && !errors.Is(userErr, repository.ErrNotFound) {
			return nil, fmt.Errorf("get user: %w", userErr)
		}
	}

	return result, nil
}

// RevokeByJTI revokes a specific access token by its JWT ID.
func (s *TokenService) RevokeByJTI(ctx context.Context, jti, reason string, expiresAt time.Time) (int, error) {
	jti = strings.TrimSpace(jti)
	if jti == "" {
		return 0, fmt.Errorf("jti is required")
	}
	if s.tokens == nil {
		return 0, fmt.Errorf("token repository not configured")
	}

	normalizedReason := normalizeRevocationReason(reason)
	reasonCopy := normalizedReason
	record := domain.RevokedAccessTokenJTI{
		JTI:       jti,
		RevokedAt: s.now(),
		Reason:    &reasonCopy,
	}

	if err := s.tokens.RevokeJTI(ctx, record); err != nil {
		return 0, fmt.Errorf("revoke jti: %w", err)
	}

	ttl := s.resolveTTL(expiresAt)
	s.cacheRevocation(ctx, jti, normalizedReason, ttl)

	return 1, nil
}

// RevokeBySession revokes all active access tokens associated with a session.
func (s *TokenService) RevokeBySession(ctx context.Context, sessionID, reason string) (int, error) {
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return 0, fmt.Errorf("session id is required")
	}
	if s.tokens == nil {
		return 0, fmt.Errorf("token repository not configured")
	}

	normalizedReason := normalizeRevocationReason(reason)
	count, err := s.tokens.RevokeJTIsBySession(ctx, sessionID, normalizedReason)
	if err != nil {
		return 0, fmt.Errorf("revoke jti by session: %w", err)
	}

	return count, nil
}

// RevokeAllForUser revokes every tracked access token for the supplied user.
func (s *TokenService) RevokeAllForUser(ctx context.Context, userID, reason string) (int, error) {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return 0, fmt.Errorf("user id is required")
	}
	if s.tokens == nil {
		return 0, fmt.Errorf("token repository not configured")
	}

	normalizedReason := normalizeRevocationReason(reason)
	count, err := s.tokens.RevokeJTIsForUser(ctx, userID, normalizedReason)
	if err != nil {
		return 0, fmt.Errorf("revoke jti by user: %w", err)
	}

	return count, nil
}

func (s *TokenService) parseAccessToken(token string, expectedAudience []string) (*security.AccessTokenClaims, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, fmt.Errorf("token is required")
	}
	if s.keys == nil {
		return nil, fmt.Errorf("key provider not configured")
	}

	audiences := s.resolveAudience(expectedAudience)
	claims := &security.AccessTokenClaims{}

	parserOptions := []jwt.ParserOption{}
	if s.now != nil {
		parserOptions = append(parserOptions, jwt.WithTimeFunc(s.now))
	}
	if issuer := s.resolveIssuer(); issuer != "" {
		parserOptions = append(parserOptions, jwt.WithIssuer(issuer))
	}
	if len(audiences) > 0 {
		for _, audience := range audiences {
			parserOptions = append(parserOptions, jwt.WithAudience(audience))
		}
	}

	parsed, err := jwt.ParseWithClaims(token, claims, func(t *jwt.Token) (interface{}, error) {
		method, ok := t.Method.(*jwt.SigningMethodRSA)
		if !ok || method == nil {
			return nil, fmt.Errorf("unexpected signing method %v", t.Header["alg"])
		}

		kid, _ := t.Header["kid"].(string)
		kid = strings.TrimSpace(kid)
		if kid == "" {
			return nil, fmt.Errorf("kid header not found")
		}

		return s.keys.GetVerificationKey(kid)
	}, parserOptions...)
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

func (s *TokenService) resolveAudience(expected []string) []string {
	cleaned := make([]string, 0, len(expected))
	for _, aud := range expected {
		aud = strings.TrimSpace(aud)
		if aud != "" {
			cleaned = append(cleaned, aud)
		}
	}
	if len(cleaned) > 0 {
		return cleaned
	}

	if s.cfg != nil {
		if name := strings.TrimSpace(s.cfg.App.Name); name != "" {
			return []string{name}
		}
	}

	return nil
}

func (s *TokenService) resolveIssuer() string {
	if s.cfg == nil {
		return ""
	}
	return strings.TrimSpace(s.cfg.App.Name)
}

func (s *TokenService) ttlFromClaims(claims *security.AccessTokenClaims) time.Duration {
	if claims != nil && claims.RegisteredClaims.ExpiresAt != nil {
		expiresAt := claims.RegisteredClaims.ExpiresAt.Time
		ttl := time.Until(expiresAt)
		if ttl > 0 {
			return ttl
		}
	}
	return s.defaultAccessTokenTTL()
}

func (s *TokenService) resolveTTL(expiresAt time.Time) time.Duration {
	if !expiresAt.IsZero() {
		ttl := time.Until(expiresAt)
		if ttl > 0 {
			return ttl
		}
		return 0
	}
	return s.defaultAccessTokenTTL()
}

func (s *TokenService) defaultAccessTokenTTL() time.Duration {
	if s.cfg != nil && s.cfg.JWT.AccessTokenTTL > 0 {
		return s.cfg.JWT.AccessTokenTTL
	}
	return 15 * time.Minute
}

func (s *TokenService) checkRevocationStatus(ctx context.Context, jti string, ttl time.Duration) (bool, string, error) {
	if s.revocations != nil {
		revoked, reason, err := s.revocations.IsRevoked(ctx, jti)
		if err != nil {
			s.logger.Warn("revocation cache check failed", zap.String("jti", jti), zap.Error(err))
		} else if revoked {
			return true, reason, nil
		}
	}

	if s.tokens == nil {
		return false, "", fmt.Errorf("token repository not configured")
	}

	revoked, err := s.tokens.IsJTIRevoked(ctx, jti)
	if err != nil {
		return false, "", fmt.Errorf("check revoked jti: %w", err)
	}

	if revoked && s.revocations != nil && ttl > 0 {
		s.cacheRevocation(ctx, jti, "", ttl)
	}

	return revoked, "", nil
}

func (s *TokenService) cacheRevocation(ctx context.Context, jti string, reason string, ttl time.Duration) {
	if s.revocations == nil || ttl <= 0 {
		return
	}
	if err := s.revocations.MarkRevoked(ctx, jti, reason, ttl); err != nil {
		s.logger.Warn("cache revoked token failed", zap.String("jti", jti), zap.Error(err))
	}
}

func copyRoles(input []string) []string {
	if len(input) == 0 {
		return nil
	}
	result := make([]string, len(input))
	copy(result, input)
	return result
}
