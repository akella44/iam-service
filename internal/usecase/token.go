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

// TokenValidationStatus enumerates possible validation outcomes for access tokens.
type TokenValidationStatus int

const (
	TokenValidationStatusUnspecified TokenValidationStatus = iota
	TokenValidationStatusActive
	TokenValidationStatusExpired
	TokenValidationStatusRevoked
	TokenValidationStatusStale
	TokenValidationStatusInvalid
)

// TokenValidationResult captures the outcome of token validation workflows.
type TokenValidationResult struct {
	Status         TokenValidationStatus
	Claims         *security.AccessTokenClaims
	SessionID      string
	SessionVersion int64
	TokenVersion   int64
	FamilyID       string
	Reason         string
	RevokedReason  string
	Source         string
}

// TokenService provides token validation and introspection workflows for internal consumers.
type TokenService struct {
	cfg               *config.AppConfig
	sessions          port.SessionRepository
	tokens            port.TokenRepository
	sessionCache      port.SessionVersionCache
	keyProvider       security.KeyProvider
	logger            *zap.Logger
	sessionCacheTTL   time.Duration
	now               func() time.Time
	jtiCache          port.JTIDenylistCache
	jtiMetrics        port.JTIDenylistMetrics
	jtiCacheWarmup    time.Duration
	jtiCacheStaleTTL  time.Duration
	startedAt         time.Time
	degradationPolicy domain.DegradationPolicy
}

// NewTokenService constructs a TokenService instance.
func NewTokenService(cfg *config.AppConfig, sessions port.SessionRepository, tokens port.TokenRepository, sessionCache port.SessionVersionCache, keyProvider security.KeyProvider, logger *zap.Logger) *TokenService {
	if logger == nil {
		logger = zap.NewNop()
	}

	ttl := 10 * time.Minute
	if cfg != nil && cfg.Redis.SessionVersionTTL > 0 {
		ttl = cfg.Redis.SessionVersionTTL
	}

	warmup := 0 * time.Second
	if cfg != nil && cfg.Revocation.Cache.WarmupGracePeriod > 0 {
		warmup = cfg.Revocation.Cache.WarmupGracePeriod
	}
	staleTTL := 30 * time.Second
	if cfg != nil && cfg.Revocation.Cache.StaleTTL > 0 {
		staleTTL = cfg.Revocation.Cache.StaleTTL
	}

	service := &TokenService{
		cfg:               cfg,
		sessions:          sessions,
		tokens:            tokens,
		sessionCache:      sessionCache,
		keyProvider:       keyProvider,
		logger:            logger,
		sessionCacheTTL:   ttl,
		jtiCacheWarmup:    warmup,
		jtiCacheStaleTTL:  staleTTL,
		degradationPolicy: domain.NewDegradationPolicy(domain.DegradationPolicyModeLenient),
	}
	service.now = func() time.Time { return time.Now().UTC() }
	service.startedAt = service.now()
	if cfg != nil {
		policyMode := domain.ParseDegradationPolicyMode(cfg.Revocation.DegradationPolicy)
		service.degradationPolicy = domain.NewDegradationPolicy(policyMode)
	}
	return service
}

// WithClock overrides the internal clock for deterministic testing.
func (s *TokenService) WithClock(clock func() time.Time) *TokenService {
	if clock != nil {
		s.now = clock
		s.startedAt = clock()
	}
	return s
}

// WithJTIDenylist injects the local denylist cache, metrics, and timing thresholds.
func (s *TokenService) WithJTIDenylist(cache port.JTIDenylistCache, metrics port.JTIDenylistMetrics, warmup, staleTTL time.Duration) *TokenService {
	if cache != nil {
		s.jtiCache = cache
	}
	if metrics != nil {
		s.jtiMetrics = metrics
	}
	if warmup >= 0 {
		s.jtiCacheWarmup = warmup
	}
	if staleTTL > 0 {
		s.jtiCacheStaleTTL = staleTTL
	}
	return s
}

// ValidateToken parses and validates an access token, returning contextual metadata for downstream services.
func (s *TokenService) ValidateToken(ctx context.Context, rawToken string) (*TokenValidationResult, error) {
	if s == nil {
		return nil, fmt.Errorf("token service not configured")
	}
	if strings.TrimSpace(rawToken) == "" {
		return nil, fmt.Errorf("access token is required")
	}
	if s.cfg == nil {
		return nil, fmt.Errorf("application configuration missing")
	}
	if s.keyProvider == nil {
		return nil, fmt.Errorf("key provider not configured")
	}

	claims := &security.AccessTokenClaims{}
	parsed, err := jwt.ParseWithClaims(
		rawToken,
		claims,
		func(token *jwt.Token) (interface{}, error) { return s.lookupVerificationKey(token) },
		jwt.WithIssuer(s.cfg.App.Name),
		jwt.WithAudience(s.cfg.App.Name),
	)

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return s.expiredResult(claims, "access token expired"), nil
		}
		s.logger.Warn("access token parse failed", zap.Error(err))
		return &TokenValidationResult{
			Status: TokenValidationStatusInvalid,
			Reason: "invalid access token",
		}, nil
	}

	if parsed == nil || !parsed.Valid {
		return &TokenValidationResult{Status: TokenValidationStatusInvalid, Reason: "invalid access token"}, nil
	}

	userID := strings.TrimSpace(claims.UserID)
	if userID == "" {
		return &TokenValidationResult{Status: TokenValidationStatusInvalid, Reason: "missing user id"}, nil
	}

	result := &TokenValidationResult{
		Status:       TokenValidationStatusActive,
		Claims:       claims,
		SessionID:    strings.TrimSpace(claims.SessionID),
		TokenVersion: claims.SessionVersion,
		Reason:       "token active",
	}

	if claims.ExpiresAt != nil {
		now := s.now()
		if !claims.ExpiresAt.Time.After(now) {
			return s.expiredResult(claims, "access token expired"), nil
		}
		result.Source = fmt.Sprintf("exp:%s", claims.ExpiresAt.Time.UTC().Format(time.RFC3339))
	}

	if status, reason, revokedReason := s.checkJTIRevocation(ctx, claims); status != TokenValidationStatusActive {
		result.Status = status
		result.Reason = reason
		result.RevokedReason = revokedReason
		return result, nil
	}

	if result.SessionID == "" {
		return result, nil
	}

	sessionEval, evalErr := s.evaluateSession(ctx, result.SessionID, claims.SessionVersion)
	if evalErr != nil {
		return nil, evalErr
	}

	result.SessionVersion = sessionEval.currentVersion
	result.FamilyID = sessionEval.familyID
	if sessionEval.status != TokenValidationStatusActive {
		result.Status = sessionEval.status
		result.Reason = sessionEval.reason
		result.RevokedReason = sessionEval.revokedReason
		return result, nil
	}

	if claims.SessionVersion <= 0 && sessionEval.currentVersion > 0 {
		result.Status = TokenValidationStatusInvalid
		result.Reason = "session-bound token missing version"
		return result, nil
	}

	if sessionEval.currentVersion > 0 && sessionEval.currentVersion > claims.SessionVersion {
		result.Status = TokenValidationStatusStale
		result.Reason = "session version mismatch"
		result.RevokedReason = sessionEval.revokedReason
		return result, nil
	}

	return result, nil
}

type sessionEvaluation struct {
	status         TokenValidationStatus
	reason         string
	revokedReason  string
	currentVersion int64
	familyID       string
}

func (s *TokenService) evaluateSession(ctx context.Context, sessionID string, tokenVersion int64) (sessionEvaluation, error) {
	eval := sessionEvaluation{status: TokenValidationStatusActive}

	var cachedVersion int64
	if s.sessionCache != nil {
		cached, err := s.sessionCache.GetSessionVersion(ctx, sessionID)
		if err == nil {
			cachedVersion = cached
		} else if !errors.Is(err, repository.ErrNotFound) {
			s.logger.Warn("fetch cached session version failed", zap.String("session_id", sessionID), zap.Error(err))
		}
	}

	if s.sessions == nil {
		if cachedVersion > 0 {
			eval.currentVersion = cachedVersion
			if cachedVersion > tokenVersion && tokenVersion > 0 {
				eval.status = TokenValidationStatusStale
				eval.reason = "session version mismatch"
			}
		} else if s.degradationPolicy.AllowsFallback(domain.DegradationReasonSessionRepositoryUnavailable) {
			s.logger.Warn(
				"session repository unavailable; allowing token validation due to degradation policy",
				zap.String("session_id", sessionID),
				zap.String("degradation_policy", string(s.degradationPolicy.Mode())),
			)
		} else {
			eval.status = TokenValidationStatusInvalid
			eval.reason = "session repository unavailable"
		}
		return eval, nil
	}

	session, err := s.sessions.Get(ctx, sessionID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			eval.status = TokenValidationStatusRevoked
			eval.reason = "session not found"
			return eval, nil
		}
		if s.degradationPolicy.AllowsFallback(domain.DegradationReasonSessionLookupFailure) {
			s.logger.Warn(
				"fetch session failed; allowing token validation due to degradation policy",
				zap.String("session_id", sessionID),
				zap.String("degradation_policy", string(s.degradationPolicy.Mode())),
				zap.Error(err),
			)
			eval.currentVersion = cachedVersion
			if cachedVersion > 0 && cachedVersion > tokenVersion && tokenVersion > 0 {
				eval.status = TokenValidationStatusStale
				eval.reason = "session version mismatch"
			}
			return eval, nil
		}
		return eval, fmt.Errorf("fetch session: %w", err)
	}

	eval.familyID = session.FamilyID
	eval.currentVersion = session.Version
	if eval.currentVersion <= 0 {
		eval.currentVersion = cachedVersion
	}

	if eval.currentVersion > 0 && s.sessionCache != nil {
		ttl := s.sessionCacheTTL
		if ttl <= 0 {
			ttl = 10 * time.Minute
		}
		if err := s.sessionCache.SetSessionVersion(ctx, sessionID, eval.currentVersion, ttl); err != nil {
			s.logger.Warn("cache session version failed", zap.String("session_id", sessionID), zap.Error(err))
		}
	}

	now := s.now()
	if session.RevokedAt != nil {
		eval.status = TokenValidationStatusRevoked
		eval.reason = "session revoked"
		if session.RevokeReason != nil {
			eval.revokedReason = strings.TrimSpace(*session.RevokeReason)
		} else {
			eval.revokedReason = "session_revoked"
		}
		return eval, nil
	}
	if !session.ExpiresAt.After(now) {
		eval.status = TokenValidationStatusExpired
		eval.reason = "session expired"
		return eval, nil
	}

	if eval.currentVersion > 0 && tokenVersion > 0 && eval.currentVersion > tokenVersion {
		eval.status = TokenValidationStatusStale
		eval.reason = "session version mismatch"
		eval.revokedReason = s.revokeFamily(ctx, session, "session_version_mismatch")
	} else if eval.currentVersion > 0 && tokenVersion <= 0 {
		eval.status = TokenValidationStatusInvalid
		eval.reason = "session-bound token missing version"
	}

	return eval, nil
}

func (s *TokenService) revokeFamily(ctx context.Context, session *domain.Session, reason string) string {
	if session == nil || strings.TrimSpace(session.FamilyID) == "" {
		return ""
	}

	revokeReason := reason
	if revokeReason == "" {
		revokeReason = "session_version_mismatch"
	}

	if s.sessions != nil {
		if _, err := s.sessions.RevokeByFamily(ctx, session.FamilyID, revokeReason); err != nil && !errors.Is(err, repository.ErrNotFound) {
			s.logger.Warn("revoke family sessions failed", zap.String("family_id", session.FamilyID), zap.Error(err))
		}
	}

	if s.tokens != nil {
		if _, err := s.tokens.RevokeRefreshTokensByFamily(ctx, session.FamilyID, revokeReason); err != nil && !errors.Is(err, repository.ErrNotFound) {
			s.logger.Warn("revoke family refresh tokens failed", zap.String("family_id", session.FamilyID), zap.Error(err))
		}
	}

	return revokeReason
}

func (s *TokenService) checkJTIRevocation(ctx context.Context, claims *security.AccessTokenClaims) (TokenValidationStatus, string, string) {
	if s == nil || claims == nil {
		return TokenValidationStatusActive, "", ""
	}

	jti := strings.TrimSpace(claims.ID)
	if jti == "" {
		return TokenValidationStatusActive, "", ""
	}

	now := s.now()
	fallback := false
	fallbackReason := domain.DegradationReasonJTICacheUnavailable

	if s.jtiCache != nil {
		revoked, err := s.jtiCache.Contains(ctx, jti)
		if err != nil {
			s.logger.Warn("jti denylist cache lookup failed", zap.String("jti", jti), zap.Error(err))
			fallback = true
			fallbackReason = domain.DegradationReasonJTICacheUnavailable
		} else if revoked {
			if s.jtiMetrics != nil {
				s.jtiMetrics.IncCacheHit()
				s.jtiMetrics.IncDeny()
			}
			return TokenValidationStatusRevoked, "token revoked", "token_revoked"
		} else {
			if s.jtiMetrics != nil {
				s.jtiMetrics.IncCacheMiss()
			}
			warmupRemaining := s.jtiCacheWarmup - now.Sub(s.startedAt)
			staleElapsed := s.jtiCacheStaleTTL > 0 && now.Sub(s.startedAt) >= s.jtiCacheStaleTTL
			if warmupRemaining > 0 || staleElapsed {
				fallback = true
				fallbackReason = domain.DegradationReasonJTICacheMiss
			}
		}
	} else {
		fallback = true
		fallbackReason = domain.DegradationReasonJTICacheUnavailable
	}

	if !fallback {
		return TokenValidationStatusActive, "", ""
	}

	return s.lookupJTIDenylistAuthority(ctx, jti, fallbackReason)
}

func (s *TokenService) lookupJTIDenylistAuthority(ctx context.Context, jti string, reason domain.DegradationReason) (TokenValidationStatus, string, string) {
	if s.tokens == nil {
		if s.degradationPolicy.AllowsFallback(reason) {
			return TokenValidationStatusActive, "", ""
		}
		return TokenValidationStatusInvalid, "denylist repository unavailable", ""
	}

	revoked, err := s.tokens.IsJTIRevoked(ctx, jti)
	if err != nil {
		s.logger.Warn("check jti revoked failed", zap.String("jti", jti), zap.Error(err))
		if s.degradationPolicy.AllowsFallback(reason) {
			return TokenValidationStatusActive, "", ""
		}
		return TokenValidationStatusInvalid, "denylist lookup failed", ""
	}

	if revoked {
		if s.jtiMetrics != nil {
			s.jtiMetrics.IncDeny()
		}
		return TokenValidationStatusRevoked, "token revoked", "token_revoked"
	}

	return TokenValidationStatusActive, "", ""
}

func (s *TokenService) expiredResult(claims *security.AccessTokenClaims, reason string) *TokenValidationResult {
	result := &TokenValidationResult{
		Status: TokenValidationStatusExpired,
		Claims: claims,
		Reason: reason,
	}
	if claims != nil {
		result.SessionID = strings.TrimSpace(claims.SessionID)
		result.TokenVersion = claims.SessionVersion
	}
	return result
}

func (s *TokenService) lookupVerificationKey(token *jwt.Token) (interface{}, error) {
	if token == nil {
		return nil, fmt.Errorf("jwt: token missing")
	}
	method, ok := token.Method.(*jwt.SigningMethodRSA)
	if !ok || method == nil {
		return nil, fmt.Errorf("jwt: unexpected signing method %v", token.Header["alg"])
	}

	rawKID, ok := token.Header["kid"].(string)
	if !ok || strings.TrimSpace(rawKID) == "" {
		return nil, fmt.Errorf("jwt: kid header not found")
	}

	key, err := s.keyProvider.GetVerificationKey(strings.TrimSpace(rawKID))
	if err != nil {
		return nil, fmt.Errorf("jwt: get verification key: %w", err)
	}
	return key, nil
}
