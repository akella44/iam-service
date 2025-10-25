package usecase

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	uuid "github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/arklim/social-platform-iam/internal/core/domain"
	"github.com/arklim/social-platform-iam/internal/core/port"
	"github.com/arklim/social-platform-iam/internal/infra/config"
	"github.com/arklim/social-platform-iam/internal/infra/security"
	"github.com/arklim/social-platform-iam/internal/repository"
)

const (
	resetDeliveryEmail = "email"
	resetDeliveryPhone = "sms"

	defaultResetTTL    = time.Hour
	fallbackCodeLength = 6

	passwordResetRateLimitScope = "password_reset"
	passwordChangeReason        = "password_change"
	passwordResetReason         = "password_reset"
)

var (
	// ErrPasswordResetUnavailable indicates the service is not properly configured.
	ErrPasswordResetUnavailable = errors.New("password reset service unavailable")
	// ErrPasswordResetContactMissing indicates the user has no reachable contact method.
	ErrPasswordResetContactMissing = errors.New("no contact method available for password reset")
	// ErrPasswordResetTokenInvalid indicates the supplied reset token/code is invalid or already used.
	ErrPasswordResetTokenInvalid = errors.New("password reset token invalid")
	// ErrPasswordResetTokenExpired indicates the supplied token/code is expired.
	ErrPasswordResetTokenExpired = errors.New("password reset token expired")
)

// PasswordResetService coordinates password reset initiation and completion.
type PasswordResetService struct {
	cfg               *config.AppConfig
	users             port.UserRepository
	tokens            port.TokenRepository
	rateLimits        port.RateLimitStore
	events            port.EventPublisher
	sessionManager    *SessionService
	passwordValidator *security.PasswordValidator
	passwordPolicy    port.PasswordPolicyValidator
	logger            *zap.Logger
	now               func() time.Time
	resetTTL          time.Duration
	historyLimit      int
}

// PasswordChangeInput captures the context required to update a password for an authenticated user.
type PasswordChangeInput struct {
	UserID          string
	ActorID         string
	CurrentPassword string
	NewPassword     string
	IP              string
	UserAgent       string
}

// PasswordChangeResult summarizes the outcome of a password change operation.
type PasswordChangeResult struct {
	UserID          string
	ChangedAt       time.Time
	SessionsRevoked int
	TokensRevoked   int
}

// PasswordResetRequestInput encapsulates metadata for a password reset request.
type PasswordResetRequestInput struct {
	Identifier string
	IP         string
	UserAgent  string
}

// PasswordResetConfirmInput carries the payload to finalize a password reset.
type PasswordResetConfirmInput struct {
	Token       string
	Code        string
	NewPassword string
	IP          string
	UserAgent   string
}

// PasswordResetConfirmResult describes the outcome of a password reset confirmation.
type PasswordResetConfirmResult struct {
	UserID          string
	ChangedAt       time.Time
	SessionsRevoked int
	TokensRevoked   int
}

type passwordChangeOutcome struct {
	user            domain.User
	changedAt       time.Time
	sessionsRevoked int
	tokensRevoked   int
}

// ResetInitiationResult describes the generated reset artifact returned to the caller.
type ResetInitiationResult struct {
	UserID    string
	RequestID string
	Delivery  string
	Contact   string
	Token     string
	Code      string
	ExpiresAt time.Time
}

// NewPasswordResetService constructs a PasswordResetService.
func NewPasswordResetService(cfg *config.AppConfig, users port.UserRepository, tokens port.TokenRepository, rateLimits port.RateLimitStore, events port.EventPublisher, sessions *SessionService, validator *security.PasswordValidator, policy port.PasswordPolicyValidator, logger *zap.Logger) *PasswordResetService {
	if validator == nil {
		validator = security.DefaultPasswordValidator()
	}
	if policy == nil {
		policy = security.NewPasswordPolicy()
	}
	if logger == nil {
		logger = zap.NewNop()
	}

	return &PasswordResetService{
		cfg:               cfg,
		users:             users,
		tokens:            tokens,
		rateLimits:        rateLimits,
		events:            events,
		sessionManager:    sessions,
		passwordValidator: validator,
		passwordPolicy:    policy,
		logger:            logger,
		now:               time.Now,
		resetTTL:          defaultResetTTL,
		historyLimit:      defaultPasswordHistoryEntries,
	}
}

// WithSessionService injects a session manager after construction (primarily for tests).
func (s *PasswordResetService) WithSessionService(session *SessionService) {
	s.sessionManager = session
}

// WithHistoryLimit adjusts the maximum password history entries considered during validation.
func (s *PasswordResetService) WithHistoryLimit(limit int) {
	if limit >= 0 {
		s.historyLimit = limit
	}
}

// InitiateReset creates a password reset token or code for the provided identifier.
func (s *PasswordResetService) InitiateReset(ctx context.Context, identifier string) (*ResetInitiationResult, error) {
	identifier = strings.TrimSpace(identifier)
	if identifier == "" {
		return nil, fmt.Errorf("identifier is required")
	}
	if s.users == nil || s.tokens == nil {
		return nil, ErrPasswordResetUnavailable
	}

	user, err := s.users.GetByIdentifier(ctx, identifier)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("lookup user: %w", err)
	}

	requestID := uuid.NewString()

	result, err := s.generateResetArtifacts(ctx, user, requestID, nil, nil)
	if err != nil {
		return nil, err
	}

	return result, nil
}

func (s *PasswordResetService) storeResetToken(ctx context.Context, userID string, raw string, expiresAt time.Time, metadata map[string]any, ip, ua *string) error {
	hashed := security.HashToken(raw)
	token := domain.PasswordResetToken{
		ID:        uuid.NewString(),
		UserID:    userID,
		TokenHash: hashed,
		IP:        ip,
		UserAgent: ua,
		CreatedAt: s.now().UTC(),
		ExpiresAt: expiresAt,
		Metadata:  metadata,
	}
	if err := s.tokens.CreatePasswordReset(ctx, token); err != nil {
		return fmt.Errorf("store password reset token: %w", err)
	}
	return nil
}

// CompleteWithToken finalizes a password reset using a raw token (magic link).
func (s *PasswordResetService) CompleteWithToken(ctx context.Context, token, newPassword string) error {
	_, err := s.complete(ctx, token, newPassword, "token", "", "")
	return err
}

// CompleteWithCode finalizes a password reset using a verification code (e.g., SMS).
func (s *PasswordResetService) CompleteWithCode(ctx context.Context, code, newPassword string) error {
	_, err := s.complete(ctx, code, newPassword, "code", "", "")
	return err
}

func (s *PasswordResetService) complete(ctx context.Context, credential, newPassword, method, ip, userAgent string) (*passwordChangeOutcome, error) {
	credential = strings.TrimSpace(credential)
	if credential == "" {
		return nil, fmt.Errorf("reset credential is required")
	}
	newPassword = strings.TrimSpace(newPassword)
	if newPassword == "" {
		return nil, fmt.Errorf("new password is required")
	}
	if s.users == nil || s.tokens == nil {
		return nil, ErrPasswordResetUnavailable
	}

	if err := s.passwordValidator.Validate(newPassword); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNewPasswordInvalid, err)
	}

	hash := security.HashToken(credential)
	token, err := s.tokens.GetPasswordResetByHash(ctx, hash)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, ErrPasswordResetTokenInvalid
		}
		return nil, fmt.Errorf("lookup password reset token: %w", err)
	}

	now := s.now().UTC()
	if token.RevokedAt != nil || token.UsedAt != nil {
		return nil, ErrPasswordResetTokenInvalid
	}
	if now.After(token.ExpiresAt) {
		return nil, ErrPasswordResetTokenExpired
	}

	user, err := s.users.GetByID(ctx, token.UserID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("lookup user: %w", err)
	}

	metadata := metadataCopy(token.Metadata)
	if metadata == nil {
		metadata = make(map[string]any)
	}
	metadata["source"] = passwordResetReason
	metadata["method"] = method
	if token.ID != "" {
		metadata["password_reset_token_id"] = token.ID
	}
	if requestID, ok := metadata["request_id"].(string); ok && requestID != "" {
		metadata["password_reset_request_id"] = requestID
	}
	if trimmed := strings.TrimSpace(ip); trimmed != "" {
		metadata["ip"] = trimmed
	}
	if trimmedUA := strings.TrimSpace(userAgent); trimmedUA != "" {
		metadata["user_agent"] = trimmedUA
	}

	outcome, err := s.applyNewPassword(ctx, *user, newPassword, user.ID, passwordResetReason, metadata)
	if err != nil {
		return nil, err
	}

	if err := s.tokens.ConsumePasswordReset(ctx, token.ID); err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, ErrPasswordResetTokenInvalid
		}
		return nil, fmt.Errorf("consume password reset token: %w", err)
	}

	return outcome, nil
}

// WithClock allows tests to override the clock used by the service.
func (s *PasswordResetService) WithClock(clock func() time.Time) {
	if clock != nil {
		s.now = clock
	}
}

// WithTTL allows tests to override the default reset TTL.
func (s *PasswordResetService) WithTTL(ttl time.Duration) {
	if ttl > 0 {
		s.resetTTL = ttl
	}
}

// ChangePassword updates an authenticated user's password after validating the current credential.
func (s *PasswordResetService) ChangePassword(ctx context.Context, input PasswordChangeInput) (*PasswordChangeResult, error) {
	if s.users == nil || s.tokens == nil {
		return nil, ErrPasswordResetUnavailable
	}

	actorID := strings.TrimSpace(input.ActorID)
	if actorID == "" {
		return nil, fmt.Errorf("actor id is required")
	}

	userID := strings.TrimSpace(input.UserID)
	if userID == "" {
		userID = actorID
	}

	currentPassword := strings.TrimSpace(input.CurrentPassword)
	if currentPassword == "" {
		return nil, ErrCurrentPasswordRequired
	}

	newPassword := strings.TrimSpace(input.NewPassword)
	if newPassword == "" {
		return nil, fmt.Errorf("new password is required")
	}

	user, err := s.users.GetByID(ctx, userID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("lookup user: %w", err)
	}

	matches, err := security.VerifyPassword(currentPassword, user.PasswordHash)
	if err != nil {
		return nil, fmt.Errorf("verify current password: %w", err)
	}
	if !matches {
		return nil, ErrCurrentPasswordInvalid
	}

	metadata := map[string]any{
		"source": passwordChangeReason,
	}
	if trimmed := strings.TrimSpace(input.IP); trimmed != "" {
		metadata["ip"] = trimmed
	}
	if trimmedUA := strings.TrimSpace(input.UserAgent); trimmedUA != "" {
		metadata["user_agent"] = trimmedUA
	}

	outcome, err := s.applyNewPassword(ctx, *user, newPassword, actorID, passwordChangeReason, metadata)
	if err != nil {
		return nil, err
	}

	return &PasswordChangeResult{
		UserID:          outcome.user.ID,
		ChangedAt:       outcome.changedAt,
		SessionsRevoked: outcome.sessionsRevoked,
		TokensRevoked:   outcome.tokensRevoked,
	}, nil
}

// RequestPasswordReset applies rate limiting, persists the reset artifact, and publishes an event for downstream delivery.
func (s *PasswordResetService) RequestPasswordReset(ctx context.Context, input PasswordResetRequestInput) (*ResetInitiationResult, error) {
	if s.users == nil || s.tokens == nil {
		return nil, ErrPasswordResetUnavailable
	}

	identifier := strings.TrimSpace(input.Identifier)
	if identifier == "" {
		return nil, fmt.Errorf("identifier is required")
	}

	now := s.now().UTC()
	if err := s.enforceResetRateLimit(ctx, identifier, now); err != nil {
		return nil, err
	}

	user, err := s.users.GetByIdentifier(ctx, identifier)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("lookup user: %w", err)
	}

	requestID := uuid.NewString()
	ipPtr := stringPtrOrNil(input.IP)
	uaPtr := stringPtrOrNil(input.UserAgent)

	result, err := s.generateResetArtifacts(ctx, user, requestID, ipPtr, uaPtr)
	if err != nil {
		return nil, err
	}

	s.publishResetRequestedEvent(ctx, user, result, input.IP, input.UserAgent)

	return result, nil
}

// ConfirmPasswordReset validates the supplied credential and applies the password change workflow.
func (s *PasswordResetService) ConfirmPasswordReset(ctx context.Context, input PasswordResetConfirmInput) (*PasswordResetConfirmResult, error) {
	credential := strings.TrimSpace(input.Token)
	method := "token"

	if credential == "" {
		credential = strings.TrimSpace(input.Code)
		method = "code"
	}

	if credential == "" {
		return nil, fmt.Errorf("token or code is required")
	}

	outcome, err := s.complete(ctx, credential, input.NewPassword, method, input.IP, input.UserAgent)
	if err != nil {
		return nil, err
	}

	return &PasswordResetConfirmResult{
		UserID:          outcome.user.ID,
		ChangedAt:       outcome.changedAt,
		SessionsRevoked: outcome.sessionsRevoked,
		TokensRevoked:   outcome.tokensRevoked,
	}, nil
}

func (s *PasswordResetService) enforceResetRateLimit(ctx context.Context, identifier string, now time.Time) error {
	if s.rateLimits == nil || s.cfg == nil {
		return nil
	}

	limit := s.cfg.RateLimit.PasswordResetMaxAttempts
	if limit <= 0 {
		return nil
	}

	window := s.cfg.RateLimit.WindowDuration
	if window <= 0 {
		window = time.Hour
	}

	identifierKey := normalizeIdentifierKey(identifier)
	if identifierKey == "" {
		return nil
	}

	storageKey := fmt.Sprintf("%s:%s", passwordResetRateLimitScope, identifierKey)

	if err := s.rateLimits.TrimWindow(ctx, storageKey, window, now); err != nil {
		s.logger.Warn("password reset rate limit trim failed", zap.String("scope", passwordResetRateLimitScope), zap.Error(err))
		return nil
	}

	count, err := s.rateLimits.CountAttempts(ctx, storageKey, window, now)
	if err != nil {
		s.logger.Warn("password reset rate limit count failed", zap.String("scope", passwordResetRateLimitScope), zap.Error(err))
		return nil
	}

	if count >= limit {
		retryAfter := time.Duration(0)
		if oldest, ok, err := s.rateLimits.OldestAttempt(ctx, storageKey, window, now); err == nil && ok {
			reset := oldest.Add(window)
			if reset.After(now) {
				retryAfter = reset.Sub(now)
			}
		} else if err != nil {
			s.logger.Warn("password reset rate limit oldest lookup failed", zap.Error(err))
		}
		return &RateLimitExceededError{Scope: passwordResetRateLimitScope, RetryAfter: retryAfter}
	}

	if err := s.rateLimits.RecordAttempt(ctx, storageKey, now); err != nil {
		s.logger.Warn("password reset rate limit record failed", zap.Error(err))
	}

	return nil
}

func (s *PasswordResetService) generateResetArtifacts(ctx context.Context, user *domain.User, requestID string, ip, ua *string) (*ResetInitiationResult, error) {
	if user == nil {
		return nil, fmt.Errorf("user is required")
	}

	now := s.now().UTC()
	expiresAt := now.Add(s.resetTTL)

	email := strings.TrimSpace(user.Email)
	var phone string
	if user.Phone != nil {
		phone = strings.TrimSpace(*user.Phone)
	}

	result := &ResetInitiationResult{
		UserID:    user.ID,
		RequestID: requestID,
		ExpiresAt: expiresAt,
	}

	metadata := map[string]any{
		"request_id": requestID,
	}

	if ip != nil && *ip != "" {
		metadata["ip"] = strings.TrimSpace(*ip)
	}
	if ua != nil && *ua != "" {
		metadata["user_agent"] = strings.TrimSpace(*ua)
	}

	switch {
	case email != "":
		raw, err := security.GenerateSecureToken(32)
		if err != nil {
			return nil, fmt.Errorf("generate reset token: %w", err)
		}
		metadata["delivery"] = resetDeliveryEmail
		metadata["contact"] = email
		result.Delivery = resetDeliveryEmail
		result.Contact = email
		result.Token = raw
		if err := s.storeResetToken(ctx, user.ID, raw, expiresAt, metadataCopy(metadata), ip, ua); err != nil {
			return nil, err
		}
	case phone != "":
		raw, err := security.GenerateNumericCode(fallbackCodeLength)
		if err != nil {
			return nil, fmt.Errorf("generate reset code: %w", err)
		}
		raw = strings.TrimSpace(raw)
		metadata["delivery"] = resetDeliveryPhone
		metadata["contact"] = phone
		result.Delivery = resetDeliveryPhone
		result.Contact = phone
		result.Code = raw
		if err := s.storeResetToken(ctx, user.ID, raw, expiresAt, metadataCopy(metadata), ip, ua); err != nil {
			return nil, err
		}
	default:
		return nil, ErrPasswordResetContactMissing
	}

	return result, nil
}

func (s *PasswordResetService) applyNewPassword(ctx context.Context, user domain.User, newPassword, changedBy, reason string, metadata map[string]any) (*passwordChangeOutcome, error) {
	trimmed := strings.TrimSpace(newPassword)
	if trimmed == "" {
		return nil, fmt.Errorf("new password is required")
	}

	if err := s.validateNewPassword(trimmed, user); err != nil {
		return nil, err
	}

	history, err := s.users.ListPasswordHistory(ctx, user.ID, s.historyLimit)
	if err != nil && !errors.Is(err, repository.ErrNotFound) {
		return nil, fmt.Errorf("list password history: %w", err)
	}

	for _, entry := range history {
		if reused, verr := security.VerifyPassword(trimmed, entry.PasswordHash); verr != nil {
			return nil, fmt.Errorf("compare password history: %w", verr)
		} else if reused {
			return nil, fmt.Errorf("%w: cannot reuse recent password", ErrNewPasswordInvalid)
		}
	}

	if same, verr := security.VerifyPassword(trimmed, user.PasswordHash); verr != nil {
		return nil, fmt.Errorf("validate new password: %w", verr)
	} else if same {
		return nil, ErrNewPasswordInvalid
	}

	hashedPassword, err := security.HashPassword(trimmed)
	if err != nil {
		return nil, fmt.Errorf("hash new password: %w", err)
	}

	changedAt := s.now().UTC()
	if err := s.users.UpdatePassword(ctx, user.ID, hashedPassword, "argon2id", changedAt); err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("update password: %w", err)
	}

	historyEntry := domain.UserPasswordHistory{
		UserID:       user.ID,
		PasswordHash: hashedPassword,
		SetAt:        changedAt,
	}

	if err := s.users.AddPasswordHistory(ctx, historyEntry); err != nil && !errors.Is(err, repository.ErrNotFound) {
		return nil, fmt.Errorf("store password history: %w", err)
	}

	if s.historyLimit > 0 {
		if err := s.users.TrimPasswordHistory(ctx, user.ID, s.historyLimit); err != nil && !errors.Is(err, repository.ErrNotFound) {
			return nil, fmt.Errorf("trim password history: %w", err)
		}
	}

	if s.tokens != nil {
		if err := s.tokens.RevokeRefreshTokensForUser(ctx, user.ID); err != nil && !errors.Is(err, repository.ErrNotFound) {
			s.logger.Warn("revoke refresh tokens failed", zap.String("user_id", user.ID), zap.Error(err))
		}
		if _, err := s.tokens.RevokeJTIsForUser(ctx, user.ID, reason); err != nil && !errors.Is(err, repository.ErrNotFound) {
			s.logger.Warn("revoke JTIs failed", zap.String("user_id", user.ID), zap.Error(err))
		}
	}

	sessionsRevoked := 0
	tokensRevoked := 0

	if s.sessionManager != nil {
		revoked, tokenCount, err := s.sessionManager.RevokeAllSessions(ctx, user.ID, reason, changedBy)
		if err != nil && !errors.Is(err, ErrSessionNotFound) {
			s.logger.Warn("revoke sessions failed", zap.String("user_id", user.ID), zap.Error(err))
		} else {
			sessionsRevoked = revoked
			tokensRevoked = tokenCount
		}
	}

	updatedUser := user
	updatedUser.LastPasswordChange = changedAt

	s.publishPasswordChangedEvent(ctx, updatedUser, changedBy, changedAt, sessionsRevoked, tokensRevoked, metadata)

	return &passwordChangeOutcome{
		user:            updatedUser,
		changedAt:       changedAt,
		sessionsRevoked: sessionsRevoked,
		tokensRevoked:   tokensRevoked,
	}, nil
}

func (s *PasswordResetService) validateNewPassword(password string, user domain.User) error {
	ctx := domain.PasswordContext{
		Username: strings.TrimSpace(user.Username),
		Email:    strings.TrimSpace(user.Email),
	}
	if user.Phone != nil {
		trimmed := strings.TrimSpace(*user.Phone)
		if trimmed != "" {
			ctx.Phone = &trimmed
		}
	}

	if s.passwordPolicy != nil {
		if err := s.passwordPolicy.Validate(password, ctx); err != nil {
			return fmt.Errorf("%w: %v", ErrNewPasswordInvalid, err)
		}
		return nil
	}

	if err := s.passwordValidator.Validate(password); err != nil {
		return fmt.Errorf("%w: %v", ErrNewPasswordInvalid, err)
	}
	return nil
}

func (s *PasswordResetService) publishPasswordChangedEvent(ctx context.Context, user domain.User, changedBy string, changedAt time.Time, sessionsRevoked, tokensRevoked int, metadata map[string]any) {
	if s.events == nil {
		return
	}

	payload := domain.PasswordChangedEvent{
		EventID:          uuid.NewString(),
		UserID:           user.ID,
		ChangedAt:        changedAt,
		ChangedBy:        strings.TrimSpace(changedBy),
		SessionsRevoked:  sessionsRevoked,
		NotificationSent: false,
		Metadata:         metadataCopy(metadata),
	}

	if payload.Metadata != nil {
		payload.Metadata["tokens_revoked"] = tokensRevoked
	} else if tokensRevoked > 0 {
		payload.Metadata = map[string]any{"tokens_revoked": tokensRevoked}
	}

	if err := s.events.PublishPasswordChanged(ctx, payload); err != nil {
		s.logger.Warn("publish password changed event failed", zap.String("user_id", user.ID), zap.Error(err))
	}
}

func (s *PasswordResetService) publishResetRequestedEvent(ctx context.Context, user *domain.User, result *ResetInitiationResult, ip string, userAgent string) {
	if s.events == nil || user == nil || result == nil {
		return
	}

	masked := maskDestination(result.Delivery, result.Contact)
	metadata := map[string]any{
		"request_id": result.RequestID,
	}
	if ua := strings.TrimSpace(userAgent); ua != "" {
		metadata["user_agent"] = ua
	}

	event := domain.PasswordResetRequestedEvent{
		EventID:           uuid.NewString(),
		UserID:            user.ID,
		RequestID:         result.RequestID,
		RequestedAt:       s.now().UTC(),
		DeliveryMethod:    result.Delivery,
		Destination:       result.Contact,
		MaskedDestination: masked,
		ExpiresAt:         result.ExpiresAt,
		Metadata:          metadataCopy(metadata),
	}

	if trimmed := strings.TrimSpace(ip); trimmed != "" {
		event.IPAddress = stringPtr(trimmed)
	}

	if err := s.events.PublishPasswordResetRequested(ctx, event); err != nil {
		s.logger.Warn("publish password reset requested failed", zap.String("user_id", user.ID), zap.Error(err))
	}
}

func maskDestination(delivery, value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}

	switch delivery {
	case resetDeliveryEmail:
		if idx := strings.Index(trimmed, "@"); idx > 0 {
			local := trimmed[:idx]
			domainPart := trimmed[idx:]
			if len(local) <= 3 {
				return "***" + domainPart
			}
			return local[:3] + "***" + domainPart
		}
		if len(trimmed) <= 3 {
			return "***"
		}
		return trimmed[:3] + "***"
	case resetDeliveryPhone:
		if len(trimmed) > 4 {
			prefix := trimmed
			suffix := ""
			if len(trimmed) > 4 {
				prefix = trimmed[:len(trimmed)-4]
				suffix = trimmed[len(trimmed)-4:]
			}
			return prefix[:min(len(prefix), 4)] + "***" + suffix
		}
		return "***"
	default:
		if len(trimmed) <= 3 {
			return "***"
		}
		return trimmed[:3] + "***"
	}
}

func stringPtrOrNil(value string) *string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil
	}
	return stringPtr(trimmed)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
