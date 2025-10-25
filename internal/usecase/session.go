package usecase

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/arklim/social-platform-iam/internal/core/domain"
	"github.com/arklim/social-platform-iam/internal/core/port"
	"github.com/arklim/social-platform-iam/internal/repository"
)

var (
	// ErrSessionNotFound indicates that the requested session does not exist.
	ErrSessionNotFound = errors.New("session not found")
	// ErrSessionForbidden indicates that the session is not owned by the caller.
	ErrSessionForbidden = errors.New("session not owned by user")
	// ErrSessionAlreadyRevoked indicates the session has already been terminated.
	ErrSessionAlreadyRevoked = errors.New("session already revoked")
)

// SessionService coordinates session listing and revocation workflows.
type SessionService struct {
	sessions port.SessionRepository
	tokens   port.TokenRepository
	events   port.EventPublisher
	logger   *zap.Logger
	now      func() time.Time
}

// NewSessionService constructs a SessionService.
func NewSessionService(sessions port.SessionRepository, tokens port.TokenRepository, events port.EventPublisher, logger *zap.Logger) *SessionService {
	if logger == nil {
		logger = zap.NewNop()
	}
	service := &SessionService{
		sessions: sessions,
		tokens:   tokens,
		events:   events,
		logger:   logger,
	}
	service.now = func() time.Time { return time.Now().UTC() }
	return service
}

// WithClock overrides the internal clock for deterministic tests.
func (s *SessionService) WithClock(clock func() time.Time) {
	if clock != nil {
		s.now = clock
	}
}

// ListSessions returns sessions owned by the supplied user. When activeOnly is true, revoked and expired sessions are filtered out.
func (s *SessionService) ListSessions(ctx context.Context, userID string, activeOnly bool) ([]domain.Session, error) {
	if strings.TrimSpace(userID) == "" {
		return nil, fmt.Errorf("user id is required")
	}
	if s.sessions == nil {
		return nil, fmt.Errorf("session repository not configured")
	}

	sessions, err := s.sessions.ListByUser(ctx, userID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, ErrSessionNotFound
		}
		return nil, fmt.Errorf("list sessions: %w", err)
	}

	if !activeOnly {
		return sessions, nil
	}

	now := s.now()
	active := make([]domain.Session, 0, len(sessions))
	for _, session := range sessions {
		if !session.IsActive(now) {
			continue
		}
		active = append(active, session)
	}

	return active, nil
}

// GetSession fetches a session and ensures it belongs to the supplied user.
func (s *SessionService) GetSession(ctx context.Context, userID, sessionID string) (*domain.Session, error) {
	if s.sessions == nil {
		return nil, fmt.Errorf("session repository not configured")
	}
	if strings.TrimSpace(sessionID) == "" {
		return nil, fmt.Errorf("session id is required")
	}

	session, err := s.fetchSession(ctx, sessionID)
	if err != nil {
		return nil, err
	}

	if userID != "" && !strings.EqualFold(session.UserID, userID) {
		return nil, ErrSessionForbidden
	}

	return session, nil
}

// RevokeSession terminates a specific session owned by the user.
func (s *SessionService) RevokeSession(ctx context.Context, userID, sessionID, reason, revokedBy string) (*domain.Session, int, error) {
	session, err := s.GetSession(ctx, userID, sessionID)
	if err != nil {
		return nil, 0, err
	}

	return s.revoke(ctx, session, reason, revokedBy)
}

// RevokeByID terminates the session without enforcing ownership checks.
func (s *SessionService) RevokeByID(ctx context.Context, sessionID, reason, revokedBy string) (*domain.Session, int, error) {
	session, err := s.fetchSession(ctx, sessionID)
	if err != nil {
		return nil, 0, err
	}

	return s.revoke(ctx, session, reason, revokedBy)
}

// RevokeAllSessions terminates every active session for the user.
func (s *SessionService) RevokeAllSessions(ctx context.Context, userID, reason, revokedBy string) (int, int, error) {
	if strings.TrimSpace(userID) == "" {
		return 0, 0, fmt.Errorf("user id is required")
	}
	if s.sessions == nil {
		return 0, 0, fmt.Errorf("session repository not configured")
	}

	sessions, err := s.sessions.ListByUser(ctx, userID)
	if err != nil {
		return 0, 0, fmt.Errorf("list sessions: %w", err)
	}

	revokedCount := 0
	tokensRevoked := 0
	now := s.now()
	for i := range sessions {
		session := &sessions[i]
		if !session.IsActive(now) {
			continue
		}
		_, tokenCount, err := s.revoke(ctx, session, reason, revokedBy)
		if err != nil {
			if errors.Is(err, ErrSessionAlreadyRevoked) {
				continue
			}
			s.logger.Warn("revoke session failed", zap.String("session_id", session.ID), zap.Error(err))
			continue
		}
		revokedCount++
		tokensRevoked += tokenCount
	}

	return revokedCount, tokensRevoked, nil
}

// RevokeAllExceptCurrent terminates every active session except the supplied current session.
func (s *SessionService) RevokeAllExceptCurrent(ctx context.Context, userID, currentSessionID, reason, revokedBy string) (int, int, error) {
	if strings.TrimSpace(currentSessionID) == "" {
		return 0, 0, fmt.Errorf("current session id is required")
	}

	sessions, err := s.sessions.ListByUser(ctx, userID)
	if err != nil {
		return 0, 0, fmt.Errorf("list sessions: %w", err)
	}

	foundCurrent := false
	revokedCount := 0
	tokensRevoked := 0
	now := s.now()

	for i := range sessions {
		session := &sessions[i]
		if session.ID == currentSessionID {
			foundCurrent = true
			continue
		}
		if !session.IsActive(now) {
			continue
		}
		_, tokenCount, err := s.revoke(ctx, session, reason, revokedBy)
		if err != nil {
			if errors.Is(err, ErrSessionAlreadyRevoked) {
				continue
			}
			s.logger.Warn("revoke other session failed", zap.String("session_id", session.ID), zap.Error(err))
			continue
		}
		revokedCount++
		tokensRevoked += tokenCount
	}

	if !foundCurrent {
		return revokedCount, tokensRevoked, ErrSessionNotFound
	}

	return revokedCount, tokensRevoked, nil
}

func (s *SessionService) fetchSession(ctx context.Context, sessionID string) (*domain.Session, error) {
	if s.sessions == nil {
		return nil, fmt.Errorf("session repository not configured")
	}

	session, err := s.sessions.Get(ctx, sessionID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, ErrSessionNotFound
		}
		return nil, fmt.Errorf("get session: %w", err)
	}

	return session, nil
}

func (s *SessionService) revoke(ctx context.Context, session *domain.Session, reason, revokedBy string) (*domain.Session, int, error) {
	if session == nil {
		return nil, 0, ErrSessionNotFound
	}
	if session.RevokedAt != nil {
		return session, 0, ErrSessionAlreadyRevoked
	}

	reason = normalizeRevocationReason(reason)
	revoker := strings.TrimSpace(revokedBy)
	if revoker == "" {
		revoker = session.UserID
	}

	if err := s.sessions.Revoke(ctx, session.ID, reason); err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, 0, ErrSessionNotFound
		}
		return nil, 0, fmt.Errorf("revoke session: %w", err)
	}

	updated, err := s.sessions.Get(ctx, session.ID)
	if err != nil {
		s.logger.Warn("reload session after revoke failed", zap.String("session_id", session.ID), zap.Error(err))
		updated = session
	}

	tokensRevoked := 0
	if s.sessions != nil {
		if count, err := s.sessions.RevokeSessionAccessTokens(ctx, session.ID, reason); err != nil {
			if !errors.Is(err, repository.ErrNotFound) {
				s.logger.Warn("revoke session access tokens failed", zap.String("session_id", session.ID), zap.Error(err))
			}
		} else {
			tokensRevoked = count
		}
	}

	if err := s.recordRevocation(ctx, updated, revoker, reason, tokensRevoked); err != nil {
		s.logger.Warn("record session revocation failed", zap.String("session_id", session.ID), zap.Error(err))
	}

	return updated, tokensRevoked, nil
}

func (s *SessionService) recordRevocation(ctx context.Context, session *domain.Session, revokedBy, reason string, tokensRevoked int) error {
	if session == nil {
		return nil
	}

	revokedAt := s.now()
	if session.RevokedAt != nil {
		revokedAt = session.RevokedAt.UTC()
	}

	details := map[string]any{
		"reason":     reason,
		"revoked_by": revokedBy,
	}
	if tokensRevoked > 0 {
		details["tokens_revoked"] = tokensRevoked
	}
	if session.FamilyID != "" {
		details["family_id"] = session.FamilyID
	}
	if session.DeviceID != nil && strings.TrimSpace(*session.DeviceID) != "" {
		details["device_id"] = strings.TrimSpace(*session.DeviceID)
	}
	if session.DeviceLabel != nil && strings.TrimSpace(*session.DeviceLabel) != "" {
		details["device_label"] = strings.TrimSpace(*session.DeviceLabel)
	}

	event := domain.SessionEvent{
		ID:        uuid.NewString(),
		SessionID: session.ID,
		Kind:      "session.revoked",
		At:        revokedAt,
		IP:        session.IPLast,
		UserAgent: session.UserAgent,
		Details:   details,
	}

	if err := s.sessions.StoreEvent(ctx, event); err != nil {
		return fmt.Errorf("store session event: %w", err)
	}

	if s.events != nil {
		metadata := map[string]any{}
		if session.FamilyID != "" {
			metadata["family_id"] = session.FamilyID
		}
		if session.DeviceID != nil && strings.TrimSpace(*session.DeviceID) != "" {
			metadata["device_id"] = strings.TrimSpace(*session.DeviceID)
		}
		if tokensRevoked > 0 {
			metadata["tokens_revoked"] = tokensRevoked
		}
		if len(metadata) == 0 {
			metadata = nil
		}
		publish := domain.SessionRevokedEvent{
			EventID:       uuid.NewString(),
			SessionID:     session.ID,
			UserID:        session.UserID,
			DeviceLabel:   session.DeviceLabel,
			RevokedAt:     revokedAt,
			RevokedBy:     revokedBy,
			Reason:        reason,
			TokensRevoked: tokensRevoked,
			IPAddress:     session.IPLast,
			Metadata:      metadata,
		}
		if err := s.events.PublishSessionRevoked(ctx, publish); err != nil {
			return fmt.Errorf("publish session revoked: %w", err)
		}
	}

	return nil
}

func normalizeRevocationReason(reason string) string {
	trimmed := strings.TrimSpace(strings.ToLower(reason))
	if trimmed == "" {
		return "user_action"
	}
	return strings.ReplaceAll(trimmed, " ", "_")
}
