package port

import (
	"context"

	"github.com/arklim/social-platform-iam/internal/core/domain"
)

// SessionRepository provides persistence operations for session aggregates.
type SessionRepository interface {
	Create(ctx context.Context, session domain.Session) error
	Get(ctx context.Context, sessionID string) (*domain.Session, error)
	ListByUser(ctx context.Context, userID string) ([]domain.Session, error)
	UpdateLastSeen(ctx context.Context, sessionID string, ip *string, userAgent *string) error
	Revoke(ctx context.Context, sessionID string, reason string) error
	RevokeByFamily(ctx context.Context, familyID string, reason string) (int, error)
	RevokeAllForUser(ctx context.Context, userID string, reason string) (int, error)
	StoreEvent(ctx context.Context, event domain.SessionEvent) error
	RevokeSessionAccessTokens(ctx context.Context, sessionID string, reason string) (int, error)
	GetVersion(ctx context.Context, sessionID string) (int64, error)
	IncrementVersion(ctx context.Context, sessionID string, reason string) (int64, error)
	SetVersion(ctx context.Context, sessionID string, version int64) error
}
