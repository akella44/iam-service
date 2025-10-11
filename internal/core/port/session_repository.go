package port

import (
	"context"

	"github.com/arklim/social-platform-iam/internal/core/domain"
)

// SessionRepository deals with session storage.
type SessionRepository interface {
	Create(ctx context.Context, session domain.Session) error
	Touch(ctx context.Context, sessionID string, ip *string, userAgent *string) error
	Revoke(ctx context.Context, sessionID string, reason string) error
	RevokeAllForUser(ctx context.Context, userID string, reason string) (int, error)
	StoreEvent(ctx context.Context, event domain.SessionEvent) error
	RevokeSessionAccessTokens(ctx context.Context, sessionID string, reason string) (int, error)
	GetByID(ctx context.Context, sessionID string) (*domain.Session, error)
	ListActiveByUser(ctx context.Context, userID string) ([]domain.Session, error)
}
