package port

import (
	"context"
	"time"
)

// SessionRevocationStore caches session revocation flags for rapid access-token checks.
type SessionRevocationStore interface {
	MarkSessionRevoked(ctx context.Context, sessionID string, reason string, ttl time.Duration) error
	IsSessionRevoked(ctx context.Context, sessionID string) (bool, string, error)
	ClearSessionRevocation(ctx context.Context, sessionID string) error
}
