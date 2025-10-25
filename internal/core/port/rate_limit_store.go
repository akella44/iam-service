package port

import (
	"context"
	"time"
)

// RateLimitStore defines the persistence operations required to enforce sliding-window limits.
type RateLimitStore interface {
	TrimWindow(ctx context.Context, identifier string, window time.Duration, reference time.Time) error
	CountAttempts(ctx context.Context, identifier string, window time.Duration, reference time.Time) (int, error)
	RecordAttempt(ctx context.Context, identifier string, at time.Time) error
	OldestAttempt(ctx context.Context, identifier string, window time.Duration, reference time.Time) (time.Time, bool, error)
}
