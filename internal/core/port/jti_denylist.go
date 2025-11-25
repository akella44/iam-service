package port

import (
	"context"
	"time"

	"github.com/arklim/social-platform-iam/internal/core/domain"
)

// JTIDenylistCache exposes in-memory denylist operations backed by sliding windows.
type JTIDenylistCache interface {
	AddRevocation(ctx context.Context, revocation domain.TokenRevocation) error
	Contains(ctx context.Context, jti string) (bool, error)
	RestoreSnapshot(ctx context.Context, snapshot domain.JTIDenylistSnapshot) error
	Snapshot(ctx context.Context) (*domain.JTIDenylistSnapshot, error)
	Prune(ctx context.Context, now time.Time) error
}

// JTIDenylistSnapshotStore persists serialised denylist snapshots for warm starts.
type JTIDenylistSnapshotStore interface {
	SaveSnapshot(ctx context.Context, snapshot domain.JTIDenylistSnapshot) error
	LoadLatestSnapshot(ctx context.Context) (*domain.JTIDenylistSnapshot, error)
}

// JTIDenylistMetrics captures telemetry hooks for denylist lookups.
type JTIDenylistMetrics interface {
	IncCacheHit()
	IncCacheMiss()
	IncDeny()
	ObserveLag(duration time.Duration)
}
