package security

import (
	"context"
	"testing"
	"time"

	"github.com/arklim/social-platform-iam/internal/core/domain"
)

func TestJTIDenylistCacheContainsAndPrune(t *testing.T) {
	ctx := context.Background()
	base := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	cache := NewJTIDenylistCache(JTIDenylistOptions{WindowDuration: time.Minute, WindowCount: 5})
	cache.WithClock(func() time.Time { return base })

	revocation := domain.TokenRevocation{
		JTI:       "revoked-jti",
		ExpiresAt: base.Add(2 * time.Minute),
	}
	if err := cache.AddRevocation(ctx, revocation); err != nil {
		t.Fatalf("AddRevocation failed: %v", err)
	}

	contains, err := cache.Contains(ctx, "revoked-jti")
	if err != nil {
		t.Fatalf("Contains returned error: %v", err)
	}
	if !contains {
		t.Fatalf("expected jti to be present in denylist")
	}

	// Advance clock beyond expiration and prune.
	cache.WithClock(func() time.Time { return base.Add(3 * time.Minute) })
	if err := cache.Prune(ctx, cache.currentTime()); err != nil {
		t.Fatalf("Prune failed: %v", err)
	}

	contains, err = cache.Contains(ctx, "revoked-jti")
	if err != nil {
		t.Fatalf("Contains returned error after prune: %v", err)
	}
	if contains {
		t.Fatalf("expected jti to be removed after expiry")
	}
}

func TestJTIDenylistSnapshotRoundTrip(t *testing.T) {
	ctx := context.Background()
	base := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	cache := NewJTIDenylistCache(JTIDenylistOptions{WindowDuration: time.Minute, WindowCount: 5})
	cache.WithClock(func() time.Time { return base })

	revocation := domain.TokenRevocation{
		JTI:       "snapshot-jti",
		ExpiresAt: base.Add(5 * time.Minute),
	}
	if err := cache.AddRevocation(ctx, revocation); err != nil {
		t.Fatalf("AddRevocation failed: %v", err)
	}

	snapshot, err := cache.Snapshot(ctx)
	if err != nil {
		t.Fatalf("Snapshot failed: %v", err)
	}
	if snapshot == nil || len(snapshot.Payload) == 0 {
		t.Fatalf("expected snapshot payload to be populated")
	}

	restored := NewJTIDenylistCache(JTIDenylistOptions{WindowDuration: time.Minute, WindowCount: 5})
	if err := restored.RestoreSnapshot(ctx, *snapshot); err != nil {
		t.Fatalf("RestoreSnapshot failed: %v", err)
	}

	restored.WithClock(func() time.Time { return base.Add(2 * time.Minute) })
	contains, err := restored.Contains(ctx, "snapshot-jti")
	if err != nil {
		t.Fatalf("Contains on restored cache returned error: %v", err)
	}
	if !contains {
		t.Fatalf("expected restored cache to contain JTI from snapshot")
	}
}
