package kafka

import (
	"context"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/arklim/social-platform-iam/internal/core/domain"
)

func TestJTIDenylistConsumerHandleEvent(t *testing.T) {
	ctx := context.Background()
	base := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

	cache := &stubDenylistCache{
		snapshot: &domain.JTIDenylistSnapshot{SnapshotID: "snap-1", Payload: []byte("cache"), GeneratedAt: base},
	}
	store := &stubDenylistSnapshotStore{}
	metrics := &stubDenylistMetrics{}

	consumer := NewJTIDenylistConsumer(cache, store, metrics, zap.NewNop(), JTIDenylistConsumerOptions{SnapshotInterval: time.Second})
	consumer.WithClock(func() time.Time { return base })

	event := domain.TokenRevokedEvent{
		EventID:   "evt-1",
		JTI:       "jti-consumer",
		SubjectID: "subject-1",
		ExpiresAt: base.Add(10 * time.Minute),
		Reason:    "manual",
		Actor:     "admin",
		RevokedAt: base.Add(-250 * time.Millisecond),
	}

	if err := consumer.HandleEvent(ctx, event); err != nil {
		t.Fatalf("HandleEvent returned error: %v", err)
	}

	if len(cache.additions) != 1 {
		t.Fatalf("expected one cache addition, got %d", len(cache.additions))
	}
	if cache.additions[0].JTI != event.JTI {
		t.Fatalf("expected addition for %s, got %s", event.JTI, cache.additions[0].JTI)
	}
	if cache.pruneCalls == 0 {
		t.Fatalf("expected cache prune to be invoked")
	}
	if len(store.saved) != 1 {
		t.Fatalf("expected snapshot to be persisted, got %d", len(store.saved))
	}
	if len(metrics.lags) != 1 {
		t.Fatalf("expected lag metric to be recorded once, got %d", len(metrics.lags))
	}
	if metrics.lags[0] != 250*time.Millisecond {
		t.Fatalf("expected lag of 250ms, got %s", metrics.lags[0])
	}

	// Subsequent event inside the snapshot interval should not persist again.
	consumer.WithClock(func() time.Time { return base.Add(500 * time.Millisecond) })
	if err := consumer.HandleEvent(ctx, event); err != nil {
		t.Fatalf("HandleEvent inside interval returned error: %v", err)
	}
	if len(store.saved) != 1 {
		t.Fatalf("expected snapshot count to remain 1, got %d", len(store.saved))
	}

	// Advance beyond interval to trigger another snapshot.
	consumer.WithClock(func() time.Time { return base.Add(2 * time.Second) })
	if err := consumer.HandleEvent(ctx, event); err != nil {
		t.Fatalf("HandleEvent beyond interval returned error: %v", err)
	}
	if len(store.saved) != 2 {
		t.Fatalf("expected snapshot to be saved twice, got %d", len(store.saved))
	}
}

type stubDenylistCache struct {
	additions  []domain.TokenRevocation
	snapshot   *domain.JTIDenylistSnapshot
	pruneCalls int
}

func (s *stubDenylistCache) AddRevocation(_ context.Context, revocation domain.TokenRevocation) error {
	s.additions = append(s.additions, revocation)
	return nil
}

func (s *stubDenylistCache) Contains(context.Context, string) (bool, error) { return false, nil }

func (s *stubDenylistCache) RestoreSnapshot(context.Context, domain.JTIDenylistSnapshot) error {
	return nil
}

func (s *stubDenylistCache) Snapshot(context.Context) (*domain.JTIDenylistSnapshot, error) {
	return s.snapshot, nil
}

func (s *stubDenylistCache) Prune(context.Context, time.Time) error {
	s.pruneCalls++
	return nil
}

type stubDenylistSnapshotStore struct {
	saved []domain.JTIDenylistSnapshot
}

func (s *stubDenylistSnapshotStore) SaveSnapshot(_ context.Context, snapshot domain.JTIDenylistSnapshot) error {
	s.saved = append(s.saved, snapshot)
	return nil
}

func (s *stubDenylistSnapshotStore) LoadLatestSnapshot(context.Context) (*domain.JTIDenylistSnapshot, error) {
	return nil, nil
}

type stubDenylistMetrics struct {
	lags []time.Duration
}

func (s *stubDenylistMetrics) IncCacheHit()  {}
func (s *stubDenylistMetrics) IncCacheMiss() {}
func (s *stubDenylistMetrics) IncDeny()      {}
func (s *stubDenylistMetrics) ObserveLag(d time.Duration) {
	s.lags = append(s.lags, d)
}
