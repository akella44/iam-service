package usecase

import (
	"context"
	"time"

	"github.com/arklim/social-platform-iam/internal/core/domain"
)

type stubJTIDenylistCache struct {
	entries   map[string]bool
	err       error
	pruneErr  error
	snapshot  *domain.JTIDenylistSnapshot
	restored  *domain.JTIDenylistSnapshot
	contains  []string
	additions []domain.TokenRevocation
}

func (s *stubJTIDenylistCache) AddRevocation(_ context.Context, revocation domain.TokenRevocation) error {
	s.additions = append(s.additions, revocation)
	return nil
}

func (s *stubJTIDenylistCache) Contains(_ context.Context, jti string) (bool, error) {
	s.contains = append(s.contains, jti)
	if s.err != nil {
		return false, s.err
	}
	if s.entries == nil {
		return false, nil
	}
	return s.entries[jti], nil
}

func (s *stubJTIDenylistCache) RestoreSnapshot(_ context.Context, snapshot domain.JTIDenylistSnapshot) error {
	s.restored = &snapshot
	return nil
}

func (s *stubJTIDenylistCache) Snapshot(context.Context) (*domain.JTIDenylistSnapshot, error) {
	return s.snapshot, nil
}

func (s *stubJTIDenylistCache) Prune(context.Context, time.Time) error {
	return s.pruneErr
}

type stubJTIDenylistMetrics struct {
	hits   int
	misses int
	denies int
	lags   []time.Duration
}

func (s *stubJTIDenylistMetrics) IncCacheHit() { s.hits++ }

func (s *stubJTIDenylistMetrics) IncCacheMiss() { s.misses++ }

func (s *stubJTIDenylistMetrics) IncDeny() { s.denies++ }

func (s *stubJTIDenylistMetrics) ObserveLag(d time.Duration) { s.lags = append(s.lags, d) }
