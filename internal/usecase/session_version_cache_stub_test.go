package usecase

import (
	"context"
	"time"

	"github.com/arklim/social-platform-iam/internal/repository"
)

type stubSessionVersionCache struct {
	setCalls []struct {
		sessionID string
		version   int64
		ttl       time.Duration
	}
	values   map[string]int64
	getCalls int
}

func (s *stubSessionVersionCache) GetSessionVersion(_ context.Context, sessionID string) (int64, error) {
	if s.values == nil {
		return 0, repository.ErrNotFound
	}
	if value, ok := s.values[sessionID]; ok {
		s.getCalls++
		return value, nil
	}
	return 0, repository.ErrNotFound
}

func (s *stubSessionVersionCache) SetSessionVersion(_ context.Context, sessionID string, version int64, ttl time.Duration) error {
	if s.values == nil {
		s.values = make(map[string]int64)
	}
	s.values[sessionID] = version
	s.setCalls = append(s.setCalls, struct {
		sessionID string
		version   int64
		ttl       time.Duration
	}{sessionID: sessionID, version: version, ttl: ttl})
	return nil
}

func (s *stubSessionVersionCache) DeleteSessionVersion(_ context.Context, sessionID string) error {
	if s.values != nil {
		delete(s.values, sessionID)
	}
	return nil
}
