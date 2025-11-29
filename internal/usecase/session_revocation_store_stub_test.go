package usecase

import (
	"context"
	"time"
)

type stubSessionRevocationStore struct {
	entries map[string]struct {
		revoked bool
		reason  string
	}
	errors struct {
		mark error
		get  error
		clr  error
	}
}

func (s *stubSessionRevocationStore) MarkSessionRevoked(_ context.Context, sessionID string, reason string, _ time.Duration) error {
	if s.errors.mark != nil {
		return s.errors.mark
	}
	if s.entries == nil {
		s.entries = make(map[string]struct {
			revoked bool
			reason  string
		})
	}
	s.entries[sessionID] = struct {
		revoked bool
		reason  string
	}{revoked: true, reason: reason}
	return nil
}

func (s *stubSessionRevocationStore) IsSessionRevoked(_ context.Context, sessionID string) (bool, string, error) {
	if s.errors.get != nil {
		return false, "", s.errors.get
	}
	if s.entries == nil {
		return false, "", nil
	}
	entry, ok := s.entries[sessionID]
	if !ok {
		return false, "", nil
	}
	return entry.revoked, entry.reason, nil
}

func (s *stubSessionRevocationStore) ClearSessionRevocation(_ context.Context, sessionID string) error {
	if s.errors.clr != nil {
		return s.errors.clr
	}
	if s.entries != nil {
		delete(s.entries, sessionID)
	}
	return nil
}
