package redis

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	red "github.com/redis/go-redis/v9"
)

const defaultSessionRevocationPrefix = "sess:revoked"

// SessionRevocationStore persists session revocation flags in Redis for near-real-time checks.
type SessionRevocationStore struct {
	client *red.Client
	prefix string
}

// NewSessionRevocationStore constructs a Redis-backed session revocation cache helper.
func NewSessionRevocationStore(client *red.Client, keyPrefix string) *SessionRevocationStore {
	prefix := strings.TrimSpace(keyPrefix)
	if prefix == "" {
		prefix = defaultSessionRevocationPrefix
	}

	return &SessionRevocationStore{client: client, prefix: prefix}
}

// MarkSessionRevoked stores the session identifier with the supplied reason and TTL window.
func (s *SessionRevocationStore) MarkSessionRevoked(ctx context.Context, sessionID string, reason string, ttl time.Duration) error {
	key := s.key(sessionID)
	if key == "" {
		return fmt.Errorf("session id is required")
	}
	if ttl <= 0 {
		return fmt.Errorf("ttl must be positive")
	}

	value := strings.TrimSpace(reason)
	if value == "" {
		value = "session_revoked"
	}

	if err := s.client.Set(ctx, key, value, ttl).Err(); err != nil {
		return fmt.Errorf("redis set session revocation: %w", err)
	}

	return nil
}

// IsSessionRevoked reports whether a session has been revoked and returns the stored reason when present.
func (s *SessionRevocationStore) IsSessionRevoked(ctx context.Context, sessionID string) (bool, string, error) {
	key := s.key(sessionID)
	if key == "" {
		return false, "", fmt.Errorf("session id is required")
	}

	value, err := s.client.Get(ctx, key).Result()
	if err != nil {
		if errors.Is(err, red.Nil) {
			return false, "", nil
		}
		return false, "", fmt.Errorf("redis get session revocation: %w", err)
	}

	return true, value, nil
}

// ClearSessionRevocation removes the cached revocation entry, typically for tests.
func (s *SessionRevocationStore) ClearSessionRevocation(ctx context.Context, sessionID string) error {
	key := s.key(sessionID)
	if key == "" {
		return fmt.Errorf("session id is required")
	}
	if err := s.client.Del(ctx, key).Err(); err != nil {
		return fmt.Errorf("redis delete session revocation: %w", err)
	}
	return nil
}

func (s *SessionRevocationStore) key(sessionID string) string {
	trimmed := strings.TrimSpace(sessionID)
	if trimmed == "" {
		return ""
	}
	return fmt.Sprintf("%s:%s", s.prefix, trimmed)
}
