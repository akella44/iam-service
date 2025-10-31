package redis

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	red "github.com/redis/go-redis/v9"

	"github.com/arklim/social-platform-iam/internal/repository"
)

const defaultSessionVersionPrefix = "iam:session_version"

// SessionVersionRepository caches session version counters for low-latency checks.
type SessionVersionRepository struct {
	client *red.Client
	prefix string
}

// NewSessionVersionRepository constructs a session version cache helper.
func NewSessionVersionRepository(client *red.Client, keyPrefix string) *SessionVersionRepository {
	prefix := strings.TrimSpace(keyPrefix)
	if prefix == "" {
		prefix = defaultSessionVersionPrefix
	}

	return &SessionVersionRepository{client: client, prefix: prefix}
}

// GetSessionVersion fetches the cached session version, returning ErrNotFound on cache miss.
func (r *SessionVersionRepository) GetSessionVersion(ctx context.Context, sessionID string) (int64, error) {
	key := r.key(sessionID)
	if key == "" {
		return 0, fmt.Errorf("session id is required")
	}

	value, err := r.client.Get(ctx, key).Result()
	if err != nil {
		if errors.Is(err, red.Nil) {
			return 0, repository.ErrNotFound
		}
		return 0, fmt.Errorf("redis get session version: %w", err)
	}

	parsed, parseErr := strconv.ParseInt(value, 10, 64)
	if parseErr != nil {
		return 0, fmt.Errorf("parse cached session version: %w", parseErr)
	}

	return parsed, nil
}

// SetSessionVersion stores the session version with the provided TTL.
func (r *SessionVersionRepository) SetSessionVersion(ctx context.Context, sessionID string, version int64, ttl time.Duration) error {
	key := r.key(sessionID)
	if key == "" {
		return fmt.Errorf("session id is required")
	}
	if version <= 0 {
		return fmt.Errorf("version must be positive")
	}
	if ttl <= 0 {
		return fmt.Errorf("ttl must be positive")
	}

	if err := r.client.Set(ctx, key, strconv.FormatInt(version, 10), ttl).Err(); err != nil {
		return fmt.Errorf("redis set session version: %w", err)
	}
	return nil
}

// DeleteSessionVersion removes the cached session version entry.
func (r *SessionVersionRepository) DeleteSessionVersion(ctx context.Context, sessionID string) error {
	key := r.key(sessionID)
	if key == "" {
		return fmt.Errorf("session id is required")
	}
	if err := r.client.Del(ctx, key).Err(); err != nil {
		return fmt.Errorf("redis delete session version: %w", err)
	}
	return nil
}

func (r *SessionVersionRepository) key(sessionID string) string {
	trimmed := strings.TrimSpace(sessionID)
	if trimmed == "" {
		return ""
	}
	return fmt.Sprintf("%s:%s", r.prefix, trimmed)
}
