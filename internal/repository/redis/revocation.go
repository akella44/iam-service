package redis

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	red "github.com/redis/go-redis/v9"
)

const defaultRevocationPrefix = "revoked"

// RevocationRepository manages access-token JTI revocation state backed by Redis.
type RevocationRepository struct {
	client *red.Client
	prefix string
}

// NewRevocationRepository wires a Redis client into a revocation repository.
func NewRevocationRepository(client *red.Client, keyPrefix string) *RevocationRepository {
	prefix := strings.TrimSpace(keyPrefix)
	if prefix == "" {
		prefix = defaultRevocationPrefix
	}

	return &RevocationRepository{client: client, prefix: prefix}
}

// MarkRevoked stores the supplied JTI with reason and TTL matching the token expiration window.
func (r *RevocationRepository) MarkRevoked(ctx context.Context, jti string, reason string, ttl time.Duration) error {
	if ttl <= 0 {
		return errors.New("ttl must be positive")
	}

	key := r.key(jti)
	if key == "" {
		return errors.New("jti must not be empty")
	}

	if err := r.client.Set(ctx, key, reason, ttl).Err(); err != nil {
		return fmt.Errorf("redis set revoked jti: %w", err)
	}

	return nil
}

// IsRevoked reports whether the JTI has been revoked and returns the stored reason when present.
func (r *RevocationRepository) IsRevoked(ctx context.Context, jti string) (bool, string, error) {
	key := r.key(jti)
	if key == "" {
		return false, "", errors.New("jti must not be empty")
	}

	value, err := r.client.Get(ctx, key).Result()
	if err != nil {
		if errors.Is(err, red.Nil) {
			return false, "", nil
		}
		return false, "", fmt.Errorf("redis get revoked jti: %w", err)
	}

	return true, value, nil
}

func (r *RevocationRepository) key(jti string) string {
	trimmed := strings.TrimSpace(jti)
	if trimmed == "" {
		return ""
	}
	return fmt.Sprintf("%s:%s", r.prefix, trimmed)
}
