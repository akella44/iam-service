package port

import (
	"context"
	"time"
)

// CacheZMember represents a sorted-set member payload for cache operations.
type CacheZMember struct {
	Member string
	Score  float64
}

// Cache exposes common cache operations leveraged across the service.
type Cache interface {
	Get(ctx context.Context, key string) (string, error)
	Set(ctx context.Context, key string, value string, ttl time.Duration) error
	Delete(ctx context.Context, key string) error
	ZAdd(ctx context.Context, key string, members ...CacheZMember) error
	ZRangeByScore(ctx context.Context, key string, min, max string, limit int64) ([]CacheZMember, error)
}

// SessionVersionCache provides optimized accessors for session version counters.
type SessionVersionCache interface {
	GetSessionVersion(ctx context.Context, sessionID string) (int64, error)
	SetSessionVersion(ctx context.Context, sessionID string, version int64, ttl time.Duration) error
	DeleteSessionVersion(ctx context.Context, sessionID string) error
}
