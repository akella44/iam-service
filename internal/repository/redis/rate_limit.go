package redis

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/arklim/social-platform-iam/internal/core/port"
)

// SlidingWindowConfig defines configuration for the sliding window limiter.
type SlidingWindowConfig struct {
	KeyPrefix string
	TTL       time.Duration
}

// RateLimitRepository persists rate-limit attempts in Redis sorted sets.
type RateLimitRepository struct {
	client *redis.Client
	cfg    SlidingWindowConfig
}

// NewRateLimitRepository constructs a repository using the provided Redis client and config.
func NewRateLimitRepository(client *redis.Client, cfg SlidingWindowConfig) *RateLimitRepository {
	return &RateLimitRepository{client: client, cfg: cfg}
}

// RecordAttempt stores the provided timestamp within the rate limit window and applies TTL.
func (r *RateLimitRepository) RecordAttempt(ctx context.Context, identifier string, at time.Time) error {
	key := r.key(identifier)
	member := redis.Z{Score: float64(at.UnixNano()), Member: at.UnixNano()}

	if err := r.client.ZAdd(ctx, key, member).Err(); err != nil {
		return fmt.Errorf("redis zadd: %w", err)
	}

	if r.cfg.TTL > 0 {
		if err := r.client.Expire(ctx, key, r.cfg.TTL).Err(); err != nil {
			return fmt.Errorf("redis expire: %w", err)
		}
	}

	return nil
}

// CountAttempts returns how many attempts occurred within the window ending at reference time.
func (r *RateLimitRepository) CountAttempts(ctx context.Context, identifier string, window time.Duration, reference time.Time) (int, error) {
	if window <= 0 {
		return 0, errors.New("window must be positive")
	}

	key := r.key(identifier)
	min := fmt.Sprintf("%f", float64(reference.Add(-window).UnixNano()))
	max := fmt.Sprintf("%f", float64(reference.UnixNano()))

	count, err := r.client.ZCount(ctx, key, min, max).Result()
	if err != nil {
		return 0, fmt.Errorf("redis zcount: %w", err)
	}

	return int(count), nil
}

// TrimWindow removes attempts older than the provided window relative to reference time.
func (r *RateLimitRepository) TrimWindow(ctx context.Context, identifier string, window time.Duration, reference time.Time) error {
	if window <= 0 {
		return errors.New("window must be positive")
	}

	key := r.key(identifier)
	threshold := fmt.Sprintf("%f", float64(reference.Add(-window).UnixNano()))

	if err := r.client.ZRemRangeByScore(ctx, key, "-inf", threshold).Err(); err != nil {
		return fmt.Errorf("redis zremrangebyscore: %w", err)
	}

	return nil
}

// OldestAttempt returns the oldest attempt remaining inside the active window.
func (r *RateLimitRepository) OldestAttempt(ctx context.Context, identifier string, window time.Duration, reference time.Time) (time.Time, bool, error) {
	if window <= 0 {
		return time.Time{}, false, errors.New("window must be positive")
	}

	key := r.key(identifier)
	min := fmt.Sprintf("%f", float64(reference.Add(-window).UnixNano()))
	max := fmt.Sprintf("%f", float64(reference.UnixNano()))

	values, err := r.client.ZRangeByScore(ctx, key, &redis.ZRangeBy{
		Min:    min,
		Max:    max,
		Offset: 0,
		Count:  1,
	}).Result()
	if err != nil {
		return time.Time{}, false, fmt.Errorf("redis zrangebyscore: %w", err)
	}

	if len(values) == 0 {
		return time.Time{}, false, nil
	}

	ts, err := strconv.ParseInt(values[0], 10, 64)
	if err != nil {
		return time.Time{}, false, fmt.Errorf("parse timestamp: %w", err)
	}

	return time.Unix(0, ts), true, nil
}

func (r *RateLimitRepository) key(identifier string) string {
	if r.cfg.KeyPrefix == "" {
		return identifier
	}
	return fmt.Sprintf("%s:%s", r.cfg.KeyPrefix, identifier)
}

var _ port.RateLimitStore = (*RateLimitRepository)(nil)
