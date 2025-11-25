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

const defaultSubjectVersionPrefix = "iam:subject_version"

// SubjectVersionCache caches subject version state for low-latency checks.
type SubjectVersionCache struct {
	client *red.Client
	prefix string
}

// NewSubjectVersionCache constructs the subject version cache helper.
func NewSubjectVersionCache(client *red.Client, keyPrefix string) *SubjectVersionCache {
	prefix := strings.TrimSpace(keyPrefix)
	if prefix == "" {
		prefix = defaultSubjectVersionPrefix
	}

	return &SubjectVersionCache{client: client, prefix: prefix}
}

// GetSubjectVersion fetches the cached version and optional not-before timestamp.
func (c *SubjectVersionCache) GetSubjectVersion(ctx context.Context, subjectID string) (int64, *time.Time, error) {
	key := c.key(subjectID)
	if key == "" {
		return 0, nil, fmt.Errorf("subject id is required")
	}

	result, err := c.client.Get(ctx, key).Result()
	if err != nil {
		if errors.Is(err, red.Nil) {
			return 0, nil, repository.ErrNotFound
		}
		return 0, nil, fmt.Errorf("redis get subject version: %w", err)
	}

	parts := strings.SplitN(result, "|", 2)
	version, parseErr := strconv.ParseInt(parts[0], 10, 64)
	if parseErr != nil {
		return 0, nil, fmt.Errorf("parse cached subject version: %w", parseErr)
	}

	var notBeforePtr *time.Time
	if len(parts) == 2 {
		candidate := strings.TrimSpace(parts[1])
		if candidate != "" {
			parsed, parseTimeErr := time.Parse(time.RFC3339Nano, candidate)
			if parseTimeErr != nil {
				return 0, nil, fmt.Errorf("parse cached subject not_before: %w", parseTimeErr)
			}
			parsed = parsed.UTC()
			notBeforePtr = &parsed
		}
	}

	return version, notBeforePtr, nil
}

// SetSubjectVersion stores the subject version and optional not-before timestamp with TTL.
func (c *SubjectVersionCache) SetSubjectVersion(ctx context.Context, subjectID string, version int64, notBefore *time.Time, ttl time.Duration) error {
	key := c.key(subjectID)
	if key == "" {
		return fmt.Errorf("subject id is required")
	}
	if version <= 0 {
		return fmt.Errorf("version must be positive")
	}
	if ttl <= 0 {
		return fmt.Errorf("ttl must be positive")
	}

	payload := strconv.FormatInt(version, 10)
	if notBefore != nil && !notBefore.IsZero() {
		payload = payload + "|" + notBefore.UTC().Format(time.RFC3339Nano)
	}

	if err := c.client.Set(ctx, key, payload, ttl).Err(); err != nil {
		return fmt.Errorf("redis set subject version: %w", err)
	}

	return nil
}

// DeleteSubjectVersion removes the cached subject version entry.
func (c *SubjectVersionCache) DeleteSubjectVersion(ctx context.Context, subjectID string) error {
	key := c.key(subjectID)
	if key == "" {
		return fmt.Errorf("subject id is required")
	}

	if err := c.client.Del(ctx, key).Err(); err != nil {
		return fmt.Errorf("redis delete subject version: %w", err)
	}

	return nil
}

func (c *SubjectVersionCache) key(subjectID string) string {
	subjectID = strings.TrimSpace(subjectID)
	if subjectID == "" {
		return ""
	}
	return fmt.Sprintf("%s:%s", c.prefix, subjectID)
}
