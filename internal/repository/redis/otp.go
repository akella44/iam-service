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

const (
	defaultOTPPrefix = "otp"

	fieldCode      = "code"
	fieldCreatedAt = "created_at"
	fieldExpiresAt = "expires_at"
	fieldAttempts  = "attempts"
)

// OTPRecord represents a stored development OTP entry.
type OTPRecord struct {
	Purpose    string
	Identifier string
	Code       string
	Attempts   int
	CreatedAt  time.Time
	ExpiresAt  time.Time
}

// OTPRepository persists temporary OTP codes in Redis for development flows.
type OTPRepository struct {
	client *red.Client
	prefix string
	now    func() time.Time
}

// NewOTPRepository constructs a new OTP repository with the provided Redis client and key prefix.
func NewOTPRepository(client *red.Client, keyPrefix string) *OTPRepository {
	prefix := strings.TrimSpace(keyPrefix)
	if prefix == "" {
		prefix = defaultOTPPrefix
	}

	return &OTPRepository{
		client: client,
		prefix: prefix,
		now:    time.Now,
	}
}

// Store persists an OTP value with the supplied purpose/identifier and TTL.
func (r *OTPRepository) Store(ctx context.Context, purpose, identifier, code string, ttl time.Duration) (*OTPRecord, error) {
	purpose = strings.TrimSpace(purpose)
	identifier = strings.TrimSpace(identifier)
	code = strings.TrimSpace(code)

	switch {
	case purpose == "":
		return nil, errors.New("purpose is required")
	case identifier == "":
		return nil, errors.New("identifier is required")
	case code == "":
		return nil, errors.New("code is required")
	case ttl <= 0:
		return nil, errors.New("ttl must be positive")
	}

	now := r.now().UTC()
	expiresAt := now.Add(ttl)

	key := r.key(purpose, identifier)

	pipe := r.client.TxPipeline()
	pipe.HSet(ctx, key, map[string]any{
		fieldCode:      code,
		fieldCreatedAt: strconv.FormatInt(now.Unix(), 10),
		fieldExpiresAt: strconv.FormatInt(expiresAt.Unix(), 10),
		fieldAttempts:  "0",
	})
	pipe.Expire(ctx, key, ttl)

	if _, err := pipe.Exec(ctx); err != nil {
		return nil, fmt.Errorf("redis store otp: %w", err)
	}

	return &OTPRecord{
		Purpose:    purpose,
		Identifier: identifier,
		Code:       code,
		Attempts:   0,
		CreatedAt:  now,
		ExpiresAt:  expiresAt,
	}, nil
}

// Fetch retrieves the OTP record for the provided purpose and identifier.
func (r *OTPRepository) Fetch(ctx context.Context, purpose, identifier string) (*OTPRecord, error) {
	key := r.key(strings.TrimSpace(purpose), strings.TrimSpace(identifier))
	if key == "" {
		return nil, errors.New("purpose and identifier are required")
	}

	values, err := r.client.HGetAll(ctx, key).Result()
	if err != nil {
		return nil, fmt.Errorf("redis hgetall otp: %w", err)
	}
	if len(values) == 0 {
		return nil, repository.ErrNotFound
	}

	code := strings.TrimSpace(values[fieldCode])
	if code == "" {
		return nil, repository.ErrNotFound
	}

	createdAt, err := parseUnix(values[fieldCreatedAt])
	if err != nil {
		return nil, fmt.Errorf("parse created_at: %w", err)
	}

	expiresAt, err := parseUnix(values[fieldExpiresAt])
	if err != nil {
		return nil, fmt.Errorf("parse expires_at: %w", err)
	}

	attempts := 0
	if raw := values[fieldAttempts]; raw != "" {
		if v, convErr := strconv.Atoi(raw); convErr == nil {
			attempts = v
		}
	}

	parts := strings.SplitN(key, ":", 3)
	purposeVal, identifierVal := strings.TrimSpace(purpose), strings.TrimSpace(identifier)
	if len(parts) == 3 {
		purposeVal = parts[1]
		identifierVal = parts[2]
	}

	return &OTPRecord{
		Purpose:    purposeVal,
		Identifier: identifierVal,
		Code:       code,
		Attempts:   attempts,
		CreatedAt:  createdAt,
		ExpiresAt:  expiresAt,
	}, nil
}

// IncrementAttempts increments the attempt counter for the OTP and returns the new value.
func (r *OTPRepository) IncrementAttempts(ctx context.Context, purpose, identifier string) (int, error) {
	if _, err := r.Fetch(ctx, purpose, identifier); err != nil {
		return 0, err
	}

	key := r.key(strings.TrimSpace(purpose), strings.TrimSpace(identifier))
	count, err := r.client.HIncrBy(ctx, key, fieldAttempts, 1).Result()
	if err != nil {
		return 0, fmt.Errorf("redis hincrby otp attempts: %w", err)
	}

	return int(count), nil
}

// Delete removes the OTP entry, enforcing single-use semantics.
func (r *OTPRepository) Delete(ctx context.Context, purpose, identifier string) error {
	key := r.key(strings.TrimSpace(purpose), strings.TrimSpace(identifier))
	if key == "" {
		return errors.New("purpose and identifier are required")
	}

	deleted, err := r.client.Del(ctx, key).Result()
	if err != nil {
		return fmt.Errorf("redis delete otp: %w", err)
	}
	if deleted == 0 {
		return repository.ErrNotFound
	}

	return nil
}

// WithClock overrides the internal clock, used in tests.
func (r *OTPRepository) WithClock(clock func() time.Time) {
	if clock != nil {
		r.now = clock
	}
}

func (r *OTPRepository) key(purpose, identifier string) string {
	purpose = strings.TrimSpace(purpose)
	identifier = strings.TrimSpace(identifier)
	if purpose == "" || identifier == "" {
		return ""
	}
	return fmt.Sprintf("%s:%s:%s", r.prefix, purpose, identifier)
}

func parseUnix(raw string) (time.Time, error) {
	if strings.TrimSpace(raw) == "" {
		return time.Time{}, errors.New("timestamp is empty")
	}
	v, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return time.Time{}, err
	}
	return time.Unix(v, 0).UTC(), nil
}
