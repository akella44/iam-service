package middleware

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap/zaptest"
)

type fakeRateLimitStore struct {
	trimErr   error
	count     int
	countErr  error
	oldest    time.Time
	hasOldest bool
	oldestErr error
	recordErr error

	trimmedKeys []string
	countedKeys []string
	recordedKey string
	recordCalls int
}

func (f *fakeRateLimitStore) TrimWindow(ctx context.Context, identifier string, window time.Duration, reference time.Time) error {
	f.trimmedKeys = append(f.trimmedKeys, identifier)
	return f.trimErr
}

func (f *fakeRateLimitStore) CountAttempts(ctx context.Context, identifier string, window time.Duration, reference time.Time) (int, error) {
	f.countedKeys = append(f.countedKeys, identifier)
	return f.count, f.countErr
}

func (f *fakeRateLimitStore) RecordAttempt(ctx context.Context, identifier string, at time.Time) error {
	f.recordedKey = identifier
	f.recordCalls++
	return f.recordErr
}

func (f *fakeRateLimitStore) OldestAttempt(ctx context.Context, identifier string, window time.Duration, reference time.Time) (time.Time, bool, error) {
	return f.oldest, f.hasOldest, f.oldestErr
}

func TestRateLimiterAllowsWhenBelowLimit(t *testing.T) {
	gin.SetMode(gin.TestMode)

	now := time.Date(2025, 10, 12, 10, 0, 0, 0, time.UTC)
	oldest := now.Add(-30 * time.Second)

	store := &fakeRateLimitStore{
		count:     2,
		oldest:    oldest,
		hasOldest: true,
	}

	limiter := NewRateLimiter(store, zaptest.NewLogger(t)).WithClock(func() time.Time { return now })

	router := gin.New()
	router.Use(limiter.RateLimit(RateLimitRule{
		Name:   "login",
		Limit:  5,
		Window: time.Minute,
		Identifier: func(c *gin.Context) (string, bool) {
			return "192.0.2.1", true
		},
	}))
	router.GET("/", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	if store.recordCalls != 1 {
		t.Fatalf("expected record attempt to be called once, got %d", store.recordCalls)
	}

	if got := rr.Header().Get("X-RateLimit-Limit"); got != "5" {
		t.Fatalf("expected limit header 5, got %q", got)
	}

	if got := rr.Header().Get("X-RateLimit-Remaining"); got != "2" {
		t.Fatalf("expected remaining header 2, got %q", got)
	}

	expectedReset := oldest.Add(time.Minute).Unix()
	if got := rr.Header().Get("X-RateLimit-Reset"); got != strconv.FormatInt(expectedReset, 10) {
		t.Fatalf("expected reset header %d, got %q", expectedReset, got)
	}

	if got := rr.Header().Get("Retry-After"); got != "" {
		t.Fatalf("expected no retry-after header, got %q", got)
	}
}

func TestRateLimiterBlocksWhenLimitExceeded(t *testing.T) {
	gin.SetMode(gin.TestMode)

	now := time.Date(2025, 10, 12, 10, 0, 0, 0, time.UTC)
	oldest := now.Add(-30 * time.Second)

	store := &fakeRateLimitStore{
		count:     5,
		oldest:    oldest,
		hasOldest: true,
	}

	limiter := NewRateLimiter(store, zaptest.NewLogger(t)).WithClock(func() time.Time { return now })

	router := gin.New()
	router.Use(limiter.RateLimit(RateLimitRule{
		Name:   "login",
		Limit:  5,
		Window: time.Minute,
		Identifier: func(c *gin.Context) (string, bool) {
			return "192.0.2.1", true
		},
	}))
	router.GET("/", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", rr.Code)
	}

	if store.recordCalls != 0 {
		t.Fatalf("expected no record attempt when blocked, got %d", store.recordCalls)
	}

	if got := rr.Header().Get("Retry-After"); got != "30" {
		t.Fatalf("expected retry-after 30, got %q", got)
	}

	var problem ProblemDetails
	if err := json.Unmarshal(rr.Body.Bytes(), &problem); err != nil {
		t.Fatalf("failed to decode body: %v", err)
	}

	if problem.Status != http.StatusTooManyRequests {
		t.Fatalf("unexpected problem status %d", problem.Status)
	}

	if problem.RetryAfter != 30 {
		t.Fatalf("expected problem retry_after 30, got %d", problem.RetryAfter)
	}
}

func TestRateLimiterFailsOpenOnStoreError(t *testing.T) {
	gin.SetMode(gin.TestMode)

	now := time.Date(2025, 10, 12, 10, 0, 0, 0, time.UTC)

	store := &fakeRateLimitStore{
		trimErr: errors.New("redis down"),
	}

	limiter := NewRateLimiter(store, zaptest.NewLogger(t)).WithClock(func() time.Time { return now })

	router := gin.New()
	router.Use(limiter.RateLimit(RateLimitRule{
		Name:   "login",
		Limit:  5,
		Window: time.Minute,
		Identifier: func(c *gin.Context) (string, bool) {
			return "192.0.2.1", true
		},
	}))
	router.GET("/", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 when failing open, got %d", rr.Code)
	}

	if store.recordCalls != 0 {
		t.Fatalf("expected no record attempt on failure, got %d", store.recordCalls)
	}
}
