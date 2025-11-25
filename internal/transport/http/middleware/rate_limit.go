package middleware

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

const (
	rateLimitProblemType  = "https://iam.social-platform.example.com/errors/rate-limit-exceeded"
	rateLimitProblemTitle = "Rate Limit Exceeded"
)

// RateLimitStore defines the persistence operations required by the middleware.
type RateLimitStore interface {
	TrimWindow(ctx context.Context, identifier string, window time.Duration, reference time.Time) error
	CountAttempts(ctx context.Context, identifier string, window time.Duration, reference time.Time) (int, error)
	RecordAttempt(ctx context.Context, identifier string, at time.Time) error
	OldestAttempt(ctx context.Context, identifier string, window time.Duration, reference time.Time) (time.Time, bool, error)
}

// IdentifierFunc extracts the identifier used to scope rate limits (e.g., client IP).
type IdentifierFunc func(*gin.Context) (string, bool)

// RateLimitRule configures a sliding-window limit for a particular identifier.
type RateLimitRule struct {
	Name       string
	Limit      int
	Window     time.Duration
	Identifier IdentifierFunc
}

type RateLimiter struct {
	store  RateLimitStore
	logger *zap.Logger
	now    func() time.Time
}

type ruleResult struct {
	rule       RateLimitRule
	allowed    bool
	limit      int
	remaining  int
	reset      time.Time
	retryAfter time.Duration
	identifier string
	storageKey string
}

// ProblemDetails represents an RFC 9457 compatible error payload for rate limits.
type ProblemDetails struct {
	Type       string         `json:"type"`
	Title      string         `json:"title"`
	Status     int            `json:"status"`
	Detail     string         `json:"detail"`
	Instance   string         `json:"instance"`
	RetryAfter int            `json:"retry_after"`
	TraceID    string         `json:"trace_id,omitempty"`
	Extensions map[string]any `json:"extensions,omitempty"`
}

// NewRateLimiter builds a reusable rate limiter middleware helper.
func NewRateLimiter(store RateLimitStore, logger *zap.Logger) *RateLimiter {
	if logger == nil {
		logger = zap.NewNop()
	}

	return &RateLimiter{
		store:  store,
		logger: logger,
		now:    time.Now,
	}
}

// WithClock allows injection of a custom clock (primarily for testing).
func (rl *RateLimiter) WithClock(now func() time.Time) *RateLimiter {
	if now != nil {
		rl.now = now
	}
	return rl
}

// ClientIPIdentifier builds an IdentifierFunc using the request's client IP.
func ClientIPIdentifier() IdentifierFunc {
	return func(c *gin.Context) (string, bool) {
		ip := c.ClientIP()
		if ip == "" {
			return "", false
		}
		return ip, true
	}
}

// RateLimit returns a Gin middleware enforcing the provided rules.
func (rl *RateLimiter) RateLimit(rules ...RateLimitRule) gin.HandlerFunc {
	filtered := make([]RateLimitRule, 0, len(rules))
	for _, rule := range rules {
		if rule.Identifier == nil || rule.Limit <= 0 || rule.Window <= 0 {
			continue
		}
		if rule.Name == "" {
			rule.Name = "default"
		}
		filtered = append(filtered, rule)
	}

	return func(c *gin.Context) {
		if len(filtered) == 0 || rl.store == nil {
			c.Next()
			return
		}

		now := rl.now()
		var bestResult *ruleResult

		for _, rule := range filtered {
			identifier, ok := rule.Identifier(c)
			if !ok || identifier == "" {
				continue
			}

			key := fmt.Sprintf("%s:%s", rule.Name, identifier)

			res, err := rl.evaluateRule(c, rule, identifier, key, now)
			if err != nil {
				rl.logger.Warn("rate limit check failed", zap.String("rule", rule.Name), zap.String("identifier", identifier), zap.Error(err))
				continue
			}

			if bestResult == nil || rl.shouldReplaceHeaderResult(*bestResult, res) {
				snapshot := res
				bestResult = &snapshot
			}

			if !res.allowed {
				rl.applyHeaders(c, res)
				rl.respondRateLimited(c, res)
				return
			}
		}

		if bestResult != nil {
			rl.applyHeaders(c, *bestResult)
		}

		c.Next()
	}
}

func (rl *RateLimiter) evaluateRule(c *gin.Context, rule RateLimitRule, identifier, key string, now time.Time) (ruleResult, error) {
	ctx := c.Request.Context()

	if err := rl.store.TrimWindow(ctx, key, rule.Window, now); err != nil {
		return ruleResult{}, err
	}

	count, err := rl.store.CountAttempts(ctx, key, rule.Window, now)
	if err != nil {
		return ruleResult{}, err
	}

	oldest, hasAttempts, err := rl.store.OldestAttempt(ctx, key, rule.Window, now)
	if err != nil {
		return ruleResult{}, err
	}

	result := ruleResult{
		rule:       rule,
		limit:      rule.Limit,
		identifier: identifier,
		storageKey: key,
		reset:      now.Add(rule.Window),
		allowed:    true,
	}

	if hasAttempts {
		result.reset = oldest.Add(rule.Window)
	}

	if count >= rule.Limit {
		result.allowed = false
		result.remaining = 0
		result.retryAfter = result.reset.Sub(now)
		if result.retryAfter < 0 {
			result.retryAfter = 0
		}
		return result, nil
	}

	if err := rl.store.RecordAttempt(ctx, key, now); err != nil {
		return ruleResult{}, err
	}

	count++
	result.remaining = rule.Limit - count
	if result.remaining < 0 {
		result.remaining = 0
	}

	result.retryAfter = result.reset.Sub(now)
	if result.retryAfter < 0 {
		result.retryAfter = 0
	}

	if !hasAttempts {
		result.reset = now.Add(rule.Window)
	}

	return result, nil
}

func (rl *RateLimiter) shouldReplaceHeaderResult(current, candidate ruleResult) bool {
	if !candidate.allowed && current.allowed {
		return true
	}

	if candidate.allowed == current.allowed {
		if candidate.remaining < current.remaining {
			return true
		}
		if candidate.remaining == current.remaining && candidate.reset.Before(current.reset) {
			return true
		}
	}

	return false
}

func (rl *RateLimiter) applyHeaders(c *gin.Context, res ruleResult) {
	headers := c.Writer.Header()
	headers.Set("X-RateLimit-Limit", strconv.Itoa(res.limit))
	headers.Set("X-RateLimit-Remaining", strconv.Itoa(max(res.remaining, 0)))
	headers.Set("X-RateLimit-Reset", strconv.FormatInt(res.reset.Unix(), 10))

	if !res.allowed {
		seconds := int(math.Ceil(res.retryAfter.Seconds()))
		if seconds < 0 {
			seconds = 0
		}
		headers.Set("Retry-After", strconv.Itoa(seconds))
	}
}

func (rl *RateLimiter) respondRateLimited(c *gin.Context, res ruleResult) {
	retrySeconds := int(math.Ceil(res.retryAfter.Seconds()))
	if retrySeconds < 0 {
		retrySeconds = 0
	}

	detail := fmt.Sprintf("Too many requests. Try again in %d seconds.", retrySeconds)
	instance := c.FullPath()
	if instance == "" {
		instance = c.Request.URL.Path
	}

	problem := ProblemDetails{
		Type:       rateLimitProblemType,
		Title:      rateLimitProblemTitle,
		Status:     http.StatusTooManyRequests,
		Detail:     detail,
		Instance:   instance,
		RetryAfter: retrySeconds,
		TraceID:    GetTraceID(c),
	}

	c.AbortWithStatusJSON(http.StatusTooManyRequests, problem)
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
