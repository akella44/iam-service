package security

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/arklim/social-platform-iam/internal/core/domain"
	"github.com/arklim/social-platform-iam/internal/core/port"
)

// JTIDenylistOptions controls in-memory denylist behaviour.
type JTIDenylistOptions struct {
	WindowDuration time.Duration
	WindowCount    int
	MaxEntries     int
}

type denylistEntry struct {
	ExpiresAt time.Time
}

// JTIDenylistCache implements a sliding window denylist for revoked JTIs.
type JTIDenylist struct {
	mu             sync.RWMutex
	entries        map[string]denylistEntry
	windowDuration time.Duration
	windowCount    int
	maxEntries     int
	now            func() time.Time
}

// NewJTIDenylistCache constructs an in-memory denylist implementation backed by sliding windows.
func NewJTIDenylistCache(opts JTIDenylistOptions) *JTIDenylist {
	if opts.WindowDuration <= 0 {
		opts.WindowDuration = time.Minute
	}
	if opts.WindowCount <= 0 {
		opts.WindowCount = 6
	}
	cache := &JTIDenylist{
		entries:        make(map[string]denylistEntry),
		windowDuration: opts.WindowDuration,
		windowCount:    opts.WindowCount,
		maxEntries:     opts.MaxEntries,
	}
	cache.now = func() time.Time { return time.Now().UTC() }
	return cache
}

// WithClock overrides the internal clock for deterministic testing.
func (c *JTIDenylist) WithClock(clock func() time.Time) *JTIDenylist {
	if clock != nil {
		c.mu.Lock()
		defer c.mu.Unlock()
		c.now = clock
	}
	return c
}

// AddRevocation records a revoked JTI until its expiration window elapses.
func (c *JTIDenylist) AddRevocation(_ context.Context, revocation domain.TokenRevocation) error {
	jti := strings.TrimSpace(revocation.JTI)
	if jti == "" {
		return fmt.Errorf("jti is required")
	}

	expiresAt := revocation.ExpiresAt.UTC()
	now := c.currentTime()
	if !revocation.ExpiresAt.IsZero() && !expiresAt.After(now) {
		return nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.maxEntries > 0 && len(c.entries) >= c.maxEntries {
		c.evictOldestLocked(len(c.entries) - c.maxEntries + 1)
	}

	c.entries[jti] = denylistEntry{ExpiresAt: expiresAt}
	return nil
}

// Contains tests whether the supplied JTI has been revoked and remains within the active window.
func (c *JTIDenylist) Contains(_ context.Context, jti string) (bool, error) {
	jti = strings.TrimSpace(jti)
	if jti == "" {
		return false, fmt.Errorf("jti is required")
	}

	now := c.currentTime()
	c.mu.RLock()
	entry, ok := c.entries[jti]
	c.mu.RUnlock()
	if !ok {
		return false, nil
	}
	if !entry.ExpiresAt.IsZero() && !entry.ExpiresAt.After(now) {
		// Expired entries are lazily pruned on access.
		c.mu.Lock()
		delete(c.entries, jti)
		c.mu.Unlock()
		return false, nil
	}
	return true, nil
}

// RestoreSnapshot replaces the in-memory state with the provided snapshot payload.
func (c *JTIDenylist) RestoreSnapshot(_ context.Context, snapshot domain.JTIDenylistSnapshot) error {
	if len(snapshot.Payload) == 0 {
		return nil
	}

	var data denylistSnapshot
	if err := json.Unmarshal(snapshot.Payload, &data); err != nil {
		return fmt.Errorf("decode denylist snapshot: %w", err)
	}

	entries := make(map[string]denylistEntry, len(data.Entries))
	for _, item := range data.Entries {
		key := strings.TrimSpace(item.JTI)
		if key == "" {
			continue
		}
		entries[key] = denylistEntry{ExpiresAt: item.ExpiresAt.UTC()}
	}

	c.mu.Lock()
	c.entries = entries
	c.mu.Unlock()
	return nil
}

// Snapshot serialises the active denylist entries for persistence.
func (c *JTIDenylist) Snapshot(_ context.Context) (*domain.JTIDenylistSnapshot, error) {
	now := c.currentTime()
	c.mu.RLock()
	entries := make([]denylistSnapshotEntry, 0, len(c.entries))
	for jti, entry := range c.entries {
		if !entry.ExpiresAt.IsZero() && !entry.ExpiresAt.After(now) {
			continue
		}
		entries = append(entries, denylistSnapshotEntry{JTI: jti, ExpiresAt: entry.ExpiresAt.UTC()})
	}
	c.mu.RUnlock()

	sort.Slice(entries, func(i, j int) bool {
		if entries[i].ExpiresAt.Equal(entries[j].ExpiresAt) {
			return entries[i].JTI < entries[j].JTI
		}
		return entries[i].ExpiresAt.Before(entries[j].ExpiresAt)
	})

	payload, err := json.Marshal(denylistSnapshot{Entries: entries})
	if err != nil {
		return nil, fmt.Errorf("encode denylist snapshot: %w", err)
	}

	checksum := sha256.Sum256(payload)
	snapshot := &domain.JTIDenylistSnapshot{
		SnapshotID:  uuid.NewString(),
		GeneratedAt: now,
		Payload:     payload,
		Checksum:    base64.StdEncoding.EncodeToString(checksum[:]),
	}
	return snapshot, nil
}

// Prune removes expired JTIs and rotates the sliding window when necessary.
func (c *JTIDenylist) Prune(_ context.Context, now time.Time) error {
	cutoff := now.UTC()
	windowHorizon := cutoff
	if c.windowDuration > 0 && c.windowCount > 0 {
		windowHorizon = cutoff.Add(-c.windowDuration * time.Duration(c.windowCount))
	}

	c.mu.Lock()
	for key, entry := range c.entries {
		expired := !entry.ExpiresAt.IsZero() && !entry.ExpiresAt.After(cutoff)
		tooOld := !entry.ExpiresAt.IsZero() && entry.ExpiresAt.Before(windowHorizon)
		if expired || tooOld {
			delete(c.entries, key)
		}
	}
	c.mu.Unlock()
	return nil
}

func (c *JTIDenylist) currentTime() time.Time {
	c.mu.RLock()
	nowFn := c.now
	c.mu.RUnlock()
	if nowFn == nil {
		return time.Now().UTC()
	}
	return nowFn().UTC()
}

func (c *JTIDenylist) evictOldestLocked(count int) {
	if count <= 0 || len(c.entries) == 0 {
		return
	}
	type item struct {
		key string
		exp time.Time
	}
	values := make([]item, 0, len(c.entries))
	for key, entry := range c.entries {
		values = append(values, item{key: key, exp: entry.ExpiresAt})
	}
	sort.Slice(values, func(i, j int) bool { return values[i].exp.Before(values[j].exp) })
	if count > len(values) {
		count = len(values)
	}
	for i := 0; i < count; i++ {
		delete(c.entries, values[i].key)
	}
}

type denylistSnapshot struct {
	Entries []denylistSnapshotEntry `json:"entries"`
}

type denylistSnapshotEntry struct {
	JTI       string    `json:"jti"`
	ExpiresAt time.Time `json:"expires_at"`
}

var _ port.JTIDenylistCache = (*JTIDenylist)(nil)
