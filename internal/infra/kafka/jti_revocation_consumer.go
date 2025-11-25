package kafka

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/IBM/sarama"
	"go.uber.org/zap"

	"github.com/arklim/social-platform-iam/internal/core/domain"
	"github.com/arklim/social-platform-iam/internal/core/port"
)

// JTIDenylistConsumerOptions controls persistence cadence and lag monitoring.
type JTIDenylistConsumerOptions struct {
	SnapshotInterval time.Duration
	MaxEventLag      time.Duration
	ReplayTolerance  time.Duration
}

// JTIDenylistConsumer hydrates the local JTI denylist cache from revoke events.
type JTIDenylistConsumer struct {
	cache            port.JTIDenylistCache
	snapshots        port.JTIDenylistSnapshotStore
	metrics          port.JTIDenylistMetrics
	logger           *zap.Logger
	snapshotInterval time.Duration
	lastSnapshot     time.Time
	maxEventLag      time.Duration
	replayTolerance  time.Duration
	now              func() time.Time
}

// NewJTIDenylistConsumer constructs a consumer that keeps the denylist cache current.
func NewJTIDenylistConsumer(cache port.JTIDenylistCache, snapshots port.JTIDenylistSnapshotStore, metrics port.JTIDenylistMetrics, logger *zap.Logger, opts JTIDenylistConsumerOptions) *JTIDenylistConsumer {
	if logger == nil {
		logger = zap.NewNop()
	}
	consumer := &JTIDenylistConsumer{
		cache:            cache,
		snapshots:        snapshots,
		metrics:          metrics,
		logger:           logger,
		snapshotInterval: opts.SnapshotInterval,
		maxEventLag:      opts.MaxEventLag,
		replayTolerance:  opts.ReplayTolerance,
	}
	if consumer.snapshotInterval <= 0 {
		consumer.snapshotInterval = 30 * time.Second
	}
	consumer.now = func() time.Time { return time.Now().UTC() }
	return consumer
}

// WithClock overrides the consumer clock for deterministic testing.
func (c *JTIDenylistConsumer) WithClock(clock func() time.Time) *JTIDenylistConsumer {
	if clock != nil {
		c.now = clock
	}
	return c
}

// HandleMessage decodes a Kafka message prior to processing.
func (c *JTIDenylistConsumer) HandleMessage(ctx context.Context, msg *sarama.ConsumerMessage) error {
	if msg == nil {
		return fmt.Errorf("message is nil")
	}

	var event domain.TokenRevokedEvent
	if err := json.Unmarshal(msg.Value, &event); err != nil {
		return fmt.Errorf("decode token revoked event: %w", err)
	}

	return c.HandleEvent(ctx, event)
}

// HandleEvent applies the revocation to the local cache and persists snapshots periodically.
func (c *JTIDenylistConsumer) HandleEvent(ctx context.Context, event domain.TokenRevokedEvent) error {
	if c.cache == nil {
		return nil
	}

	now := c.now()
	if !event.ExpiresAt.IsZero() && c.replayTolerance > 0 {
		expiredCutoff := now.Add(-c.replayTolerance)
		if !event.ExpiresAt.After(expiredCutoff) {
			c.logger.Debug("skip expired revocation", zap.String("jti", event.JTI))
			return nil
		}
	}

	if !event.RevokedAt.IsZero() {
		lag := now.Sub(event.RevokedAt)
		if lag < 0 {
			lag = 0
		}
		if c.metrics != nil {
			c.metrics.ObserveLag(lag)
		}
		if c.maxEventLag > 0 && lag > c.maxEventLag {
			c.logger.Warn("token revocation event lag exceeds threshold", zap.Duration("lag", lag), zap.Duration("threshold", c.maxEventLag), zap.String("jti", event.JTI))
		}
	}

	createdAt := event.RevokedAt.UTC()
	if createdAt.IsZero() {
		createdAt = now
	}
	expiresAt := event.ExpiresAt.UTC()
	revocation := domain.TokenRevocation{
		RevocationID: event.EventID,
		JTI:          event.JTI,
		SubjectID:    event.SubjectID,
		SessionID:    event.SessionID,
		ExpiresAt:    expiresAt,
		Reason:       event.Reason,
		Actor:        event.Actor,
		IssuedBy:     event.Actor,
		CreatedAt:    createdAt,
		Metadata:     event.Metadata,
	}

	if err := c.cache.AddRevocation(ctx, revocation); err != nil {
		return fmt.Errorf("cache revocation: %w", err)
	}

	if err := c.cache.Prune(ctx, now); err != nil {
		c.logger.Warn("prune denylist cache failed", zap.Error(err))
	}

	if c.snapshots != nil && c.shouldPersist(now) {
		snapshot, err := c.cache.Snapshot(ctx)
		if err != nil {
			return fmt.Errorf("snapshot denylist: %w", err)
		}
		if snapshot != nil {
			if err := c.snapshots.SaveSnapshot(ctx, *snapshot); err != nil {
				return fmt.Errorf("save denylist snapshot: %w", err)
			}
		}
		c.lastSnapshot = now
	}

	return nil
}

func (c *JTIDenylistConsumer) shouldPersist(now time.Time) bool {
	if c.lastSnapshot.IsZero() {
		return true
	}
	return now.Sub(c.lastSnapshot) >= c.snapshotInterval
}

var _ interface {
	HandleMessage(context.Context, *sarama.ConsumerMessage) error
	HandleEvent(context.Context, domain.TokenRevokedEvent) error
} = (*JTIDenylistConsumer)(nil)
