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

// SubjectVersionConsumer updates local caches when subject version events are observed.
type SubjectVersionConsumer struct {
	cache  port.SubjectVersionCache
	ttl    time.Duration
	logger *zap.Logger
}

// NewSubjectVersionConsumer constructs a consumer that hydrates the subject version cache.
func NewSubjectVersionConsumer(cache port.SubjectVersionCache, ttl time.Duration, logger *zap.Logger) *SubjectVersionConsumer {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &SubjectVersionConsumer{cache: cache, ttl: ttl, logger: logger}
}

// HandleMessage decodes a Kafka message and updates the cache.
func (c *SubjectVersionConsumer) HandleMessage(ctx context.Context, msg *sarama.ConsumerMessage) error {
	if msg == nil {
		return fmt.Errorf("message is nil")
	}

	var event domain.SubjectVersionBumpedEvent
	if err := json.Unmarshal(msg.Value, &event); err != nil {
		return fmt.Errorf("decode subject version event: %w", err)
	}

	return c.HandleEvent(ctx, event)
}

// HandleEvent applies the subject version change to the cache.
func (c *SubjectVersionConsumer) HandleEvent(ctx context.Context, event domain.SubjectVersionBumpedEvent) error {
	if c.cache == nil {
		return nil
	}
	ttl := c.ttl
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}

	if err := c.cache.SetSubjectVersion(ctx, event.SubjectID, event.NewVersion, event.NewNotBefore, ttl); err != nil {
		c.logger.Warn("failed to hydrate subject version cache", zap.String("subject_id", event.SubjectID), zap.Error(err))
		return fmt.Errorf("cache subject version: %w", err)
	}

	return nil
}
