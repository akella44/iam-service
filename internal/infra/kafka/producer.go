package kafka

import (
	"fmt"
	"strings"
	"time"

	"github.com/IBM/sarama"
	"github.com/arklim/social-platform-iam/internal/infra/config"
	"go.uber.org/zap"
)

// Producer wraps Sarama AsyncProducer with error handling and lifecycle management
type Producer struct {
	producer sarama.AsyncProducer
	logger   *zap.Logger
	cfg      config.KafkaSettings
	errChan  chan error
	done     chan struct{}
}

// NewProducer initializes Kafka async producer with error channel handling
func NewProducer(cfg config.KafkaSettings, logger *zap.Logger) (*Producer, error) {
	saramaConfig := sarama.NewConfig()
	saramaConfig.Version = sarama.V3_5_0_0 // Kafka 7.5.0 corresponds to protocol 3.5

	// Producer configuration
	saramaConfig.Producer.RequiredAcks = sarama.WaitForLocal // Wait for leader ack only (performance vs durability trade-off)
	saramaConfig.Producer.Compression = sarama.CompressionSnappy
	saramaConfig.Producer.Flush.Frequency = 100 * time.Millisecond
	saramaConfig.Producer.Flush.Messages = 100
	saramaConfig.Producer.Retry.Max = 3
	saramaConfig.Producer.Return.Successes = false // Don't need success confirmations for async fire-and-forget
	saramaConfig.Producer.Return.Errors = true     // Must return errors for monitoring

	// Metadata refresh settings
	saramaConfig.Metadata.Retry.Max = 3
	saramaConfig.Metadata.Retry.Backoff = 250 * time.Millisecond

	// Create async producer
	producer, err := sarama.NewAsyncProducer(cfg.Brokers, saramaConfig)
	if err != nil {
		return nil, fmt.Errorf("create kafka producer: %w", err)
	}

	p := &Producer{
		producer: producer,
		logger:   logger,
		cfg:      cfg,
		errChan:  make(chan error, 256), // Buffered channel for error handling
		done:     make(chan struct{}),
	}

	// Start error handler goroutine
	go p.handleErrors()

	logger.Info("Kafka producer initialized",
		zap.Strings("brokers", cfg.Brokers),
		zap.String("topic_prefix", cfg.TopicPrefix),
		zap.Bool("async", cfg.Async),
	)

	return p, nil
}

// handleErrors monitors the Errors channel and logs/handles producer errors
func (p *Producer) handleErrors() {
	for {
		select {
		case err := <-p.producer.Errors():
			if err != nil {
				p.logger.Error("Kafka producer error",
					zap.Error(err.Err),
					zap.String("topic", err.Msg.Topic),
					zap.Int32("partition", err.Msg.Partition),
					zap.Int64("offset", err.Msg.Offset),
				)
				// Send to error channel for optional external monitoring
				select {
				case p.errChan <- err.Err:
				default:
					// Channel full, log and drop
					p.logger.Warn("Error channel full, dropping error")
				}
			}
		case <-p.done:
			return
		}
	}
}

// Producer returns the underlying Sarama AsyncProducer
func (p *Producer) Producer() sarama.AsyncProducer {
	return p.producer
}

// Errors returns the error channel for external monitoring
func (p *Producer) Errors() <-chan error {
	return p.errChan
}

// Close gracefully closes the producer and waits for pending messages
func (p *Producer) Close() error {
	p.logger.Info("Closing Kafka producer")
	close(p.done)

	if err := p.producer.Close(); err != nil {
		return fmt.Errorf("close kafka producer: %w", err)
	}

	close(p.errChan)
	return nil
}

// TopicName returns the full topic name with prefix
func (p *Producer) TopicName(eventType string) string {
	if p.cfg.TopicPrefix == "" {
		return eventType
	}

	prefix := fmt.Sprintf("%s.", p.cfg.TopicPrefix)
	if strings.HasPrefix(eventType, prefix) {
		return eventType
	}

	return fmt.Sprintf("%s%s", prefix, eventType)
}
