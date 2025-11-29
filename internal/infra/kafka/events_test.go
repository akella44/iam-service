package kafka

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/IBM/sarama"
	"go.uber.org/zap/zaptest"

	"github.com/arklim/social-platform-iam/internal/core/domain"
	"github.com/arklim/social-platform-iam/internal/infra/config"
)

type fakeAsyncProducer struct {
	input  chan *sarama.ProducerMessage
	errors chan *sarama.ProducerError
}

func newFakeAsyncProducer() *fakeAsyncProducer {
	return &fakeAsyncProducer{
		input:  make(chan *sarama.ProducerMessage, 1),
		errors: make(chan *sarama.ProducerError, 1),
	}
}

func (f *fakeAsyncProducer) AsyncClose() {}

func (f *fakeAsyncProducer) Close() error { return nil }

func (f *fakeAsyncProducer) Input() chan<- *sarama.ProducerMessage { return f.input }

func (f *fakeAsyncProducer) Successes() <-chan *sarama.ProducerMessage { return nil }

func (f *fakeAsyncProducer) Errors() <-chan *sarama.ProducerError { return f.errors }

func (f *fakeAsyncProducer) IsTransactional() bool { return false }

func (f *fakeAsyncProducer) BeginTxn() error { return nil }

func (f *fakeAsyncProducer) CommitTxn() error { return nil }

func (f *fakeAsyncProducer) AbortTxn() error { return nil }

func (f *fakeAsyncProducer) AddOffsetsToTxn(offsets map[string][]*sarama.PartitionOffsetMetadata, groupID string) error {
	return nil
}

func (f *fakeAsyncProducer) AddMessageToTxn(msg *sarama.ConsumerMessage, groupID string, metadata *string) error {
	return nil
}

func (f *fakeAsyncProducer) TxnStatus() sarama.ProducerTxnStatusFlag {
	return sarama.ProducerTxnStatusFlag(0)
}

func TestPublishSessionVersionBumped(t *testing.T) {
	asyncProducer := newFakeAsyncProducer()

	producer := &Producer{
		producer: asyncProducer,
		logger:   zaptest.NewLogger(t),
		cfg: config.KafkaSettings{
			TopicPrefix: "iam",
		},
		errChan: make(chan error, 1),
		done:    make(chan struct{}),
	}

	publisher := NewEventPublisher(producer, config.AppSettings{
		Name: "iam-service",
		Env:  "test",
	}, zaptest.NewLogger(t))

	bumpedAt := time.Date(2025, 10, 31, 12, 0, 0, 0, time.UTC)
	event := domain.SessionVersionBumpedEvent{
		EventID:   "event-123",
		SessionID: "session-456",
		UserID:    "user-789",
		Version:   3,
		Reason:    "refresh_rotation",
		BumpedAt:  bumpedAt,
		Metadata:  map[string]any{"source": "unit-test"},
	}

	if err := publisher.PublishSessionVersionBumped(context.Background(), event); err != nil {
		t.Fatalf("PublishSessionVersionBumped returned error: %v", err)
	}

	select {
	case msg := <-asyncProducer.input:
		if msg.Topic != "iam.session.version.bumped" {
			t.Fatalf("unexpected topic: %s", msg.Topic)
		}

		bytes, err := msg.Value.Encode()
		if err != nil {
			t.Fatalf("Value.Encode returned error: %v", err)
		}

		var envelope map[string]any
		if err := json.Unmarshal(bytes, &envelope); err != nil {
			t.Fatalf("failed to unmarshal envelope: %v", err)
		}

		if got := envelope["event_type"]; got != "iam.session.version.bumped" {
			t.Fatalf("unexpected event_type: %v", got)
		}

		if got := envelope["user_id"]; got != event.UserID {
			t.Fatalf("unexpected user_id: %v", got)
		}

		timestamp, ok := envelope["timestamp"].(string)
		if !ok {
			t.Fatalf("timestamp not a string: %T", envelope["timestamp"])
		}

		if timestamp != bumpedAt.Format(time.RFC3339Nano) {
			t.Fatalf("unexpected timestamp: %s", timestamp)
		}

		payload, ok := envelope["payload"].(map[string]any)
		if !ok {
			t.Fatalf("payload not a map: %T", envelope["payload"])
		}

		if got := payload["session_id"]; got != event.SessionID {
			t.Fatalf("unexpected session_id: %v", got)
		}

		if got := payload["user_id"]; got != event.UserID {
			t.Fatalf("unexpected payload.user_id: %v", got)
		}

		if got := payload["reason"]; got != event.Reason {
			t.Fatalf("unexpected reason: %v", got)
		}

		versionValue, ok := payload["version"].(float64)
		if !ok {
			t.Fatalf("version not a number: %T", payload["version"])
		}

		if int64(versionValue) != event.Version {
			t.Fatalf("unexpected version: %v", versionValue)
		}

		bumpedAtValue, ok := payload["bumped_at"].(string)
		if !ok {
			t.Fatalf("bumped_at not a string: %T", payload["bumped_at"])
		}

		if bumpedAtValue != bumpedAt.Format(time.RFC3339Nano) {
			t.Fatalf("unexpected bumped_at: %s", bumpedAtValue)
		}

		metadata, ok := payload["metadata"].(map[string]any)
		if !ok {
			t.Fatalf("metadata not a map: %T", payload["metadata"])
		}

		if metadata["source"] != "unit-test" {
			t.Fatalf("metadata did not round-trip: %v", metadata)
		}

		envelopeMetadata, ok := envelope["metadata"].(map[string]any)
		if !ok {
			t.Fatalf("envelope metadata not a map: %T", envelope["metadata"])
		}

		if envelopeMetadata["service"] != "iam-service" {
			t.Fatalf("unexpected metadata service: %v", envelopeMetadata["service"])
		}

		if envelopeMetadata["environment"] != "test" {
			t.Fatalf("unexpected metadata environment: %v", envelopeMetadata["environment"])
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for message on async producer input channel")
	}
}
