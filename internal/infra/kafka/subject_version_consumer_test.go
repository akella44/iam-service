package kafka

import (
	"context"
	"testing"
	"time"

	"go.uber.org/zap/zaptest"

	"github.com/arklim/social-platform-iam/internal/core/domain"
)

type stubSubjectVersionCache struct {
	setCalls []cacheCall
}

type cacheCall struct {
	subjectID string
	version   int64
	notBefore *time.Time
	ttl       time.Duration
}

func (s *stubSubjectVersionCache) GetSubjectVersion(context.Context, string) (int64, *time.Time, error) {
	return 0, nil, nil
}

func (s *stubSubjectVersionCache) SetSubjectVersion(_ context.Context, subjectID string, version int64, notBefore *time.Time, ttl time.Duration) error {
	s.setCalls = append(s.setCalls, cacheCall{
		subjectID: subjectID,
		version:   version,
		notBefore: notBefore,
		ttl:       ttl,
	})
	return nil
}

func (s *stubSubjectVersionCache) DeleteSubjectVersion(context.Context, string) error { return nil }

func TestSubjectVersionConsumerHandleEvent(t *testing.T) {
	cache := &stubSubjectVersionCache{}
	ttl := 30 * time.Second
	consumer := NewSubjectVersionConsumer(cache, ttl, zaptest.NewLogger(t))

	event := domain.SubjectVersionBumpedEvent{
		SubjectID:  "subject-123",
		NewVersion: 9,
		NewNotBefore: func() *time.Time {
			nb := time.Now().UTC()
			return &nb
		}(),
	}

	if err := consumer.HandleEvent(context.Background(), event); err != nil {
		t.Fatalf("HandleEvent returned error: %v", err)
	}

	if len(cache.setCalls) != 1 {
		t.Fatalf("expected 1 cache call, got %d", len(cache.setCalls))
	}

	call := cache.setCalls[0]
	if call.subjectID != event.SubjectID {
		t.Fatalf("unexpected subject id: %s", call.subjectID)
	}

	if call.version != event.NewVersion {
		t.Fatalf("unexpected version: %d", call.version)
	}

	if call.ttl != ttl {
		t.Fatalf("unexpected ttl: %v", call.ttl)
	}

	if call.notBefore == nil || call.notBefore.IsZero() {
		t.Fatalf("expected not_before to be set")
	}
}
