package usecase

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/arklim/social-platform-iam/internal/core/domain"
	"github.com/arklim/social-platform-iam/internal/core/port"
	"github.com/arklim/social-platform-iam/internal/repository"
)

type stubSubjectVersionRepo struct {
	state map[string]domain.SubjectVersion
	audit []domain.SubjectVersionAuditEntry
}

func newStubSubjectVersionRepo() *stubSubjectVersionRepo {
	return &stubSubjectVersionRepo{state: make(map[string]domain.SubjectVersion)}
}

func (s *stubSubjectVersionRepo) Get(_ context.Context, subjectID string) (*domain.SubjectVersion, error) {
	if v, ok := s.state[subjectID]; ok {
		copy := v
		return &copy, nil
	}
	return nil, repository.ErrNotFound
}

func (s *stubSubjectVersionRepo) ApplyMutation(_ context.Context, mutation domain.SubjectVersionMutation) (domain.SubjectVersionChange, error) {
	current, ok := s.state[mutation.SubjectID]
	change := domain.SubjectVersionChange{}
	if ok {
		copy := current
		change.Previous = &copy
	}

	var newVersion int64
	if mutation.NewVersion != nil {
		newVersion = *mutation.NewVersion
	} else if ok {
		newVersion = current.CurrentVersion + 1
	} else {
		newVersion = 1
	}

	next := domain.SubjectVersion{
		SubjectID:      mutation.SubjectID,
		CurrentVersion: newVersion,
		NotBefore:      mutation.NotBefore,
		UpdatedAt:      mutation.AppliedAt,
		UpdatedBy:      mutation.Actor,
	}

	if reason := strings.TrimSpace(mutation.Reason); reason != "" {
		next.Reason = &reason
	}

	s.state[mutation.SubjectID] = next
	change.Current = next
	return change, nil
}

func (s *stubSubjectVersionRepo) AppendAudit(_ context.Context, entry domain.SubjectVersionAuditEntry) error {
	s.audit = append(s.audit, entry)
	return nil
}

type stubSubjectVersionCache struct {
	values map[string]cacheValue
}

type cacheValue struct {
	version   int64
	notBefore *time.Time
}

func newStubSubjectVersionCache() *stubSubjectVersionCache {
	return &stubSubjectVersionCache{values: make(map[string]cacheValue)}
}

func (s *stubSubjectVersionCache) GetSubjectVersion(_ context.Context, subjectID string) (int64, *time.Time, error) {
	v, ok := s.values[subjectID]
	if !ok {
		return 0, nil, repository.ErrNotFound
	}
	return v.version, v.notBefore, nil
}

func (s *stubSubjectVersionCache) SetSubjectVersion(_ context.Context, subjectID string, version int64, notBefore *time.Time, _ time.Duration) error {
	s.values[subjectID] = cacheValue{version: version, notBefore: notBefore}
	return nil
}

func (s *stubSubjectVersionCache) DeleteSubjectVersion(_ context.Context, subjectID string) error {
	delete(s.values, subjectID)
	return nil
}

type stubSubjectVersionMetrics struct {
	hits   int
	misses int
	bumps  int
	lags   []time.Duration
}

func (s *stubSubjectVersionMetrics) IncCacheHit()  { s.hits++ }
func (s *stubSubjectVersionMetrics) IncCacheMiss() { s.misses++ }
func (s *stubSubjectVersionMetrics) IncBump()      { s.bumps++ }
func (s *stubSubjectVersionMetrics) ObserveLag(d time.Duration) {
	s.lags = append(s.lags, d)
}

type stubSubjectEventPublisher struct {
	events []domain.SubjectVersionBumpedEvent
}

func (s *stubSubjectEventPublisher) PublishUserRegistered(context.Context, domain.UserRegisteredEvent) error {
	return nil
}
func (s *stubSubjectEventPublisher) PublishPasswordChanged(context.Context, domain.PasswordChangedEvent) error {
	return nil
}
func (s *stubSubjectEventPublisher) PublishPasswordResetRequested(context.Context, domain.PasswordResetRequestedEvent) error {
	return nil
}
func (s *stubSubjectEventPublisher) PublishRolesAssigned(context.Context, domain.RolesAssignedEvent) error {
	return nil
}
func (s *stubSubjectEventPublisher) PublishRolesRevoked(context.Context, domain.RolesRevokedEvent) error {
	return nil
}
func (s *stubSubjectEventPublisher) PublishSessionRevoked(context.Context, domain.SessionRevokedEvent) error {
	return nil
}
func (s *stubSubjectEventPublisher) PublishSessionVersionBumped(context.Context, domain.SessionVersionBumpedEvent) error {
	return nil
}
func (s *stubSubjectEventPublisher) PublishSubjectVersionBumped(_ context.Context, event domain.SubjectVersionBumpedEvent) error {
	s.events = append(s.events, event)
	return nil
}

func TestSubjectVersionServiceBumpNewSubject(t *testing.T) {
	repo := newStubSubjectVersionRepo()
	cache := newStubSubjectVersionCache()
	metrics := &stubSubjectVersionMetrics{}
	publisher := &stubSubjectEventPublisher{}
	tx := func(ctx context.Context, fn func(repo port.SubjectVersionRepository) error) error {
		return fn(repo)
	}

	service := NewSubjectVersionService(repo, tx, cache, publisher, SubjectVersionOptions{CacheTTL: time.Minute}).WithNow(func() time.Time {
		return time.Date(2025, 11, 18, 9, 0, 0, 0, time.UTC)
	}).WithMetrics(metrics)

	nextVersion := int64(5)
	change, err := service.BumpSubjectVersion(context.Background(), "subject-1", &nextVersion, nil, "admin", "manual", map[string]any{"source": "test"})
	if err != nil {
		t.Fatalf("BumpSubjectVersion returned error: %v", err)
	}

	if change.Current.CurrentVersion != nextVersion {
		t.Fatalf("expected version %d, got %d", nextVersion, change.Current.CurrentVersion)
	}

	if _, ok := cache.values["subject-1"]; !ok {
		t.Fatal("expected cache to be populated")
	}

	if len(publisher.events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(publisher.events))
	}

	if metrics.bumps != 1 {
		t.Fatalf("expected metrics bumps to be 1, got %d", metrics.bumps)
	}

	if metrics.hits != 0 || metrics.misses != 0 {
		t.Fatalf("unexpected cache metrics: hits=%d misses=%d", metrics.hits, metrics.misses)
	}

	if len(repo.audit) != 1 {
		t.Fatalf("expected audit entry, got %d", len(repo.audit))
	}
}

func TestSubjectVersionServiceGetUsesCache(t *testing.T) {
	repo := newStubSubjectVersionRepo()
	cache := newStubSubjectVersionCache()
	metrics := &stubSubjectVersionMetrics{}
	publisher := &stubSubjectEventPublisher{}
	tx := func(ctx context.Context, fn func(repo port.SubjectVersionRepository) error) error { return fn(repo) }

	notBefore := time.Date(2025, 11, 18, 10, 0, 0, 0, time.UTC)
	cache.SetSubjectVersion(context.Background(), "subject-2", 7, &notBefore, time.Minute)

	service := NewSubjectVersionService(repo, tx, cache, publisher, SubjectVersionOptions{CacheTTL: time.Minute}).WithMetrics(metrics)

	subject, err := service.Get(context.Background(), "subject-2")
	if err != nil {
		t.Fatalf("Get returned error: %v", err)
	}

	if subject.CurrentVersion != 7 {
		t.Fatalf("expected version 7, got %d", subject.CurrentVersion)
	}

	if metrics.hits != 1 {
		t.Fatalf("expected cache hit metric, got %d", metrics.hits)
	}

	if metrics.misses != 0 {
		t.Fatalf("unexpected cache miss count: %d", metrics.misses)
	}
}

func TestSubjectVersionServiceGetFallsBackToRepository(t *testing.T) {
	repo := newStubSubjectVersionRepo()
	repo.state["subject-3"] = domain.SubjectVersion{SubjectID: "subject-3", CurrentVersion: 4}
	cache := newStubSubjectVersionCache()
	metrics := &stubSubjectVersionMetrics{}
	publisher := &stubSubjectEventPublisher{}
	tx := func(ctx context.Context, fn func(repo port.SubjectVersionRepository) error) error { return fn(repo) }

	service := NewSubjectVersionService(repo, tx, cache, publisher, SubjectVersionOptions{CacheTTL: time.Minute}).WithMetrics(metrics)

	subject, err := service.Get(context.Background(), "subject-3")
	if err != nil {
		t.Fatalf("Get returned error: %v", err)
	}

	if subject.CurrentVersion != 4 {
		t.Fatalf("expected version 4, got %d", subject.CurrentVersion)
	}

	if metrics.misses != 1 {
		t.Fatalf("expected cache miss metric, got %d", metrics.misses)
	}

	if _, ok := cache.values["subject-3"]; !ok {
		t.Fatal("expected cache to be warmed")
	}
}
