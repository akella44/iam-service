package usecase

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/arklim/social-platform-iam/internal/core/domain"
	"github.com/arklim/social-platform-iam/internal/core/port"
	"github.com/arklim/social-platform-iam/internal/repository"
)

var (
	// ErrSubjectIDRequired indicates the subject identifier is missing.
	ErrSubjectIDRequired = errors.New("subject id is required")
	// ErrActorRequired indicates the actor responsible for the mutation is missing.
	ErrActorRequired = errors.New("actor is required")
)

// SubjectVersionTxFunc wraps repository operations in a transaction.
type SubjectVersionTxFunc func(ctx context.Context, fn func(repo port.SubjectVersionRepository) error) error

// SubjectVersionService manages subject version state and cache/event propagation.
type SubjectVersionService struct {
	repo     port.SubjectVersionRepository
	tx       SubjectVersionTxFunc
	cache    port.SubjectVersionCache
	events   port.EventPublisher
	cacheTTL time.Duration
	logger   *zap.Logger
	now      func() time.Time
	metrics  SubjectVersionMetrics
}

// SubjectVersionMetrics captures telemetry hooks for cache and propagation tracking.
type SubjectVersionMetrics interface {
	IncCacheHit()
	IncCacheMiss()
	IncBump()
	ObserveLag(duration time.Duration)
}

// SubjectVersionOptions configures optional behaviours for the service.
type SubjectVersionOptions struct {
	CacheTTL time.Duration
}

// NewSubjectVersionService constructs the subject version service.
func NewSubjectVersionService(repo port.SubjectVersionRepository, tx SubjectVersionTxFunc, cache port.SubjectVersionCache, events port.EventPublisher, opts SubjectVersionOptions) *SubjectVersionService {
	svc := &SubjectVersionService{
		repo:     repo,
		tx:       tx,
		cache:    cache,
		events:   events,
		cacheTTL: opts.CacheTTL,
		logger:   zap.NewNop(),
		now:      time.Now,
	}
	if svc.cacheTTL <= 0 {
		svc.cacheTTL = 5 * time.Minute
	}
	return svc
}

// WithLogger attaches a structured logger to the service for operational diagnostics.
func (s *SubjectVersionService) WithLogger(logger *zap.Logger) *SubjectVersionService {
	if logger != nil {
		s.logger = logger
	}
	return s
}

// WithNow overrides the clock, primarily for deterministic testing.
func (s *SubjectVersionService) WithNow(now func() time.Time) *SubjectVersionService {
	if now != nil {
		s.now = now
	}
	return s
}

// WithMetrics wires telemetry observers for subject version operations.
func (s *SubjectVersionService) WithMetrics(metrics SubjectVersionMetrics) *SubjectVersionService {
	if metrics != nil {
		s.metrics = metrics
	}
	return s
}

// Get retrieves the subject version, hydrating the cache on miss.
func (s *SubjectVersionService) Get(ctx context.Context, subjectID string) (*domain.SubjectVersion, error) {
	subjectID = strings.TrimSpace(subjectID)
	if subjectID == "" {
		return nil, ErrSubjectIDRequired
	}

	if s.cache != nil {
		version, notBefore, err := s.cache.GetSubjectVersion(ctx, subjectID)
		if err == nil {
			if s.metrics != nil {
				s.metrics.IncCacheHit()
			}
			subject := &domain.SubjectVersion{
				SubjectID:      subjectID,
				CurrentVersion: version,
				NotBefore:      notBefore,
				UpdatedAt:      s.now().UTC(),
				UpdatedBy:      "cache",
			}
			return subject, nil
		}
		if errors.Is(err, repository.ErrNotFound) {
			if s.metrics != nil {
				s.metrics.IncCacheMiss()
			}
		} else {
			s.logger.Warn("subject version cache lookup failed", zap.String("subject_id", subjectID), zap.Error(err))
			if s.metrics != nil {
				s.metrics.IncCacheMiss()
			}
		}
	}

	subject, err := s.repo.Get(ctx, subjectID)
	if err != nil {
		return nil, err
	}

	if s.cache != nil {
		if cacheErr := s.cache.SetSubjectVersion(ctx, subject.SubjectID, subject.CurrentVersion, subject.NotBefore, s.cacheTTL); cacheErr != nil {
			s.logger.Warn("failed to populate subject version cache", zap.String("subject_id", subject.SubjectID), zap.Error(cacheErr))
		}
	}

	return subject, nil
}

// BumpSubjectVersion applies a version mutation and emits corresponding audit and event payloads.
func (s *SubjectVersionService) BumpSubjectVersion(ctx context.Context, subjectID string, newVersion *int64, notBefore *time.Time, actor string, reason string, metadata map[string]any) (domain.SubjectVersionChange, error) {
	subjectID = strings.TrimSpace(subjectID)
	if subjectID == "" {
		return domain.SubjectVersionChange{}, ErrSubjectIDRequired
	}

	actor = strings.TrimSpace(actor)
	if actor == "" {
		return domain.SubjectVersionChange{}, ErrActorRequired
	}

	appliedAt := s.now().UTC()
	normalizedReason := strings.TrimSpace(reason)

	mutation := domain.SubjectVersionMutation{
		SubjectID:  subjectID,
		Actor:      actor,
		Reason:     normalizedReason,
		NewVersion: newVersion,
		NotBefore:  notBefore,
		Metadata:   metadata,
		AppliedAt:  appliedAt,
	}

	var change domain.SubjectVersionChange
	txFn := s.tx
	if txFn == nil {
		txFn = func(ctx context.Context, fn func(repo port.SubjectVersionRepository) error) error {
			return fn(s.repo)
		}
	}

	err := txFn(ctx, func(repo port.SubjectVersionRepository) error {
		updated, err := repo.ApplyMutation(ctx, mutation)
		if err != nil {
			return err
		}

		audit := domain.SubjectVersionAuditEntry{
			EventID:      uuid.NewString(),
			SubjectID:    subjectID,
			NewVersion:   updated.Current.CurrentVersion,
			NewNotBefore: updated.Current.NotBefore,
			Actor:        actor,
			Reason:       normalizedReason,
			CreatedAt:    appliedAt,
		}
		if updated.Previous != nil {
			audit.PreviousVersion = &updated.Previous.CurrentVersion
			audit.PreviousNotBefore = updated.Previous.NotBefore
		}

		if err := repo.AppendAudit(ctx, audit); err != nil {
			return err
		}

		change = updated
		return nil
	})
	if err != nil {
		return domain.SubjectVersionChange{}, err
	}

	if s.cache != nil {
		if cacheErr := s.cache.SetSubjectVersion(ctx, change.Current.SubjectID, change.Current.CurrentVersion, change.Current.NotBefore, s.cacheTTL); cacheErr != nil {
			s.logger.Warn("failed to update subject version cache", zap.String("subject_id", change.Current.SubjectID), zap.Error(cacheErr))
		}
	}

	if s.events != nil {
		event := domain.SubjectVersionBumpedEvent{
			EventID:           uuid.NewString(),
			SubjectID:         change.Current.SubjectID,
			PreviousVersion:   nil,
			NewVersion:        change.Current.CurrentVersion,
			PreviousNotBefore: nil,
			NewNotBefore:      change.Current.NotBefore,
			Actor:             actor,
			Reason:            normalizedReason,
			BumpedAt:          appliedAt,
			Metadata:          cloneMetadata(metadata),
		}
		if change.Previous != nil {
			event.PreviousVersion = &change.Previous.CurrentVersion
			event.PreviousNotBefore = change.Previous.NotBefore
		}
		if err := s.events.PublishSubjectVersionBumped(ctx, event); err != nil {
			s.logger.Warn("failed to publish subject version event", zap.String("subject_id", event.SubjectID), zap.Error(err))
		}
	}

	if s.metrics != nil {
		s.metrics.IncBump()
		s.metrics.ObserveLag(s.now().UTC().Sub(appliedAt))
	}

	return change, nil
}

func cloneMetadata(src map[string]any) map[string]any {
	if len(src) == 0 {
		return nil
	}
	dst := make(map[string]any, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}
