package port

import (
	"context"
	"time"
)

// SubjectVersionCache exposes cache helpers for subject version lookups.
type SubjectVersionCache interface {
	GetSubjectVersion(ctx context.Context, subjectID string) (int64, *time.Time, error)
	SetSubjectVersion(ctx context.Context, subjectID string, version int64, notBefore *time.Time, ttl time.Duration) error
	DeleteSubjectVersion(ctx context.Context, subjectID string) error
}
