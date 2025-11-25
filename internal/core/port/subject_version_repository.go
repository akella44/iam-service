package port

import (
	"context"

	"github.com/arklim/social-platform-iam/internal/core/domain"
)

// SubjectVersionRepository persists subject version state and audit history.
type SubjectVersionRepository interface {
	Get(ctx context.Context, subjectID string) (*domain.SubjectVersion, error)
	ApplyMutation(ctx context.Context, mutation domain.SubjectVersionMutation) (domain.SubjectVersionChange, error)
	AppendAudit(ctx context.Context, entry domain.SubjectVersionAuditEntry) error
}
