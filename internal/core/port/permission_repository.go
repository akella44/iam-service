package port

import (
	"context"

	"github.com/arklim/social-platform-iam/internal/core/domain"
)

// PermissionRepository manages permission storage.
type PermissionRepository interface {
	Create(ctx context.Context, permission domain.Permission) error
	GetByName(ctx context.Context, name string) (*domain.Permission, error)
	ListByRole(ctx context.Context, roleID string) ([]domain.Permission, error)
	ListByUser(ctx context.Context, userID string) ([]domain.Permission, error)
}
