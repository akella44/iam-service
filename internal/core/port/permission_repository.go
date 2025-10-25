package port

import (
	"context"

	"github.com/arklim/social-platform-iam/internal/core/domain"
)

// PermissionFilter provides optional controls for listing permissions.
type PermissionFilter struct {
	ServiceNamespace string
	Limit            int
	Offset           int
}

// PermissionNamespaceSummary represents aggregated statistics for a namespace catalog view.
type PermissionNamespaceSummary struct {
	ServiceNamespace string
	PermissionCount  int
}

// PermissionRepository manages permission storage.
type PermissionRepository interface {
	Create(ctx context.Context, permission domain.Permission) error
	GetByID(ctx context.Context, id string) (*domain.Permission, error)
	GetByName(ctx context.Context, name string) (*domain.Permission, error)
	Update(ctx context.Context, permission domain.Permission) error
	Delete(ctx context.Context, id string) error
	List(ctx context.Context, filter PermissionFilter) ([]domain.Permission, error)
	Count(ctx context.Context, filter PermissionFilter) (int, error)
	ListNamespaces(ctx context.Context) ([]PermissionNamespaceSummary, error)
	ListByRole(ctx context.Context, roleID string) ([]domain.Permission, error)
	ListByUser(ctx context.Context, userID string) ([]domain.Permission, error)
}
