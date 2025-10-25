package port

import (
	"context"

	"github.com/arklim/social-platform-iam/internal/core/domain"
)

// RoleRepository handles role CRUD.
type RoleRepository interface {
	Create(ctx context.Context, role domain.Role) error
	List(ctx context.Context) ([]domain.Role, error)
	GetByName(ctx context.Context, name string) (*domain.Role, error)
	AssignPermissions(ctx context.Context, roleID string, permissionIDs []string) (int, error)
	RevokePermissions(ctx context.Context, roleID string, permissionIDs []string) (int, error)
	GetRolePermissions(ctx context.Context, roleID string) ([]domain.Permission, error)
	AssignToUsers(ctx context.Context, roleID string, userIDs []string) error
	ListByUser(ctx context.Context, userID string) ([]domain.Role, error)
}
