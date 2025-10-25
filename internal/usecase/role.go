package usecase

import (
	"context"
	"errors"
	"fmt"
	"strings"

	uuid "github.com/google/uuid"

	"github.com/arklim/social-platform-iam/internal/core/domain"
	"github.com/arklim/social-platform-iam/internal/core/port"
	"github.com/arklim/social-platform-iam/internal/repository"
)

const (
	PermissionRoleCreate = "role:create"
	PermissionRoleAssign = "role:assign"
)

var (
	// ErrRoleExists indicates a role with the provided name already exists.
	ErrRoleExists = errors.New("role already exists")
	// ErrPermissionDenied indicates the actor lacks required permissions.
	ErrPermissionDenied = errors.New("insufficient permissions")
	// ErrUserNotFound is returned when attempting to assign a role to an unknown user.
	ErrUserNotFound = errors.New("user not found")
)

// PermissionInput represents an incoming permission definition.
type PermissionInput struct {
	Name        string
	Description *string
}

// CreateRoleInput captures the payload for creating a role.
type CreateRoleInput struct {
	Name          string
	Description   *string
	Permissions   []PermissionInput
	AssignUserIDs []string
}

// CreateRoleResult returns the created role, its permissions, and user assignments.
type CreateRoleResult struct {
	Role            domain.Role
	Permissions     []domain.Permission
	AssignedUserIDs []string
}

// RoleService manages roles and permissions.
type RoleService struct {
	roles       port.RoleRepository
	permissions port.PermissionRepository
	users       port.UserRepository
}

// NewRoleService constructs a RoleService.
func NewRoleService(roles port.RoleRepository, permissions port.PermissionRepository, users port.UserRepository) *RoleService {
	return &RoleService{roles: roles, permissions: permissions, users: users}
}

// ListRoles returns all roles.
func (s *RoleService) ListRoles(ctx context.Context) ([]domain.Role, error) {
	return s.roles.List(ctx)
}

// CreateRole provisions a new role, ensuring the actor has sufficient permissions.
func (s *RoleService) CreateRole(ctx context.Context, actorID string, input CreateRoleInput) (CreateRoleResult, error) {
	var result CreateRoleResult

	actorID = strings.TrimSpace(actorID)
	if actorID == "" {
		return result, fmt.Errorf("actor id is required")
	}

	roleName := strings.TrimSpace(input.Name)
	if roleName == "" {
		return result, fmt.Errorf("role name is required")
	}

	actorPermissions, err := s.permissions.ListByUser(ctx, actorID)
	if err != nil {
		return result, fmt.Errorf("list actor permissions: %w", err)
	}

	permSet := make(map[string]struct{}, len(actorPermissions))
	for _, permission := range actorPermissions {
		permSet[permission.Name] = struct{}{}
	}

	if _, ok := permSet[PermissionRoleCreate]; !ok {
		return result, ErrPermissionDenied
	}
	if _, ok := permSet[PermissionRoleAssign]; !ok {
		return result, ErrPermissionDenied
	}

	if existing, err := s.roles.GetByName(ctx, roleName); err == nil && existing != nil {
		return result, ErrRoleExists
	} else if err != nil && !errors.Is(err, repository.ErrNotFound) {
		return result, fmt.Errorf("lookup role by name: %w", err)
	}

	role := domain.Role{ID: uuid.NewString(), Name: roleName}
	if input.Description != nil {
		trimmed := strings.TrimSpace(*input.Description)
		if trimmed != "" {
			role.Description = &trimmed
		}
	}

	if err := s.roles.Create(ctx, role); err != nil {
		return result, fmt.Errorf("create role: %w", err)
	}

	permissionIDs := make([]string, 0, len(input.Permissions))
	result.Permissions = make([]domain.Permission, 0, len(input.Permissions))
	seenPermissions := make(map[string]struct{}, len(input.Permissions))

	for _, permInput := range input.Permissions {
		name := strings.TrimSpace(permInput.Name)
		if name == "" {
			return result, fmt.Errorf("permission name is required")
		}

		canonical := strings.ToLower(name)
		if _, exists := seenPermissions[canonical]; exists {
			continue
		}
		seenPermissions[canonical] = struct{}{}

		permission, err := s.permissions.GetByName(ctx, name)
		if err != nil {
			if errors.Is(err, repository.ErrNotFound) {
				var descPtr *string
				if permInput.Description != nil {
					trimmed := strings.TrimSpace(*permInput.Description)
					if trimmed != "" {
						descPtr = &trimmed
					}
				}

				permission = &domain.Permission{
					ID:          uuid.NewString(),
					Name:        name,
					Description: descPtr,
				}

				if err := s.permissions.Create(ctx, *permission); err != nil {
					return result, fmt.Errorf("create permission %q: %w", name, err)
				}
			} else {
				return result, fmt.Errorf("lookup permission %q: %w", name, err)
			}
		}

		permissionIDs = append(permissionIDs, permission.ID)
		result.Permissions = append(result.Permissions, *permission)
	}

	if _, err := s.roles.AssignPermissions(ctx, role.ID, permissionIDs); err != nil {
		return result, fmt.Errorf("assign permissions: %w", err)
	}

	uniqueUserIDs := make([]string, 0, len(input.AssignUserIDs))
	seenUsers := make(map[string]struct{}, len(input.AssignUserIDs))

	for _, userID := range input.AssignUserIDs {
		trimmed := strings.TrimSpace(userID)
		if trimmed == "" {
			continue
		}
		if _, exists := seenUsers[trimmed]; exists {
			continue
		}

		if _, err := s.users.GetByID(ctx, trimmed); err != nil {
			if errors.Is(err, repository.ErrNotFound) {
				return result, fmt.Errorf("user %s: %w", trimmed, ErrUserNotFound)
			}
			return result, fmt.Errorf("lookup user %s: %w", trimmed, err)
		}

		seenUsers[trimmed] = struct{}{}
		uniqueUserIDs = append(uniqueUserIDs, trimmed)
	}

	if err := s.roles.AssignToUsers(ctx, role.ID, uniqueUserIDs); err != nil {
		return result, fmt.Errorf("assign role to users: %w", err)
	}

	result.Role = role
	result.AssignedUserIDs = uniqueUserIDs

	return result, nil
}
