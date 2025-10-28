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

// GetRole retrieves a role by ID.
func (s *RoleService) GetRole(ctx context.Context, roleID string) (*domain.Role, error) {
	roleID = strings.TrimSpace(roleID)
	if roleID == "" {
		return nil, fmt.Errorf("role id is required")
	}

	role, err := s.roles.GetByID(ctx, roleID)
	if err != nil {
		return nil, fmt.Errorf("get role: %w", err)
	}

	return role, nil
}

// UpdateRoleInput captures the payload for updating a role.
type UpdateRoleInput struct {
	ID          string
	Name        *string
	Description *string
}

// UpdateRole modifies an existing role's name and/or description.
func (s *RoleService) UpdateRole(ctx context.Context, actorID string, input UpdateRoleInput) (*domain.Role, error) {
	actorID = strings.TrimSpace(actorID)
	if actorID == "" {
		return nil, fmt.Errorf("actor id is required")
	}

	roleID := strings.TrimSpace(input.ID)
	if roleID == "" {
		return nil, fmt.Errorf("role id is required")
	}

	// Verify actor has permission
	actorPermissions, err := s.permissions.ListByUser(ctx, actorID)
	if err != nil {
		return nil, fmt.Errorf("list actor permissions: %w", err)
	}

	permSet := make(map[string]struct{}, len(actorPermissions))
	for _, permission := range actorPermissions {
		permSet[permission.Name] = struct{}{}
	}

	if _, ok := permSet[PermissionRoleCreate]; !ok {
		return nil, ErrPermissionDenied
	}

	// Get existing role
	role, err := s.roles.GetByID(ctx, roleID)
	if err != nil {
		return nil, fmt.Errorf("get role: %w", err)
	}

	// Update fields if provided
	if input.Name != nil {
		trimmed := strings.TrimSpace(*input.Name)
		if trimmed == "" {
			return nil, fmt.Errorf("role name cannot be empty")
		}
		role.Name = trimmed
	}

	if input.Description != nil {
		trimmed := strings.TrimSpace(*input.Description)
		if trimmed == "" {
			role.Description = nil
		} else {
			role.Description = &trimmed
		}
	}

	if err := s.roles.Update(ctx, *role); err != nil {
		return nil, fmt.Errorf("update role: %w", err)
	}

	return role, nil
}

// DeleteRole removes a role by ID.
func (s *RoleService) DeleteRole(ctx context.Context, actorID, roleID string) error {
	actorID = strings.TrimSpace(actorID)
	if actorID == "" {
		return fmt.Errorf("actor id is required")
	}

	roleID = strings.TrimSpace(roleID)
	if roleID == "" {
		return fmt.Errorf("role id is required")
	}

	// Verify actor has permission
	actorPermissions, err := s.permissions.ListByUser(ctx, actorID)
	if err != nil {
		return fmt.Errorf("list actor permissions: %w", err)
	}

	permSet := make(map[string]struct{}, len(actorPermissions))
	for _, permission := range actorPermissions {
		permSet[permission.Name] = struct{}{}
	}

	if _, ok := permSet[PermissionRoleCreate]; !ok {
		return ErrPermissionDenied
	}

	if err := s.roles.Delete(ctx, roleID); err != nil {
		return fmt.Errorf("delete role: %w", err)
	}

	return nil
}

// AssignPermissionsInput captures the payload for assigning permissions to a role.
type AssignPermissionsInput struct {
	RoleID        string
	PermissionIDs []string
}

// AssignPermissions links permissions to a role.
func (s *RoleService) AssignPermissions(ctx context.Context, actorID string, input AssignPermissionsInput) (int, error) {
	actorID = strings.TrimSpace(actorID)
	if actorID == "" {
		return 0, fmt.Errorf("actor id is required")
	}

	roleID := strings.TrimSpace(input.RoleID)
	if roleID == "" {
		return 0, fmt.Errorf("role id is required")
	}

	// Verify actor has permission
	actorPermissions, err := s.permissions.ListByUser(ctx, actorID)
	if err != nil {
		return 0, fmt.Errorf("list actor permissions: %w", err)
	}

	permSet := make(map[string]struct{}, len(actorPermissions))
	for _, permission := range actorPermissions {
		permSet[permission.Name] = struct{}{}
	}

	if _, ok := permSet[PermissionRoleAssign]; !ok {
		return 0, ErrPermissionDenied
	}

	// Verify role exists
	if _, err := s.roles.GetByID(ctx, roleID); err != nil {
		return 0, fmt.Errorf("get role: %w", err)
	}

	// Filter to unique, non-empty permission IDs
	uniquePermIDs := make([]string, 0, len(input.PermissionIDs))
	seen := make(map[string]struct{}, len(input.PermissionIDs))

	for _, permID := range input.PermissionIDs {
		trimmed := strings.TrimSpace(permID)
		if trimmed == "" {
			continue
		}
		if _, exists := seen[trimmed]; exists {
			continue
		}
		seen[trimmed] = struct{}{}
		uniquePermIDs = append(uniquePermIDs, trimmed)
	}

	count, err := s.roles.AssignPermissions(ctx, roleID, uniquePermIDs)
	if err != nil {
		return 0, fmt.Errorf("assign permissions: %w", err)
	}

	return count, nil
}

// RevokePermissionsInput captures the payload for revoking permissions from a role.
type RevokePermissionsInput struct {
	RoleID        string
	PermissionIDs []string
}

// RevokePermissions removes permissions from a role.
func (s *RoleService) RevokePermissions(ctx context.Context, actorID string, input RevokePermissionsInput) (int, error) {
	actorID = strings.TrimSpace(actorID)
	if actorID == "" {
		return 0, fmt.Errorf("actor id is required")
	}

	roleID := strings.TrimSpace(input.RoleID)
	if roleID == "" {
		return 0, fmt.Errorf("role id is required")
	}

	// Verify actor has permission
	actorPermissions, err := s.permissions.ListByUser(ctx, actorID)
	if err != nil {
		return 0, fmt.Errorf("list actor permissions: %w", err)
	}

	permSet := make(map[string]struct{}, len(actorPermissions))
	for _, permission := range actorPermissions {
		permSet[permission.Name] = struct{}{}
	}

	if _, ok := permSet[PermissionRoleAssign]; !ok {
		return 0, ErrPermissionDenied
	}

	// Verify role exists
	if _, err := s.roles.GetByID(ctx, roleID); err != nil {
		return 0, fmt.Errorf("get role: %w", err)
	}

	// Filter to unique, non-empty permission IDs
	uniquePermIDs := make([]string, 0, len(input.PermissionIDs))
	seen := make(map[string]struct{}, len(input.PermissionIDs))

	for _, permID := range input.PermissionIDs {
		trimmed := strings.TrimSpace(permID)
		if trimmed == "" {
			continue
		}
		if _, exists := seen[trimmed]; exists {
			continue
		}
		seen[trimmed] = struct{}{}
		uniquePermIDs = append(uniquePermIDs, trimmed)
	}

	count, err := s.roles.RevokePermissions(ctx, roleID, uniquePermIDs)
	if err != nil {
		return 0, fmt.Errorf("revoke permissions: %w", err)
	}

	return count, nil
}
