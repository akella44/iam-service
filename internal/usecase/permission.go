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
	PermissionManage = "permission:manage"
)

var (
	// ErrPermissionExists indicates a permission with the provided name already exists.
	ErrPermissionExists = errors.New("permission already exists")
	// ErrInvalidNamespace indicates the service namespace is invalid or empty.
	ErrInvalidNamespace = errors.New("invalid service namespace")
	// ErrInvalidAction indicates the action is invalid or empty.
	ErrInvalidAction = errors.New("invalid action")
)

// CreatePermissionInput captures the payload for creating a permission.
type CreatePermissionInput struct {
	ServiceNamespace string
	Action           string
	Description      *string
}

// UpdatePermissionInput captures the payload for updating a permission.
type UpdatePermissionInput struct {
	ID               string
	ServiceNamespace *string
	Action           *string
	Description      *string
}

// ListPermissionsInput captures filters for listing permissions.
type ListPermissionsInput struct {
	ServiceNamespace string
	Limit            int
	Offset           int
}

// ListPermissionsResult includes permissions and pagination metadata.
type ListPermissionsResult struct {
	Permissions []domain.Permission
	Total       int
	Limit       int
	Offset      int
}

// PermissionService manages permissions.
type PermissionService struct {
	permissions port.PermissionRepository
}

// NewPermissionService constructs a PermissionService.
func NewPermissionService(permissions port.PermissionRepository) *PermissionService {
	return &PermissionService{permissions: permissions}
}

// CreatePermission provisions a new permission, ensuring the actor has sufficient permissions.
func (s *PermissionService) CreatePermission(ctx context.Context, actorID string, input CreatePermissionInput) (*domain.Permission, error) {
	actorID = strings.TrimSpace(actorID)
	if actorID == "" {
		return nil, fmt.Errorf("actor id is required")
	}

	// Verify actor has permission to manage permissions
	actorPermissions, err := s.permissions.ListByUser(ctx, actorID)
	if err != nil {
		return nil, fmt.Errorf("list actor permissions: %w", err)
	}

	hasPermission := false
	for _, perm := range actorPermissions {
		if perm.Name == PermissionManage {
			hasPermission = true
			break
		}
	}

	if !hasPermission {
		return nil, ErrPermissionDenied
	}

	// Validate input
	namespace := strings.TrimSpace(input.ServiceNamespace)
	if namespace == "" {
		return nil, ErrInvalidNamespace
	}

	action := strings.TrimSpace(input.Action)
	if action == "" {
		return nil, ErrInvalidAction
	}

	// Build canonical name
	name := fmt.Sprintf("%s:%s", namespace, action)

	// Check if permission already exists
	if existing, err := s.permissions.GetByName(ctx, name); err == nil && existing != nil {
		return nil, ErrPermissionExists
	} else if err != nil && !errors.Is(err, repository.ErrNotFound) {
		return nil, fmt.Errorf("lookup permission by name: %w", err)
	}

	permission := domain.Permission{
		ID:               uuid.NewString(),
		Name:             name,
		ServiceNamespace: namespace,
		Action:           action,
	}

	if input.Description != nil {
		trimmed := strings.TrimSpace(*input.Description)
		if trimmed != "" {
			permission.Description = &trimmed
		}
	}

	if err := s.permissions.Create(ctx, permission); err != nil {
		return nil, fmt.Errorf("create permission: %w", err)
	}

	return &permission, nil
}

// GetPermission retrieves a permission by ID.
func (s *PermissionService) GetPermission(ctx context.Context, permissionID string) (*domain.Permission, error) {
	permissionID = strings.TrimSpace(permissionID)
	if permissionID == "" {
		return nil, fmt.Errorf("permission id is required")
	}

	permission, err := s.permissions.GetByID(ctx, permissionID)
	if err != nil {
		return nil, fmt.Errorf("get permission: %w", err)
	}

	return permission, nil
}

// UpdatePermission modifies an existing permission.
func (s *PermissionService) UpdatePermission(ctx context.Context, actorID string, input UpdatePermissionInput) (*domain.Permission, error) {
	actorID = strings.TrimSpace(actorID)
	if actorID == "" {
		return nil, fmt.Errorf("actor id is required")
	}

	permissionID := strings.TrimSpace(input.ID)
	if permissionID == "" {
		return nil, fmt.Errorf("permission id is required")
	}

	// Verify actor has permission
	actorPermissions, err := s.permissions.ListByUser(ctx, actorID)
	if err != nil {
		return nil, fmt.Errorf("list actor permissions: %w", err)
	}

	hasPermission := false
	for _, perm := range actorPermissions {
		if perm.Name == PermissionManage {
			hasPermission = true
			break
		}
	}

	if !hasPermission {
		return nil, ErrPermissionDenied
	}

	// Get existing permission
	permission, err := s.permissions.GetByID(ctx, permissionID)
	if err != nil {
		return nil, fmt.Errorf("get permission: %w", err)
	}

	// Update fields if provided
	if input.ServiceNamespace != nil {
		trimmed := strings.TrimSpace(*input.ServiceNamespace)
		if trimmed == "" {
			return nil, ErrInvalidNamespace
		}
		permission.ServiceNamespace = trimmed
	}

	if input.Action != nil {
		trimmed := strings.TrimSpace(*input.Action)
		if trimmed == "" {
			return nil, ErrInvalidAction
		}
		permission.Action = trimmed
	}

	// Rebuild canonical name if namespace or action changed
	if input.ServiceNamespace != nil || input.Action != nil {
		permission.Name = fmt.Sprintf("%s:%s", permission.ServiceNamespace, permission.Action)
	}

	if input.Description != nil {
		trimmed := strings.TrimSpace(*input.Description)
		if trimmed == "" {
			permission.Description = nil
		} else {
			permission.Description = &trimmed
		}
	}

	if err := s.permissions.Update(ctx, *permission); err != nil {
		return nil, fmt.Errorf("update permission: %w", err)
	}

	return permission, nil
}

// DeletePermission removes a permission by ID.
func (s *PermissionService) DeletePermission(ctx context.Context, actorID, permissionID string) error {
	actorID = strings.TrimSpace(actorID)
	if actorID == "" {
		return fmt.Errorf("actor id is required")
	}

	permissionID = strings.TrimSpace(permissionID)
	if permissionID == "" {
		return fmt.Errorf("permission id is required")
	}

	// Verify actor has permission
	actorPermissions, err := s.permissions.ListByUser(ctx, actorID)
	if err != nil {
		return fmt.Errorf("list actor permissions: %w", err)
	}

	hasPermission := false
	for _, perm := range actorPermissions {
		if perm.Name == PermissionManage {
			hasPermission = true
			break
		}
	}

	if !hasPermission {
		return ErrPermissionDenied
	}

	if err := s.permissions.Delete(ctx, permissionID); err != nil {
		return fmt.Errorf("delete permission: %w", err)
	}

	return nil
}

// ListPermissions returns permissions with optional filtering and pagination.
func (s *PermissionService) ListPermissions(ctx context.Context, input ListPermissionsInput) (*ListPermissionsResult, error) {
	filter := port.PermissionFilter{
		ServiceNamespace: strings.TrimSpace(input.ServiceNamespace),
		Limit:            input.Limit,
		Offset:           input.Offset,
	}

	permissions, err := s.permissions.List(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("list permissions: %w", err)
	}

	total, err := s.permissions.Count(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("count permissions: %w", err)
	}

	return &ListPermissionsResult{
		Permissions: permissions,
		Total:       total,
		Limit:       input.Limit,
		Offset:      input.Offset,
	}, nil
}

// ListNamespaces returns aggregated permission counts per service namespace.
func (s *PermissionService) ListNamespaces(ctx context.Context) ([]port.PermissionNamespaceSummary, error) {
	summaries, err := s.permissions.ListNamespaces(ctx)
	if err != nil {
		return nil, fmt.Errorf("list permission namespaces: %w", err)
	}

	return summaries, nil
}
