package usecase

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/arklim/social-platform-iam/internal/core/domain"
	"github.com/arklim/social-platform-iam/internal/core/port"
	"github.com/arklim/social-platform-iam/internal/repository"
)

// Mock repository for permission testing

type permRepoMock struct {
	permissions       map[string]domain.Permission
	permissionsByName map[string]domain.Permission
	userPermissions   map[string][]domain.Permission
	createErr         error
	updateErr         error
	deleteErr         error
}

func (m *permRepoMock) Create(_ context.Context, perm domain.Permission) error {
	if m.createErr != nil {
		return m.createErr
	}
	if m.permissions == nil {
		m.permissions = make(map[string]domain.Permission)
	}
	if m.permissionsByName == nil {
		m.permissionsByName = make(map[string]domain.Permission)
	}
	m.permissions[perm.ID] = perm
	m.permissionsByName[perm.Name] = perm
	return nil
}

func (m *permRepoMock) GetByID(_ context.Context, id string) (*domain.Permission, error) {
	if perm, ok := m.permissions[id]; ok {
		return &perm, nil
	}
	return nil, repository.ErrNotFound
}

func (m *permRepoMock) GetByName(_ context.Context, name string) (*domain.Permission, error) {
	if perm, ok := m.permissionsByName[name]; ok {
		return &perm, nil
	}
	return nil, repository.ErrNotFound
}

func (m *permRepoMock) Update(_ context.Context, perm domain.Permission) error {
	if m.updateErr != nil {
		return m.updateErr
	}
	if _, exists := m.permissions[perm.ID]; !exists {
		return repository.ErrNotFound
	}
	m.permissions[perm.ID] = perm
	// Update name index
	m.permissionsByName[perm.Name] = perm
	return nil
}

func (m *permRepoMock) Delete(_ context.Context, id string) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	perm, exists := m.permissions[id]
	if !exists {
		return repository.ErrNotFound
	}
	delete(m.permissions, id)
	delete(m.permissionsByName, perm.Name)
	return nil
}

func (m *permRepoMock) List(_ context.Context, filter port.PermissionFilter) ([]domain.Permission, error) {
	result := make([]domain.Permission, 0)
	for _, perm := range m.permissions {
		// Apply namespace filter
		if filter.ServiceNamespace != "" {
			parts := strings.Split(perm.Name, ":")
			if len(parts) != 2 || parts[0] != filter.ServiceNamespace {
				continue
			}
		}
		result = append(result, perm)
	}

	// Apply pagination
	start := filter.Offset
	end := start + filter.Limit

	if start >= len(result) {
		return []domain.Permission{}, nil
	}
	if filter.Limit > 0 && end < len(result) {
		return result[start:end], nil
	}
	if start > 0 {
		return result[start:], nil
	}

	return result, nil
}

func (m *permRepoMock) Count(_ context.Context, filter port.PermissionFilter) (int, error) {
	count := 0
	for _, perm := range m.permissions {
		// Apply namespace filter
		if filter.ServiceNamespace != "" {
			parts := strings.Split(perm.Name, ":")
			if len(parts) != 2 || parts[0] != filter.ServiceNamespace {
				continue
			}
		}
		count++
	}
	return count, nil
}

func (m *permRepoMock) ListNamespaces(_ context.Context) ([]port.PermissionNamespaceSummary, error) {
	namespaceMap := make(map[string]int)
	for _, perm := range m.permissions {
		parts := strings.Split(perm.Name, ":")
		if len(parts) == 2 {
			namespaceMap[parts[0]]++
		}
	}

	summaries := make([]port.PermissionNamespaceSummary, 0, len(namespaceMap))
	for ns, count := range namespaceMap {
		summaries = append(summaries, port.PermissionNamespaceSummary{
			ServiceNamespace: ns,
			PermissionCount:  count,
		})
	}
	return summaries, nil
}

func (m *permRepoMock) ListByUser(_ context.Context, userID string) ([]domain.Permission, error) {
	if perms, ok := m.userPermissions[userID]; ok {
		return perms, nil
	}
	return []domain.Permission{}, nil
}

func (m *permRepoMock) ListByRole(_ context.Context, roleID string) ([]domain.Permission, error) {
	return []domain.Permission{}, nil
}

// Tests

func TestPermissionService_CreatePermission_Success(t *testing.T) {
	repo := &permRepoMock{
		userPermissions: map[string][]domain.Permission{
			"admin-1": {
				{ID: "p1", Name: PermissionManage},
			},
		},
	}

	service := NewPermissionService(repo)

	desc := "Read user data"
	input := CreatePermissionInput{
		ServiceNamespace: "user",
		Action:           "read",
		Description:      &desc,
	}

	perm, err := service.CreatePermission(context.Background(), "admin-1", input)
	if err != nil {
		t.Fatalf("CreatePermission failed: %v", err)
	}

	if perm.Name != "user:read" {
		t.Errorf("expected name 'user:read', got %s", perm.Name)
	}

	if perm.Description == nil || *perm.Description != desc {
		t.Errorf("expected description %q, got %v", desc, perm.Description)
	}
}

func TestPermissionService_CreatePermission_DeniedWithoutPermissions(t *testing.T) {
	repo := &permRepoMock{
		userPermissions: map[string][]domain.Permission{
			"user-1": {}, // No permissions
		},
	}

	service := NewPermissionService(repo)

	input := CreatePermissionInput{
		ServiceNamespace: "user",
		Action:           "read",
	}

	_, err := service.CreatePermission(context.Background(), "user-1", input)
	if !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("expected ErrPermissionDenied, got %v", err)
	}
}

func TestPermissionService_CreatePermission_InvalidNamespace(t *testing.T) {
	repo := &permRepoMock{
		userPermissions: map[string][]domain.Permission{
			"admin-1": {
				{ID: "p1", Name: PermissionManage},
			},
		},
	}

	service := NewPermissionService(repo)

	input := CreatePermissionInput{
		ServiceNamespace: "",
		Action:           "read",
	}

	_, err := service.CreatePermission(context.Background(), "admin-1", input)
	if !errors.Is(err, ErrInvalidNamespace) {
		t.Fatalf("expected ErrInvalidNamespace, got %v", err)
	}
}

func TestPermissionService_CreatePermission_InvalidAction(t *testing.T) {
	repo := &permRepoMock{
		userPermissions: map[string][]domain.Permission{
			"admin-1": {
				{ID: "p1", Name: PermissionManage},
			},
		},
	}

	service := NewPermissionService(repo)

	input := CreatePermissionInput{
		ServiceNamespace: "user",
		Action:           "",
	}

	_, err := service.CreatePermission(context.Background(), "admin-1", input)
	if !errors.Is(err, ErrInvalidAction) {
		t.Fatalf("expected ErrInvalidAction, got %v", err)
	}
}

func TestPermissionService_CreatePermission_DuplicateName(t *testing.T) {
	repo := &permRepoMock{
		permissionsByName: map[string]domain.Permission{
			"user:read": {ID: "perm-1", Name: "user:read"},
		},
		userPermissions: map[string][]domain.Permission{
			"admin-1": {
				{ID: "p1", Name: PermissionManage},
			},
		},
	}

	service := NewPermissionService(repo)

	input := CreatePermissionInput{
		ServiceNamespace: "user",
		Action:           "read",
	}

	_, err := service.CreatePermission(context.Background(), "admin-1", input)
	if !errors.Is(err, ErrPermissionExists) {
		t.Fatalf("expected ErrPermissionExists, got %v", err)
	}
}

func TestPermissionService_GetPermission_Success(t *testing.T) {
	expectedPerm := domain.Permission{ID: "perm-1", Name: "user:read"}
	repo := &permRepoMock{
		permissions: map[string]domain.Permission{
			"perm-1": expectedPerm,
		},
	}

	service := NewPermissionService(repo)

	perm, err := service.GetPermission(context.Background(), "perm-1")
	if err != nil {
		t.Fatalf("GetPermission failed: %v", err)
	}

	if perm.ID != expectedPerm.ID || perm.Name != expectedPerm.Name {
		t.Errorf("expected permission %+v, got %+v", expectedPerm, perm)
	}
}

func TestPermissionService_GetPermission_NotFound(t *testing.T) {
	repo := &permRepoMock{}
	service := NewPermissionService(repo)

	_, err := service.GetPermission(context.Background(), "nonexistent")
	if !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestPermissionService_UpdatePermission_Success(t *testing.T) {
	desc := "Original description"
	repo := &permRepoMock{
		permissions: map[string]domain.Permission{
			"perm-1": {ID: "perm-1", Name: "user:read", Description: &desc},
		},
		permissionsByName: map[string]domain.Permission{
			"user:read": {ID: "perm-1", Name: "user:read", Description: &desc},
		},
		userPermissions: map[string][]domain.Permission{
			"admin-1": {
				{ID: "p1", Name: PermissionManage},
			},
		},
	}

	service := NewPermissionService(repo)

	newNamespace := "survey"
	newAction := "create"
	newDesc := "Create surveys"
	input := UpdatePermissionInput{
		ID:               "perm-1",
		ServiceNamespace: &newNamespace,
		Action:           &newAction,
		Description:      &newDesc,
	}

	perm, err := service.UpdatePermission(context.Background(), "admin-1", input)
	if err != nil {
		t.Fatalf("UpdatePermission failed: %v", err)
	}

	if perm.Name != "survey:create" {
		t.Errorf("expected name 'survey:create', got %s", perm.Name)
	}

	if perm.Description == nil || *perm.Description != "Create surveys" {
		t.Errorf("expected description 'Create surveys', got %v", perm.Description)
	}
}

func TestPermissionService_UpdatePermission_DeniedWithoutPermissions(t *testing.T) {
	repo := &permRepoMock{
		permissions: map[string]domain.Permission{
			"perm-1": {ID: "perm-1", Name: "user:read"},
		},
		userPermissions: map[string][]domain.Permission{
			"user-1": {}, // No permissions
		},
	}

	service := NewPermissionService(repo)

	newNamespace := "survey"
	input := UpdatePermissionInput{ID: "perm-1", ServiceNamespace: &newNamespace}

	_, err := service.UpdatePermission(context.Background(), "user-1", input)
	if !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("expected ErrPermissionDenied, got %v", err)
	}
}

func TestPermissionService_DeletePermission_Success(t *testing.T) {
	repo := &permRepoMock{
		permissions: map[string]domain.Permission{
			"perm-1": {ID: "perm-1", Name: "user:read"},
		},
		userPermissions: map[string][]domain.Permission{
			"admin-1": {
				{ID: "p1", Name: PermissionManage},
			},
		},
	}

	service := NewPermissionService(repo)

	err := service.DeletePermission(context.Background(), "admin-1", "perm-1")
	if err != nil {
		t.Fatalf("DeletePermission failed: %v", err)
	}

	// Verify permission is deleted
	_, err = repo.GetByID(context.Background(), "perm-1")
	if !errors.Is(err, repository.ErrNotFound) {
		t.Errorf("expected permission to be deleted, but it still exists")
	}
}

func TestPermissionService_DeletePermission_DeniedWithoutPermissions(t *testing.T) {
	repo := &permRepoMock{
		permissions: map[string]domain.Permission{
			"perm-1": {ID: "perm-1", Name: "user:read"},
		},
		userPermissions: map[string][]domain.Permission{
			"user-1": {}, // No permissions
		},
	}

	service := NewPermissionService(repo)

	err := service.DeletePermission(context.Background(), "user-1", "perm-1")
	if !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("expected ErrPermissionDenied, got %v", err)
	}
}

func TestPermissionService_ListPermissions_AllNamespaces(t *testing.T) {
	repo := &permRepoMock{
		permissions: map[string]domain.Permission{
			"perm-1": {ID: "perm-1", Name: "user:read"},
			"perm-2": {ID: "perm-2", Name: "user:write"},
			"perm-3": {ID: "perm-3", Name: "survey:read"},
		},
		permissionsByName: map[string]domain.Permission{
			"user:read":   {ID: "perm-1", Name: "user:read"},
			"user:write":  {ID: "perm-2", Name: "user:write"},
			"survey:read": {ID: "perm-3", Name: "survey:read"},
		},
	}

	service := NewPermissionService(repo)

	input := ListPermissionsInput{
		ServiceNamespace: "",
		Limit:            10,
		Offset:           0,
	}

	result, err := service.ListPermissions(context.Background(), input)
	if err != nil {
		t.Fatalf("ListPermissions failed: %v", err)
	}

	if len(result.Permissions) != 3 {
		t.Errorf("expected 3 permissions, got %d", len(result.Permissions))
	}
}

func TestPermissionService_ListPermissions_FilterByNamespace(t *testing.T) {
	repo := &permRepoMock{
		permissions: map[string]domain.Permission{
			"perm-1": {ID: "perm-1", Name: "user:read"},
			"perm-2": {ID: "perm-2", Name: "user:write"},
			"perm-3": {ID: "perm-3", Name: "survey:read"},
		},
		permissionsByName: map[string]domain.Permission{
			"user:read":   {ID: "perm-1", Name: "user:read"},
			"user:write":  {ID: "perm-2", Name: "user:write"},
			"survey:read": {ID: "perm-3", Name: "survey:read"},
		},
	}

	service := NewPermissionService(repo)

	input := ListPermissionsInput{
		ServiceNamespace: "user",
		Limit:            10,
		Offset:           0,
	}

	result, err := service.ListPermissions(context.Background(), input)
	if err != nil {
		t.Fatalf("ListPermissions failed: %v", err)
	}

	if len(result.Permissions) != 2 {
		t.Errorf("expected 2 permissions for 'user' namespace, got %d", len(result.Permissions))
	}

	// Verify both are in user namespace
	for _, perm := range result.Permissions {
		if !strings.HasPrefix(perm.Name, "user:") {
			t.Errorf("expected permission in 'user' namespace, got %s", perm.Name)
		}
	}
}

func TestPermissionService_ListPermissions_Pagination(t *testing.T) {
	repo := &permRepoMock{
		permissions: map[string]domain.Permission{
			"perm-1": {ID: "perm-1", Name: "user:read"},
			"perm-2": {ID: "perm-2", Name: "user:write"},
			"perm-3": {ID: "perm-3", Name: "user:delete"},
		},
		permissionsByName: map[string]domain.Permission{
			"user:read":   {ID: "perm-1", Name: "user:read"},
			"user:write":  {ID: "perm-2", Name: "user:write"},
			"user:delete": {ID: "perm-3", Name: "user:delete"},
		},
	}

	service := NewPermissionService(repo)

	// First page
	input := ListPermissionsInput{
		ServiceNamespace: "",
		Limit:            2,
		Offset:           0,
	}

	result, err := service.ListPermissions(context.Background(), input)
	if err != nil {
		t.Fatalf("ListPermissions failed: %v", err)
	}

	if len(result.Permissions) != 2 {
		t.Errorf("expected 2 permissions on first page, got %d", len(result.Permissions))
	}

	// Second page
	input.Offset = 2

	result, err = service.ListPermissions(context.Background(), input)
	if err != nil {
		t.Fatalf("ListPermissions failed: %v", err)
	}

	if len(result.Permissions) != 1 {
		t.Errorf("expected 1 permission on second page, got %d", len(result.Permissions))
	}
}

func TestPermissionService_ListNamespaces_Success(t *testing.T) {
	repo := &permRepoMock{
		permissions: map[string]domain.Permission{
			"perm-1": {ID: "perm-1", Name: "user:read"},
			"perm-2": {ID: "perm-2", Name: "user:write"},
			"perm-3": {ID: "perm-3", Name: "survey:read"},
			"perm-4": {ID: "perm-4", Name: "role:create"},
		},
		permissionsByName: map[string]domain.Permission{
			"user:read":   {ID: "perm-1", Name: "user:read"},
			"user:write":  {ID: "perm-2", Name: "user:write"},
			"survey:read": {ID: "perm-3", Name: "survey:read"},
			"role:create": {ID: "perm-4", Name: "role:create"},
		},
	}

	service := NewPermissionService(repo)

	namespaces, err := service.ListNamespaces(context.Background())
	if err != nil {
		t.Fatalf("ListNamespaces failed: %v", err)
	}

	if len(namespaces) != 3 {
		t.Errorf("expected 3 namespaces, got %d", len(namespaces))
	}

	// Verify expected namespaces (order may vary)
	expectedNS := map[string]bool{"user": false, "survey": false, "role": false}
	for _, summary := range namespaces {
		if _, ok := expectedNS[summary.ServiceNamespace]; ok {
			expectedNS[summary.ServiceNamespace] = true
		}
	}

	for ns, found := range expectedNS {
		if !found {
			t.Errorf("expected namespace %q not found", ns)
		}
	}
}

func TestPermissionService_CanonicalName_Format(t *testing.T) {
	repo := &permRepoMock{
		userPermissions: map[string][]domain.Permission{
			"admin-1": {
				{ID: "p1", Name: PermissionManage},
			},
		},
	}

	service := NewPermissionService(repo)

	tests := []struct {
		namespace string
		action    string
		expected  string
	}{
		{"user", "read", "user:read"},
		{"survey", "create", "survey:create"},
		{"  spaces  ", "  trim  ", "spaces:trim"},
		{"UPPER", "CASE", "UPPER:CASE"},
	}

	for _, tt := range tests {
		input := CreatePermissionInput{
			ServiceNamespace: tt.namespace,
			Action:           tt.action,
		}

		perm, err := service.CreatePermission(context.Background(), "admin-1", input)
		if err != nil {
			t.Fatalf("CreatePermission failed for %s:%s: %v", tt.namespace, tt.action, err)
		}

		if perm.Name != tt.expected {
			t.Errorf("expected canonical name %q, got %q", tt.expected, perm.Name)
		}
	}
}
