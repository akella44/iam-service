package usecase

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/arklim/social-platform-iam/internal/core/domain"
	"github.com/arklim/social-platform-iam/internal/core/port"
	"github.com/arklim/social-platform-iam/internal/repository"
)

// Mock repositories for role testing

type roleRepoMock struct {
	roles            map[string]domain.Role
	rolesByName      map[string]domain.Role
	rolePermissions  map[string][]string
	roleUsers        map[string][]string
	createErr        error
	updateErr        error
	deleteErr        error
	assignPermsErr   error
	revokePermsErr   error
	assignUsersErr   error
	assignPermsCount int
	revokePermsCount int
}

func (m *roleRepoMock) Create(_ context.Context, role domain.Role) error {
	if m.createErr != nil {
		return m.createErr
	}
	if m.roles == nil {
		m.roles = make(map[string]domain.Role)
	}
	if m.rolesByName == nil {
		m.rolesByName = make(map[string]domain.Role)
	}
	m.roles[role.ID] = role
	m.rolesByName[role.Name] = role
	return nil
}

func (m *roleRepoMock) GetByID(_ context.Context, id string) (*domain.Role, error) {
	if role, ok := m.roles[id]; ok {
		return &role, nil
	}
	return nil, repository.ErrNotFound
}

func (m *roleRepoMock) GetByName(_ context.Context, name string) (*domain.Role, error) {
	if role, ok := m.rolesByName[name]; ok {
		return &role, nil
	}
	return nil, repository.ErrNotFound
}

func (m *roleRepoMock) List(_ context.Context) ([]domain.Role, error) {
	roles := make([]domain.Role, 0, len(m.roles))
	for _, role := range m.roles {
		roles = append(roles, role)
	}
	return roles, nil
}

func (m *roleRepoMock) Update(_ context.Context, role domain.Role) error {
	if m.updateErr != nil {
		return m.updateErr
	}
	if _, exists := m.roles[role.ID]; !exists {
		return repository.ErrNotFound
	}
	if m.rolesByName == nil {
		m.rolesByName = make(map[string]domain.Role)
	}
	m.roles[role.ID] = role
	m.rolesByName[role.Name] = role
	return nil
}

func (m *roleRepoMock) Delete(_ context.Context, id string) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	role, exists := m.roles[id]
	if !exists {
		return repository.ErrNotFound
	}
	delete(m.roles, id)
	delete(m.rolesByName, role.Name)
	return nil
}

func (m *roleRepoMock) AssignPermissions(_ context.Context, roleID string, permissionIDs []string) (int, error) {
	if m.assignPermsErr != nil {
		return 0, m.assignPermsErr
	}
	if m.rolePermissions == nil {
		m.rolePermissions = make(map[string][]string)
	}

	existing := m.rolePermissions[roleID]
	existingSet := make(map[string]struct{})
	for _, id := range existing {
		existingSet[id] = struct{}{}
	}

	assigned := 0
	for _, permID := range permissionIDs {
		if _, exists := existingSet[permID]; !exists {
			m.rolePermissions[roleID] = append(m.rolePermissions[roleID], permID)
			assigned++
		}
	}

	m.assignPermsCount = assigned
	return assigned, nil
}

func (m *roleRepoMock) RevokePermissions(_ context.Context, roleID string, permissionIDs []string) (int, error) {
	if m.revokePermsErr != nil {
		return 0, m.revokePermsErr
	}
	if m.rolePermissions == nil {
		return 0, nil
	}

	existing := m.rolePermissions[roleID]
	toRemove := make(map[string]struct{})
	for _, id := range permissionIDs {
		toRemove[id] = struct{}{}
	}

	filtered := make([]string, 0)
	revoked := 0
	for _, id := range existing {
		if _, shouldRemove := toRemove[id]; shouldRemove {
			revoked++
		} else {
			filtered = append(filtered, id)
		}
	}

	m.rolePermissions[roleID] = filtered
	m.revokePermsCount = revoked
	return revoked, nil
}

func (m *roleRepoMock) GetRolePermissions(_ context.Context, roleID string) ([]domain.Permission, error) {
	permIDs := m.rolePermissions[roleID]
	perms := make([]domain.Permission, 0, len(permIDs))
	for _, id := range permIDs {
		perms = append(perms, domain.Permission{ID: id, Name: "perm:" + id})
	}
	return perms, nil
}

func (m *roleRepoMock) AssignToUsers(_ context.Context, roleID string, userIDs []string) error {
	if m.assignUsersErr != nil {
		return m.assignUsersErr
	}
	if m.roleUsers == nil {
		m.roleUsers = make(map[string][]string)
	}
	m.roleUsers[roleID] = append(m.roleUsers[roleID], userIDs...)
	return nil
}

func (m *roleRepoMock) ListByUser(_ context.Context, userID string) ([]domain.Role, error) {
	roles := make([]domain.Role, 0)
	for roleID, users := range m.roleUsers {
		for _, uid := range users {
			if uid == userID {
				if role, ok := m.roles[roleID]; ok {
					roles = append(roles, role)
				}
				break
			}
		}
	}
	return roles, nil
}

type rolePermRepoMock struct {
	permissions       map[string]domain.Permission
	permissionsByName map[string]domain.Permission
	userPermissions   map[string][]domain.Permission
	createErr         error
}

func (m *rolePermRepoMock) Create(_ context.Context, perm domain.Permission) error {
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

func (m *rolePermRepoMock) GetByID(_ context.Context, id string) (*domain.Permission, error) {
	if perm, ok := m.permissions[id]; ok {
		return &perm, nil
	}
	return nil, repository.ErrNotFound
}

func (m *rolePermRepoMock) GetByName(_ context.Context, name string) (*domain.Permission, error) {
	if perm, ok := m.permissionsByName[name]; ok {
		return &perm, nil
	}
	return nil, repository.ErrNotFound
}

func (m *rolePermRepoMock) Update(_ context.Context, perm domain.Permission) error {
	if _, exists := m.permissions[perm.ID]; !exists {
		return repository.ErrNotFound
	}
	m.permissions[perm.ID] = perm
	m.permissionsByName[perm.Name] = perm
	return nil
}

func (m *rolePermRepoMock) Delete(_ context.Context, id string) error {
	perm, exists := m.permissions[id]
	if !exists {
		return repository.ErrNotFound
	}
	delete(m.permissions, id)
	delete(m.permissionsByName, perm.Name)
	return nil
}

func (m *rolePermRepoMock) List(_ context.Context, filter port.PermissionFilter) ([]domain.Permission, error) {
	perms := make([]domain.Permission, 0, len(m.permissions))
	for _, perm := range m.permissions {
		perms = append(perms, perm)
	}
	return perms, nil
}

func (m *rolePermRepoMock) Count(_ context.Context, filter port.PermissionFilter) (int, error) {
	return len(m.permissions), nil
}

func (m *rolePermRepoMock) ListNamespaces(_ context.Context) ([]port.PermissionNamespaceSummary, error) {
	return []port.PermissionNamespaceSummary{
		{ServiceNamespace: "user", PermissionCount: 1},
		{ServiceNamespace: "role", PermissionCount: 1},
		{ServiceNamespace: "permission", PermissionCount: 1},
	}, nil
}

func (m *rolePermRepoMock) ListByUser(_ context.Context, userID string) ([]domain.Permission, error) {
	if perms, ok := m.userPermissions[userID]; ok {
		return perms, nil
	}
	return []domain.Permission{}, nil
}

func (m *rolePermRepoMock) ListByRole(_ context.Context, roleID string) ([]domain.Permission, error) {
	return []domain.Permission{}, nil
}

type roleUserRepoMock struct {
	users map[string]domain.User
}

func (m *roleUserRepoMock) Create(_ context.Context, user domain.User) error {
	return errors.New("unexpected call: Create")
}

func (m *roleUserRepoMock) GetByID(_ context.Context, id string) (*domain.User, error) {
	if user, ok := m.users[id]; ok {
		return &user, nil
	}
	return nil, repository.ErrNotFound
}

func (m *roleUserRepoMock) GetByIdentifier(_ context.Context, identifier string) (*domain.User, error) {
	return nil, errors.New("unexpected call: GetByIdentifier")
}

func (m *roleUserRepoMock) UpdateStatus(_ context.Context, id string, status domain.UserStatus) error {
	return errors.New("unexpected call: UpdateStatus")
}

func (m *roleUserRepoMock) UpdatePassword(_ context.Context, id, hash, algo string, changedAt time.Time) error {
	return errors.New("unexpected call: UpdatePassword")
}

func (m *roleUserRepoMock) AssignRoles(_ context.Context, userID string, roleIDs []string) error {
	return errors.New("unexpected call: AssignRoles")
}

func (m *roleUserRepoMock) RevokeRoles(_ context.Context, userID string, roleIDs []string) error {
	return errors.New("unexpected call: RevokeRoles")
}

func (m *roleUserRepoMock) GetUserRoles(_ context.Context, userID string) ([]domain.UserRole, error) {
	return nil, errors.New("unexpected call: GetUserRoles")
}

func (m *roleUserRepoMock) ListPasswordHistory(_ context.Context, userID string, limit int) ([]domain.UserPasswordHistory, error) {
	return nil, errors.New("unexpected call: ListPasswordHistory")
}

func (m *roleUserRepoMock) AddPasswordHistory(_ context.Context, entry domain.UserPasswordHistory) error {
	return errors.New("unexpected call: AddPasswordHistory")
}

func (m *roleUserRepoMock) TrimPasswordHistory(_ context.Context, userID string, maxEntries int) error {
	return errors.New("unexpected call: TrimPasswordHistory")
}

func (m *roleUserRepoMock) Update(_ context.Context, user domain.User) error {
	return errors.New("unexpected call: Update")
}

func (m *roleUserRepoMock) SoftDelete(_ context.Context, id string) error {
	return errors.New("unexpected call: SoftDelete")
}

func (m *roleUserRepoMock) List(_ context.Context, filter port.UserFilter) ([]domain.User, error) {
	return nil, errors.New("unexpected call: List")
}

func (m *roleUserRepoMock) Count(_ context.Context, filter port.UserFilter) (int, error) {
	return 0, errors.New("unexpected call: Count")
}

// Tests

func TestRoleService_CreateRole_Success(t *testing.T) {
	roleRepo := &roleRepoMock{}
	permRepo := &rolePermRepoMock{
		userPermissions: map[string][]domain.Permission{
			"admin-1": {
				{ID: "p1", Name: PermissionRoleCreate},
				{ID: "p2", Name: PermissionRoleAssign},
			},
		},
	}
	userRepo := &roleUserRepoMock{
		users: map[string]domain.User{
			"user-1": {ID: "user-1", Username: "testuser"},
		},
	}

	service := NewRoleService(roleRepo, permRepo, userRepo)

	desc := "Test role"
	input := CreateRoleInput{
		Name:        "test-role",
		Description: &desc,
		Permissions: []PermissionInput{
			{Name: "user:read"},
		},
		AssignUserIDs: []string{"user-1"},
	}

	result, err := service.CreateRole(context.Background(), "admin-1", input)
	if err != nil {
		t.Fatalf("CreateRole failed: %v", err)
	}

	if result.Role.Name != "test-role" {
		t.Errorf("expected role name 'test-role', got %s", result.Role.Name)
	}

	if len(result.AssignedUserIDs) != 1 || result.AssignedUserIDs[0] != "user-1" {
		t.Errorf("expected assigned user 'user-1', got %v", result.AssignedUserIDs)
	}
}

func TestRoleService_CreateRole_DeniedWithoutPermissions(t *testing.T) {
	roleRepo := &roleRepoMock{}
	permRepo := &rolePermRepoMock{
		userPermissions: map[string][]domain.Permission{
			"user-1": {}, // No permissions
		},
	}
	userRepo := &roleUserRepoMock{}

	service := NewRoleService(roleRepo, permRepo, userRepo)

	input := CreateRoleInput{Name: "test-role"}

	_, err := service.CreateRole(context.Background(), "user-1", input)
	if !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("expected ErrPermissionDenied, got %v", err)
	}
}

func TestRoleService_CreateRole_DuplicateName(t *testing.T) {
	roleRepo := &roleRepoMock{
		rolesByName: map[string]domain.Role{
			"existing-role": {ID: "role-1", Name: "existing-role"},
		},
	}
	permRepo := &rolePermRepoMock{
		userPermissions: map[string][]domain.Permission{
			"admin-1": {
				{ID: "p1", Name: PermissionRoleCreate},
				{ID: "p2", Name: PermissionRoleAssign},
			},
		},
	}
	userRepo := &roleUserRepoMock{}

	service := NewRoleService(roleRepo, permRepo, userRepo)

	input := CreateRoleInput{Name: "existing-role"}

	_, err := service.CreateRole(context.Background(), "admin-1", input)
	if !errors.Is(err, ErrRoleExists) {
		t.Fatalf("expected ErrRoleExists, got %v", err)
	}
}

func TestRoleService_GetRole_Success(t *testing.T) {
	expectedRole := domain.Role{ID: "role-1", Name: "test-role"}
	roleRepo := &roleRepoMock{
		roles: map[string]domain.Role{
			"role-1": expectedRole,
		},
	}
	permRepo := &rolePermRepoMock{}
	userRepo := &roleUserRepoMock{}

	service := NewRoleService(roleRepo, permRepo, userRepo)

	role, err := service.GetRole(context.Background(), "role-1")
	if err != nil {
		t.Fatalf("GetRole failed: %v", err)
	}

	if role.ID != expectedRole.ID || role.Name != expectedRole.Name {
		t.Errorf("expected role %+v, got %+v", expectedRole, role)
	}
}

func TestRoleService_GetRole_NotFound(t *testing.T) {
	roleRepo := &roleRepoMock{}
	permRepo := &rolePermRepoMock{}
	userRepo := &roleUserRepoMock{}

	service := NewRoleService(roleRepo, permRepo, userRepo)

	_, err := service.GetRole(context.Background(), "nonexistent")
	if !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestRoleService_UpdateRole_Success(t *testing.T) {
	desc := "Original description"
	roleRepo := &roleRepoMock{
		roles: map[string]domain.Role{
			"role-1": {ID: "role-1", Name: "old-name", Description: &desc},
		},
	}
	permRepo := &rolePermRepoMock{
		userPermissions: map[string][]domain.Permission{
			"admin-1": {
				{ID: "p1", Name: PermissionRoleCreate},
			},
		},
	}
	userRepo := &roleUserRepoMock{}

	service := NewRoleService(roleRepo, permRepo, userRepo)

	newName := "new-name"
	newDesc := "New description"
	input := UpdateRoleInput{
		ID:          "role-1",
		Name:        &newName,
		Description: &newDesc,
	}

	role, err := service.UpdateRole(context.Background(), "admin-1", input)
	if err != nil {
		t.Fatalf("UpdateRole failed: %v", err)
	}

	if role.Name != "new-name" {
		t.Errorf("expected name 'new-name', got %s", role.Name)
	}

	if role.Description == nil || *role.Description != "New description" {
		t.Errorf("expected description 'New description', got %v", role.Description)
	}
}

func TestRoleService_UpdateRole_DeniedWithoutPermissions(t *testing.T) {
	roleRepo := &roleRepoMock{
		roles: map[string]domain.Role{
			"role-1": {ID: "role-1", Name: "test-role"},
		},
	}
	permRepo := &rolePermRepoMock{
		userPermissions: map[string][]domain.Permission{
			"user-1": {}, // No permissions
		},
	}
	userRepo := &roleUserRepoMock{}

	service := NewRoleService(roleRepo, permRepo, userRepo)

	newName := "new-name"
	input := UpdateRoleInput{ID: "role-1", Name: &newName}

	_, err := service.UpdateRole(context.Background(), "user-1", input)
	if !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("expected ErrPermissionDenied, got %v", err)
	}
}

func TestRoleService_DeleteRole_Success(t *testing.T) {
	roleRepo := &roleRepoMock{
		roles: map[string]domain.Role{
			"role-1": {ID: "role-1", Name: "test-role"},
		},
	}
	permRepo := &rolePermRepoMock{
		userPermissions: map[string][]domain.Permission{
			"admin-1": {
				{ID: "p1", Name: PermissionRoleCreate},
			},
		},
	}
	userRepo := &roleUserRepoMock{}

	service := NewRoleService(roleRepo, permRepo, userRepo)

	err := service.DeleteRole(context.Background(), "admin-1", "role-1")
	if err != nil {
		t.Fatalf("DeleteRole failed: %v", err)
	}

	// Verify role is deleted
	_, err = roleRepo.GetByID(context.Background(), "role-1")
	if !errors.Is(err, repository.ErrNotFound) {
		t.Errorf("expected role to be deleted, but it still exists")
	}
}

func TestRoleService_DeleteRole_DeniedWithoutPermissions(t *testing.T) {
	roleRepo := &roleRepoMock{
		roles: map[string]domain.Role{
			"role-1": {ID: "role-1", Name: "test-role"},
		},
	}
	permRepo := &rolePermRepoMock{
		userPermissions: map[string][]domain.Permission{
			"user-1": {}, // No permissions
		},
	}
	userRepo := &roleUserRepoMock{}

	service := NewRoleService(roleRepo, permRepo, userRepo)

	err := service.DeleteRole(context.Background(), "user-1", "role-1")
	if !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("expected ErrPermissionDenied, got %v", err)
	}
}

func TestRoleService_AssignPermissions_Success(t *testing.T) {
	roleRepo := &roleRepoMock{
		roles: map[string]domain.Role{
			"role-1": {ID: "role-1", Name: "test-role"},
		},
	}
	permRepo := &rolePermRepoMock{
		userPermissions: map[string][]domain.Permission{
			"admin-1": {
				{ID: "p1", Name: PermissionRoleAssign},
			},
		},
	}
	userRepo := &roleUserRepoMock{}

	service := NewRoleService(roleRepo, permRepo, userRepo)

	input := AssignPermissionsInput{
		RoleID:        "role-1",
		PermissionIDs: []string{"perm-1", "perm-2"},
	}

	count, err := service.AssignPermissions(context.Background(), "admin-1", input)
	if err != nil {
		t.Fatalf("AssignPermissions failed: %v", err)
	}

	if count != 2 {
		t.Errorf("expected 2 permissions assigned, got %d", count)
	}
}

func TestRoleService_AssignPermissions_DeniedWithoutPermissions(t *testing.T) {
	roleRepo := &roleRepoMock{
		roles: map[string]domain.Role{
			"role-1": {ID: "role-1", Name: "test-role"},
		},
	}
	permRepo := &rolePermRepoMock{
		userPermissions: map[string][]domain.Permission{
			"user-1": {}, // No permissions
		},
	}
	userRepo := &roleUserRepoMock{}

	service := NewRoleService(roleRepo, permRepo, userRepo)

	input := AssignPermissionsInput{
		RoleID:        "role-1",
		PermissionIDs: []string{"perm-1"},
	}

	_, err := service.AssignPermissions(context.Background(), "user-1", input)
	if !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("expected ErrPermissionDenied, got %v", err)
	}
}

func TestRoleService_RevokePermissions_Success(t *testing.T) {
	roleRepo := &roleRepoMock{
		roles: map[string]domain.Role{
			"role-1": {ID: "role-1", Name: "test-role"},
		},
		rolePermissions: map[string][]string{
			"role-1": {"perm-1", "perm-2", "perm-3"},
		},
	}
	permRepo := &rolePermRepoMock{
		userPermissions: map[string][]domain.Permission{
			"admin-1": {
				{ID: "p1", Name: PermissionRoleAssign},
			},
		},
	}
	userRepo := &roleUserRepoMock{}

	service := NewRoleService(roleRepo, permRepo, userRepo)

	input := RevokePermissionsInput{
		RoleID:        "role-1",
		PermissionIDs: []string{"perm-1", "perm-2"},
	}

	count, err := service.RevokePermissions(context.Background(), "admin-1", input)
	if err != nil {
		t.Fatalf("RevokePermissions failed: %v", err)
	}

	if count != 2 {
		t.Errorf("expected 2 permissions revoked, got %d", count)
	}

	// Verify only perm-3 remains
	remaining := roleRepo.rolePermissions["role-1"]
	if len(remaining) != 1 || remaining[0] != "perm-3" {
		t.Errorf("expected only perm-3 to remain, got %v", remaining)
	}
}

func TestRoleService_RevokePermissions_DeniedWithoutPermissions(t *testing.T) {
	roleRepo := &roleRepoMock{
		roles: map[string]domain.Role{
			"role-1": {ID: "role-1", Name: "test-role"},
		},
	}
	permRepo := &rolePermRepoMock{
		userPermissions: map[string][]domain.Permission{
			"user-1": {}, // No permissions
		},
	}
	userRepo := &roleUserRepoMock{}

	service := NewRoleService(roleRepo, permRepo, userRepo)

	input := RevokePermissionsInput{
		RoleID:        "role-1",
		PermissionIDs: []string{"perm-1"},
	}

	_, err := service.RevokePermissions(context.Background(), "user-1", input)
	if !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("expected ErrPermissionDenied, got %v", err)
	}
}

func TestRoleService_ListRoles_Success(t *testing.T) {
	roleRepo := &roleRepoMock{
		roles: map[string]domain.Role{
			"role-1": {ID: "role-1", Name: "admin"},
			"role-2": {ID: "role-2", Name: "user"},
		},
	}
	permRepo := &rolePermRepoMock{}
	userRepo := &roleUserRepoMock{}

	service := NewRoleService(roleRepo, permRepo, userRepo)

	roles, err := service.ListRoles(context.Background())
	if err != nil {
		t.Fatalf("ListRoles failed: %v", err)
	}

	if len(roles) != 2 {
		t.Errorf("expected 2 roles, got %d", len(roles))
	}
}
