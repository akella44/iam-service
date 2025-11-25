package usecase

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/arklim/social-platform-iam/internal/core/domain"
	"github.com/arklim/social-platform-iam/internal/core/port"
	"github.com/arklim/social-platform-iam/internal/infra/security"
	"github.com/arklim/social-platform-iam/internal/repository"
)

// Mock repositories for user CRUD and role assignment testing

type userCRUDRepoMock struct {
	users          map[string]domain.User
	createErr      error
	updateErr      error
	softDeleteErr  error
	assignRolesErr error
	revokeRolesErr error
	listResult     []domain.User
	countResult    int
	userRoles      map[string][]string
}

func (m *userCRUDRepoMock) Create(_ context.Context, user domain.User) error {
	if m.createErr != nil {
		return m.createErr
	}
	if m.users == nil {
		m.users = make(map[string]domain.User)
	}
	m.users[user.ID] = user
	return nil
}

func (m *userCRUDRepoMock) GetByID(_ context.Context, id string) (*domain.User, error) {
	if user, ok := m.users[id]; ok {
		return &user, nil
	}
	return nil, repository.ErrNotFound
}

func (m *userCRUDRepoMock) GetByIdentifier(_ context.Context, identifier string) (*domain.User, error) {
	for _, user := range m.users {
		if user.Username == identifier || user.Email == identifier {
			u := user
			return &u, nil
		}
	}
	return nil, repository.ErrNotFound
}

func (m *userCRUDRepoMock) UpdateStatus(_ context.Context, id string, status domain.UserStatus) error {
	user, ok := m.users[id]
	if !ok {
		return repository.ErrNotFound
	}
	user.Status = status
	m.users[id] = user
	return nil
}

func (m *userCRUDRepoMock) UpdatePassword(_ context.Context, id, hash, algo string, changedAt time.Time) error {
	user, ok := m.users[id]
	if !ok {
		return repository.ErrNotFound
	}
	user.PasswordHash = hash
	user.PasswordAlgo = algo
	user.LastPasswordChange = changedAt
	m.users[id] = user
	return nil
}

func (m *userCRUDRepoMock) Update(_ context.Context, user domain.User) error {
	if m.updateErr != nil {
		return m.updateErr
	}
	if _, exists := m.users[user.ID]; !exists {
		return repository.ErrNotFound
	}
	m.users[user.ID] = user
	return nil
}

func (m *userCRUDRepoMock) SoftDelete(_ context.Context, id string) error {
	if m.softDeleteErr != nil {
		return m.softDeleteErr
	}
	user, ok := m.users[id]
	if !ok {
		return repository.ErrNotFound
	}
	user.IsActive = false
	user.Status = domain.UserStatusDisabled
	m.users[id] = user
	return nil
}

func (m *userCRUDRepoMock) List(_ context.Context, filter port.UserFilter) ([]domain.User, error) {
	if m.listResult != nil {
		return m.listResult, nil
	}

	users := make([]domain.User, 0)
	for _, user := range m.users {
		// Apply filters
		if filter.Status != "" && user.Status != filter.Status {
			continue
		}
		if filter.IsActive != nil && user.IsActive != *filter.IsActive {
			continue
		}
		users = append(users, user)
	}

	// Apply pagination
	start := filter.Offset
	end := start + filter.Limit

	if start >= len(users) {
		return []domain.User{}, nil
	}
	if filter.Limit > 0 && end < len(users) {
		return users[start:end], nil
	}
	if start > 0 {
		return users[start:], nil
	}

	return users, nil
}

func (m *userCRUDRepoMock) Count(_ context.Context, filter port.UserFilter) (int, error) {
	if m.countResult > 0 {
		return m.countResult, nil
	}

	count := 0
	for _, user := range m.users {
		if filter.Status != "" && user.Status != filter.Status {
			continue
		}
		if filter.IsActive != nil && user.IsActive != *filter.IsActive {
			continue
		}
		count++
	}
	return count, nil
}

func (m *userCRUDRepoMock) AssignRoles(_ context.Context, userID string, roleIDs []string) error {
	if m.assignRolesErr != nil {
		return m.assignRolesErr
	}
	if m.userRoles == nil {
		m.userRoles = make(map[string][]string)
	}

	// Add unique role IDs
	existing := m.userRoles[userID]
	existingSet := make(map[string]struct{})
	for _, id := range existing {
		existingSet[id] = struct{}{}
	}

	for _, roleID := range roleIDs {
		if _, exists := existingSet[roleID]; !exists {
			m.userRoles[userID] = append(m.userRoles[userID], roleID)
		}
	}

	return nil
}

func (m *userCRUDRepoMock) RevokeRoles(_ context.Context, userID string, roleIDs []string) error {
	if m.revokeRolesErr != nil {
		return m.revokeRolesErr
	}

	existing := m.userRoles[userID]
	toRemove := make(map[string]struct{})
	for _, id := range roleIDs {
		toRemove[id] = struct{}{}
	}

	filtered := make([]string, 0)
	for _, id := range existing {
		if _, shouldRemove := toRemove[id]; !shouldRemove {
			filtered = append(filtered, id)
		}
	}

	m.userRoles[userID] = filtered
	return nil
}

func (m *userCRUDRepoMock) GetUserRoles(_ context.Context, userID string) ([]domain.UserRole, error) {
	roleIDs := m.userRoles[userID]
	userRoles := make([]domain.UserRole, 0, len(roleIDs))
	for _, roleID := range roleIDs {
		userRoles = append(userRoles, domain.UserRole{
			UserID: userID,
			RoleID: roleID,
		})
	}
	return userRoles, nil
}

func (m *userCRUDRepoMock) ListPasswordHistory(_ context.Context, userID string, limit int) ([]domain.UserPasswordHistory, error) {
	return []domain.UserPasswordHistory{}, nil
}

func (m *userCRUDRepoMock) AddPasswordHistory(_ context.Context, entry domain.UserPasswordHistory) error {
	return nil
}

func (m *userCRUDRepoMock) TrimPasswordHistory(_ context.Context, userID string, maxEntries int) error {
	return nil
}

type userCRUDPermRepoMock struct {
	userPermissions map[string][]domain.Permission
}

func (m *userCRUDPermRepoMock) Create(_ context.Context, perm domain.Permission) error {
	return errors.New("unexpected call: Create")
}

func (m *userCRUDPermRepoMock) GetByID(_ context.Context, id string) (*domain.Permission, error) {
	return nil, errors.New("unexpected call: GetByID")
}

func (m *userCRUDPermRepoMock) GetByName(_ context.Context, name string) (*domain.Permission, error) {
	return nil, errors.New("unexpected call: GetByName")
}

func (m *userCRUDPermRepoMock) Update(_ context.Context, perm domain.Permission) error {
	return errors.New("unexpected call: Update")
}

func (m *userCRUDPermRepoMock) Delete(_ context.Context, id string) error {
	return errors.New("unexpected call: Delete")
}

func (m *userCRUDPermRepoMock) List(_ context.Context, filter port.PermissionFilter) ([]domain.Permission, error) {
	return nil, errors.New("unexpected call: List")
}

func (m *userCRUDPermRepoMock) Count(_ context.Context, filter port.PermissionFilter) (int, error) {
	return 0, errors.New("unexpected call: Count")
}

func (m *userCRUDPermRepoMock) ListNamespaces(_ context.Context) ([]port.PermissionNamespaceSummary, error) {
	return nil, errors.New("unexpected call: ListNamespaces")
}

func (m *userCRUDPermRepoMock) ListByUser(_ context.Context, userID string) ([]domain.Permission, error) {
	if perms, ok := m.userPermissions[userID]; ok {
		return perms, nil
	}
	return []domain.Permission{}, nil
}

func (m *userCRUDPermRepoMock) ListByRole(_ context.Context, roleID string) ([]domain.Permission, error) {
	return nil, errors.New("unexpected call: ListByRole")
}

type userCRUDRoleRepoMock struct {
	roles map[string]domain.Role
}

func (m *userCRUDRoleRepoMock) Create(_ context.Context, role domain.Role) error {
	return errors.New("unexpected call: Create")
}

func (m *userCRUDRoleRepoMock) GetByID(_ context.Context, id string) (*domain.Role, error) {
	if role, ok := m.roles[id]; ok {
		return &role, nil
	}
	return nil, repository.ErrNotFound
}

func (m *userCRUDRoleRepoMock) GetByName(_ context.Context, name string) (*domain.Role, error) {
	return nil, errors.New("unexpected call: GetByName")
}

func (m *userCRUDRoleRepoMock) List(_ context.Context) ([]domain.Role, error) {
	return nil, errors.New("unexpected call: List")
}

func (m *userCRUDRoleRepoMock) Update(_ context.Context, role domain.Role) error {
	return errors.New("unexpected call: Update")
}

func (m *userCRUDRoleRepoMock) Delete(_ context.Context, id string) error {
	return errors.New("unexpected call: Delete")
}

func (m *userCRUDRoleRepoMock) AssignPermissions(_ context.Context, roleID string, permissionIDs []string) (int, error) {
	return 0, errors.New("unexpected call: AssignPermissions")
}

func (m *userCRUDRoleRepoMock) RevokePermissions(_ context.Context, roleID string, permissionIDs []string) (int, error) {
	return 0, errors.New("unexpected call: RevokePermissions")
}

func (m *userCRUDRoleRepoMock) GetRolePermissions(_ context.Context, roleID string) ([]domain.Permission, error) {
	return nil, errors.New("unexpected call: GetRolePermissions")
}

func (m *userCRUDRoleRepoMock) AssignToUsers(_ context.Context, roleID string, userIDs []string) error {
	return errors.New("unexpected call: AssignToUsers")
}

func (m *userCRUDRoleRepoMock) ListByUser(_ context.Context, userID string) ([]domain.Role, error) {
	return nil, errors.New("unexpected call: ListByUser")
}

type userCRUDEventPublisherMock struct {
	rolesAssignedEvents []domain.RolesAssignedEvent
	rolesRevokedEvents  []domain.RolesRevokedEvent
}

func (m *userCRUDEventPublisherMock) PublishUserRegistered(_ context.Context, event domain.UserRegisteredEvent) error {
	return nil
}

func (m *userCRUDEventPublisherMock) PublishPasswordChanged(_ context.Context, event domain.PasswordChangedEvent) error {
	return nil
}

func (m *userCRUDEventPublisherMock) PublishPasswordResetRequested(_ context.Context, event domain.PasswordResetRequestedEvent) error {
	return nil
}

func (m *userCRUDEventPublisherMock) PublishRolesAssigned(_ context.Context, event domain.RolesAssignedEvent) error {
	if m.rolesAssignedEvents == nil {
		m.rolesAssignedEvents = make([]domain.RolesAssignedEvent, 0)
	}
	m.rolesAssignedEvents = append(m.rolesAssignedEvents, event)
	return nil
}

func (m *userCRUDEventPublisherMock) PublishRolesRevoked(_ context.Context, event domain.RolesRevokedEvent) error {
	if m.rolesRevokedEvents == nil {
		m.rolesRevokedEvents = make([]domain.RolesRevokedEvent, 0)
	}
	m.rolesRevokedEvents = append(m.rolesRevokedEvents, event)
	return nil
}

func (m *userCRUDEventPublisherMock) PublishSessionRevoked(_ context.Context, event domain.SessionRevokedEvent) error {
	return nil
}

func (m *userCRUDEventPublisherMock) PublishSessionVersionBumped(_ context.Context, event domain.SessionVersionBumpedEvent) error {
	return nil
}

func (m *userCRUDEventPublisherMock) PublishSubjectVersionBumped(_ context.Context, event domain.SubjectVersionBumpedEvent) error {
	return nil
}

// Tests

func TestUserService_CreateUserAdmin_Success(t *testing.T) {
	userRepo := &userCRUDRepoMock{}
	permRepo := &userCRUDPermRepoMock{
		userPermissions: map[string][]domain.Permission{
			"admin-1": {
				{ID: "p1", Name: PermissionUserManage},
			},
		},
	}
	roleRepo := &userCRUDRoleRepoMock{}
	events := &userCRUDEventPublisherMock{}

	service := NewUserService(userRepo, permRepo, roleRepo, events, security.DefaultPasswordValidator())

	input := CreateUserInput{
		Username: "newuser",
		Email:    "newuser@example.com",
		Password: "C0mplex!Passphrase#2025",
		Status:   domain.UserStatusActive,
	}

	user, err := service.CreateUserAdmin(context.Background(), "admin-1", input)
	if err != nil {
		t.Fatalf("CreateUserAdmin failed: %v", err)
	}

	if user.Username != "newuser" {
		t.Errorf("expected username 'newuser', got %s", user.Username)
	}

	if user.Email != "newuser@example.com" {
		t.Errorf("expected email 'newuser@example.com', got %s", user.Email)
	}

	if user.Status != domain.UserStatusActive {
		t.Errorf("expected status active, got %s", user.Status)
	}
}

func TestUserService_CreateUserAdmin_DeniedWithoutPermissions(t *testing.T) {
	userRepo := &userCRUDRepoMock{}
	permRepo := &userCRUDPermRepoMock{
		userPermissions: map[string][]domain.Permission{
			"user-1": {}, // No permissions
		},
	}
	roleRepo := &userCRUDRoleRepoMock{}
	events := &userCRUDEventPublisherMock{}

	service := NewUserService(userRepo, permRepo, roleRepo, events, security.DefaultPasswordValidator())

	input := CreateUserInput{
		Username: "newuser",
		Email:    "newuser@example.com",
		Password: "C0mplex!Passphrase#2025",
	}

	_, err := service.CreateUserAdmin(context.Background(), "user-1", input)
	if !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("expected ErrPermissionDenied, got %v", err)
	}
}

func TestUserService_GetUser_Success(t *testing.T) {
	expectedUser := domain.User{
		ID:       "user-1",
		Username: "testuser",
		Email:    "test@example.com",
	}
	userRepo := &userCRUDRepoMock{
		users: map[string]domain.User{
			"user-1": expectedUser,
		},
	}
	permRepo := &userCRUDPermRepoMock{}
	roleRepo := &userCRUDRoleRepoMock{}
	events := &userCRUDEventPublisherMock{}

	service := NewUserService(userRepo, permRepo, roleRepo, events, nil)

	user, err := service.GetUser(context.Background(), "user-1")
	if err != nil {
		t.Fatalf("GetUser failed: %v", err)
	}

	if user.ID != expectedUser.ID || user.Username != expectedUser.Username {
		t.Errorf("expected user %+v, got %+v", expectedUser, user)
	}
}

func TestUserService_GetUser_NotFound(t *testing.T) {
	userRepo := &userCRUDRepoMock{}
	permRepo := &userCRUDPermRepoMock{}
	roleRepo := &userCRUDRoleRepoMock{}
	events := &userCRUDEventPublisherMock{}

	service := NewUserService(userRepo, permRepo, roleRepo, events, nil)

	_, err := service.GetUser(context.Background(), "nonexistent")
	if !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestUserService_UpdateUser_Success(t *testing.T) {
	userRepo := &userCRUDRepoMock{
		users: map[string]domain.User{
			"user-1": {ID: "user-1", Username: "oldname", Email: "old@example.com", Status: domain.UserStatusActive},
		},
	}
	permRepo := &userCRUDPermRepoMock{
		userPermissions: map[string][]domain.Permission{
			"admin-1": {
				{ID: "p1", Name: PermissionUserManage},
			},
		},
	}
	roleRepo := &userCRUDRoleRepoMock{}
	events := &userCRUDEventPublisherMock{}

	service := NewUserService(userRepo, permRepo, roleRepo, events, nil)

	newUsername := "newname"
	newEmail := "new@example.com"
	newStatus := domain.UserStatusPending
	input := UpdateUserInput{
		ID:       "user-1",
		Username: &newUsername,
		Email:    &newEmail,
		Status:   &newStatus,
	}

	user, err := service.UpdateUser(context.Background(), "admin-1", input)
	if err != nil {
		t.Fatalf("UpdateUser failed: %v", err)
	}

	if user.Username != "newname" {
		t.Errorf("expected username 'newname', got %s", user.Username)
	}

	if user.Email != "new@example.com" {
		t.Errorf("expected email 'new@example.com', got %s", user.Email)
	}

	if user.Status != domain.UserStatusPending {
		t.Errorf("expected status pending, got %s", user.Status)
	}
}

func TestUserService_UpdateUser_DeniedWithoutPermissions(t *testing.T) {
	userRepo := &userCRUDRepoMock{
		users: map[string]domain.User{
			"user-1": {ID: "user-1", Username: "testuser"},
		},
	}
	permRepo := &userCRUDPermRepoMock{
		userPermissions: map[string][]domain.Permission{
			"user-2": {}, // No permissions
		},
	}
	roleRepo := &userCRUDRoleRepoMock{}
	events := &userCRUDEventPublisherMock{}

	service := NewUserService(userRepo, permRepo, roleRepo, events, nil)

	newUsername := "newname"
	input := UpdateUserInput{ID: "user-1", Username: &newUsername}

	_, err := service.UpdateUser(context.Background(), "user-2", input)
	if !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("expected ErrPermissionDenied, got %v", err)
	}
}

func TestUserService_DeleteUser_Success(t *testing.T) {
	userRepo := &userCRUDRepoMock{
		users: map[string]domain.User{
			"user-1": {ID: "user-1", Username: "testuser", IsActive: true, Status: domain.UserStatusActive},
		},
	}
	permRepo := &userCRUDPermRepoMock{
		userPermissions: map[string][]domain.Permission{
			"admin-1": {
				{ID: "p1", Name: PermissionUserManage},
			},
		},
	}
	roleRepo := &userCRUDRoleRepoMock{}
	events := &userCRUDEventPublisherMock{}

	service := NewUserService(userRepo, permRepo, roleRepo, events, nil)

	err := service.DeleteUser(context.Background(), "admin-1", "user-1")
	if err != nil {
		t.Fatalf("DeleteUser failed: %v", err)
	}

	// Verify user is soft deleted
	user := userRepo.users["user-1"]
	if user.IsActive {
		t.Errorf("expected user to be inactive after soft delete")
	}
	if user.Status != domain.UserStatusDisabled {
		t.Errorf("expected user status to be disabled, got %s", user.Status)
	}
}

func TestUserService_DeleteUser_DeniedWithoutPermissions(t *testing.T) {
	userRepo := &userCRUDRepoMock{
		users: map[string]domain.User{
			"user-1": {ID: "user-1", Username: "testuser"},
		},
	}
	permRepo := &userCRUDPermRepoMock{
		userPermissions: map[string][]domain.Permission{
			"user-2": {}, // No permissions
		},
	}
	roleRepo := &userCRUDRoleRepoMock{}
	events := &userCRUDEventPublisherMock{}

	service := NewUserService(userRepo, permRepo, roleRepo, events, nil)

	err := service.DeleteUser(context.Background(), "user-2", "user-1")
	if !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("expected ErrPermissionDenied, got %v", err)
	}
}

func TestUserService_ListUsers_Success(t *testing.T) {
	userRepo := &userCRUDRepoMock{
		users: map[string]domain.User{
			"user-1": {ID: "user-1", Username: "user1", Status: domain.UserStatusActive, IsActive: true},
			"user-2": {ID: "user-2", Username: "user2", Status: domain.UserStatusPending, IsActive: true},
			"user-3": {ID: "user-3", Username: "user3", Status: domain.UserStatusActive, IsActive: false},
		},
	}
	permRepo := &userCRUDPermRepoMock{}
	roleRepo := &userCRUDRoleRepoMock{}
	events := &userCRUDEventPublisherMock{}

	service := NewUserService(userRepo, permRepo, roleRepo, events, nil)

	input := ListUsersInput{
		Status: domain.UserStatusActive,
		Limit:  10,
		Offset: 0,
	}

	result, err := service.ListUsers(context.Background(), input)
	if err != nil {
		t.Fatalf("ListUsers failed: %v", err)
	}

	if len(result.Users) != 2 {
		t.Errorf("expected 2 active users, got %d", len(result.Users))
	}
}

func TestUserService_ListUsers_FilterByIsActive(t *testing.T) {
	isActive := true
	userRepo := &userCRUDRepoMock{
		users: map[string]domain.User{
			"user-1": {ID: "user-1", Username: "user1", IsActive: true},
			"user-2": {ID: "user-2", Username: "user2", IsActive: false},
			"user-3": {ID: "user-3", Username: "user3", IsActive: true},
		},
	}
	permRepo := &userCRUDPermRepoMock{}
	roleRepo := &userCRUDRoleRepoMock{}
	events := &userCRUDEventPublisherMock{}

	service := NewUserService(userRepo, permRepo, roleRepo, events, nil)

	input := ListUsersInput{
		IsActive: &isActive,
		Limit:    10,
		Offset:   0,
	}

	result, err := service.ListUsers(context.Background(), input)
	if err != nil {
		t.Fatalf("ListUsers failed: %v", err)
	}

	if len(result.Users) != 2 {
		t.Errorf("expected 2 active users, got %d", len(result.Users))
	}

	for _, user := range result.Users {
		if !user.IsActive {
			t.Errorf("expected all users to be active, got inactive user %s", user.ID)
		}
	}
}

func TestUserService_AssignRoles_Success(t *testing.T) {
	userRepo := &userCRUDRepoMock{
		users: map[string]domain.User{
			"user-1": {ID: "user-1", Username: "testuser"},
		},
	}
	permRepo := &userCRUDPermRepoMock{
		userPermissions: map[string][]domain.Permission{
			"admin-1": {
				{ID: "p1", Name: PermissionRoleAssign},
			},
		},
	}
	roleRepo := &userCRUDRoleRepoMock{
		roles: map[string]domain.Role{
			"role-1": {ID: "role-1", Name: "admin"},
			"role-2": {ID: "role-2", Name: "user"},
		},
	}
	events := &userCRUDEventPublisherMock{}

	service := NewUserService(userRepo, permRepo, roleRepo, events, nil)

	input := AssignRolesToUserInput{
		UserID:  "user-1",
		RoleIDs: []string{"role-1", "role-2"},
	}

	err := service.AssignRoles(context.Background(), "admin-1", input)
	if err != nil {
		t.Fatalf("AssignRoles failed: %v", err)
	}

	// Verify roles were assigned
	roles := userRepo.userRoles["user-1"]
	if len(roles) != 2 {
		t.Errorf("expected 2 roles assigned, got %d", len(roles))
	}

	// Verify event was published
	if len(events.rolesAssignedEvents) != 1 {
		t.Errorf("expected 1 RolesAssigned event, got %d", len(events.rolesAssignedEvents))
	}

	event := events.rolesAssignedEvents[0]
	if event.UserID != "user-1" {
		t.Errorf("expected event for user-1, got %s", event.UserID)
	}
	if len(event.RolesAdded) != 2 {
		t.Errorf("expected 2 roles in event, got %d", len(event.RolesAdded))
	}
}

func TestUserService_AssignRoles_DeniedWithoutPermissions(t *testing.T) {
	userRepo := &userCRUDRepoMock{
		users: map[string]domain.User{
			"user-1": {ID: "user-1", Username: "testuser"},
		},
	}
	permRepo := &userCRUDPermRepoMock{
		userPermissions: map[string][]domain.Permission{
			"user-2": {}, // No permissions
		},
	}
	roleRepo := &userCRUDRoleRepoMock{}
	events := &userCRUDEventPublisherMock{}

	service := NewUserService(userRepo, permRepo, roleRepo, events, nil)

	input := AssignRolesToUserInput{
		UserID:  "user-1",
		RoleIDs: []string{"role-1"},
	}

	err := service.AssignRoles(context.Background(), "user-2", input)
	if !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("expected ErrPermissionDenied, got %v", err)
	}
}

func TestUserService_RevokeRoles_Success(t *testing.T) {
	userRepo := &userCRUDRepoMock{
		users: map[string]domain.User{
			"user-1": {ID: "user-1", Username: "testuser"},
		},
		userRoles: map[string][]string{
			"user-1": {"role-1", "role-2", "role-3"},
		},
	}
	permRepo := &userCRUDPermRepoMock{
		userPermissions: map[string][]domain.Permission{
			"admin-1": {
				{ID: "p1", Name: PermissionRoleAssign},
			},
		},
	}
	roleRepo := &userCRUDRoleRepoMock{
		roles: map[string]domain.Role{
			"role-1": {ID: "role-1", Name: "admin"},
			"role-2": {ID: "role-2", Name: "moderator"},
		},
	}
	events := &userCRUDEventPublisherMock{}

	service := NewUserService(userRepo, permRepo, roleRepo, events, nil)

	input := RevokeRolesFromUserInput{
		UserID:  "user-1",
		RoleIDs: []string{"role-1", "role-2"},
	}

	err := service.RevokeRoles(context.Background(), "admin-1", input)
	if err != nil {
		t.Fatalf("RevokeRoles failed: %v", err)
	}

	// Verify only role-3 remains
	roles := userRepo.userRoles["user-1"]
	if len(roles) != 1 || roles[0] != "role-3" {
		t.Errorf("expected only role-3 to remain, got %v", roles)
	}

	// Verify event was published
	if len(events.rolesRevokedEvents) != 1 {
		t.Errorf("expected 1 RolesRevoked event, got %d", len(events.rolesRevokedEvents))
	}

	event := events.rolesRevokedEvents[0]
	if event.UserID != "user-1" {
		t.Errorf("expected event for user-1, got %s", event.UserID)
	}
	if len(event.RolesRemoved) != 2 {
		t.Errorf("expected 2 roles in event, got %d", len(event.RolesRemoved))
	}
}

func TestUserService_RevokeRoles_DeniedWithoutPermissions(t *testing.T) {
	userRepo := &userCRUDRepoMock{
		users: map[string]domain.User{
			"user-1": {ID: "user-1", Username: "testuser"},
		},
	}
	permRepo := &userCRUDPermRepoMock{
		userPermissions: map[string][]domain.Permission{
			"user-2": {}, // No permissions
		},
	}
	roleRepo := &userCRUDRoleRepoMock{}
	events := &userCRUDEventPublisherMock{}

	service := NewUserService(userRepo, permRepo, roleRepo, events, nil)

	input := RevokeRolesFromUserInput{
		UserID:  "user-1",
		RoleIDs: []string{"role-1"},
	}

	err := service.RevokeRoles(context.Background(), "user-2", input)
	if !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("expected ErrPermissionDenied, got %v", err)
	}
}

func TestUserService_RoleAssignmentPublishesEvents(t *testing.T) {
	userRepo := &userCRUDRepoMock{
		users: map[string]domain.User{
			"user-1": {ID: "user-1", Username: "testuser"},
		},
		userRoles: map[string][]string{
			"user-1": {"role-1"},
		},
	}
	permRepo := &userCRUDPermRepoMock{
		userPermissions: map[string][]domain.Permission{
			"admin-1": {
				{ID: "p1", Name: PermissionRoleAssign},
			},
		},
	}
	roleRepo := &userCRUDRoleRepoMock{
		roles: map[string]domain.Role{
			"role-1": {ID: "role-1", Name: "admin"},
			"role-2": {ID: "role-2", Name: "moderator"},
		},
	}
	events := &userCRUDEventPublisherMock{}

	service := NewUserService(userRepo, permRepo, roleRepo, events, nil)

	// Assign role-2
	assignInput := AssignRolesToUserInput{
		UserID:  "user-1",
		RoleIDs: []string{"role-2"},
	}
	err := service.AssignRoles(context.Background(), "admin-1", assignInput)
	if err != nil {
		t.Fatalf("AssignRoles failed: %v", err)
	}

	// Verify RolesAssigned event
	if len(events.rolesAssignedEvents) != 1 {
		t.Fatalf("expected 1 RolesAssigned event, got %d", len(events.rolesAssignedEvents))
	}
	assignEvent := events.rolesAssignedEvents[0]
	if assignEvent.AssignedBy != "admin-1" {
		t.Errorf("expected AssignedBy to be admin-1, got %s", assignEvent.AssignedBy)
	}

	// Revoke role-1
	revokeInput := RevokeRolesFromUserInput{
		UserID:  "user-1",
		RoleIDs: []string{"role-1"},
	}
	err = service.RevokeRoles(context.Background(), "admin-1", revokeInput)
	if err != nil {
		t.Fatalf("RevokeRoles failed: %v", err)
	}

	// Verify RolesRevoked event
	if len(events.rolesRevokedEvents) != 1 {
		t.Fatalf("expected 1 RolesRevoked event, got %d", len(events.rolesRevokedEvents))
	}
	revokeEvent := events.rolesRevokedEvents[0]
	if revokeEvent.RevokedBy != "admin-1" {
		t.Errorf("expected RevokedBy to be admin-1, got %s", revokeEvent.RevokedBy)
	}
}
