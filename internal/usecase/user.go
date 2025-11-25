package usecase

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	uuid "github.com/google/uuid"

	"github.com/arklim/social-platform-iam/internal/core/domain"
	"github.com/arklim/social-platform-iam/internal/core/port"
	"github.com/arklim/social-platform-iam/internal/infra/security"
	"github.com/arklim/social-platform-iam/internal/repository"
)

const (
	PermissionUserManage            = "user:manage"
	PermissionUserPasswordChangeAny = "user:password:change:any"
)

var (
	// ErrCurrentPasswordRequired indicates the current password must be provided for self-service changes.
	ErrCurrentPasswordRequired = errors.New("current password is required")
	// ErrCurrentPasswordInvalid indicates the provided current password is incorrect.
	ErrCurrentPasswordInvalid = errors.New("current password is incorrect")
	// ErrNewPasswordInvalid indicates the desired password fails validation (e.g., matches existing).
	ErrNewPasswordInvalid = errors.New("new password is invalid")
)

// ChangePasswordInput captures the payload for a password change request.
type ChangePasswordInput struct {
	TargetUserID    string
	CurrentPassword string
	NewPassword     string
}

// UserService handles user lifecycle operations.
type UserService struct {
	users             port.UserRepository
	permissions       port.PermissionRepository
	roles             port.RoleRepository
	events            port.EventPublisher
	passwordValidator *security.PasswordValidator
	sessionManager    *SessionService
}

// NewUserService constructs UserService.
func NewUserService(
	users port.UserRepository,
	permissions port.PermissionRepository,
	roles port.RoleRepository,
	events port.EventPublisher,
	validator *security.PasswordValidator,
) *UserService {
	if validator == nil {
		validator = security.DefaultPasswordValidator()
	}
	return &UserService{
		users:             users,
		permissions:       permissions,
		roles:             roles,
		events:            events,
		passwordValidator: validator,
	}
}

// WithSessionService wires the session manager used for version bumps on administrative actions.
func (s *UserService) WithSessionService(manager *SessionService) *UserService {
	s.sessionManager = manager
	return s
}

func (s *UserService) bumpUserSessions(ctx context.Context, userID, reason string) error {
	if s.sessionManager == nil {
		return nil
	}
	trimmed := strings.TrimSpace(userID)
	if trimmed == "" {
		return nil
	}
	if _, err := s.sessionManager.BumpActiveSessionVersions(ctx, trimmed, reason); err != nil {
		if errors.Is(err, ErrSessionNotFound) {
			return nil
		}
		return fmt.Errorf("bump session versions for user %s: %w", trimmed, err)
	}
	return nil
}

// CreateUser persists a new user.
func (s *UserService) CreateUser(ctx context.Context, user domain.User) error {
	return s.users.Create(ctx, user)
}

// ChangePassword updates a user's password after validating credentials and permissions.
func (s *UserService) ChangePassword(ctx context.Context, actorID string, input ChangePasswordInput) error {
	actorID = strings.TrimSpace(actorID)
	if actorID == "" {
		return fmt.Errorf("actor id is required")
	}

	newPassword := strings.TrimSpace(input.NewPassword)
	if newPassword == "" {
		return fmt.Errorf("new password is required")
	}

	if err := s.passwordValidator.Validate(newPassword); err != nil {
		return fmt.Errorf("%w: %v", ErrNewPasswordInvalid, err)
	}

	targetID := strings.TrimSpace(input.TargetUserID)
	if targetID == "" {
		targetID = actorID
	}

	current := strings.TrimSpace(input.CurrentPassword)

	selfChange := targetID == actorID
	if selfChange && current == "" {
		return ErrCurrentPasswordRequired
	}

	user, err := s.users.GetByID(ctx, targetID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return ErrUserNotFound
		}
		return fmt.Errorf("lookup user: %w", err)
	}

	if targetID != actorID {
		if s.permissions == nil {
			return ErrPermissionDenied
		}
		perms, err := s.permissions.ListByUser(ctx, actorID)
		if err != nil {
			return fmt.Errorf("list actor permissions: %w", err)
		}
		allowed := false
		for _, perm := range perms {
			if perm.Name == PermissionUserPasswordChangeAny {
				allowed = true
				break
			}
		}
		if !allowed {
			return ErrPermissionDenied
		}
	}

	if selfChange {
		validCurrent, err := security.VerifyPassword(current, user.PasswordHash)
		if err != nil {
			return fmt.Errorf("verify current password: %w", err)
		}
		if !validCurrent {
			return ErrCurrentPasswordInvalid
		}
	}

	if matches, err := security.VerifyPassword(newPassword, user.PasswordHash); err != nil {
		return fmt.Errorf("validate new password: %w", err)
	} else if matches {
		return ErrNewPasswordInvalid
	}

	hashed, err := security.HashPassword(newPassword)
	if err != nil {
		return fmt.Errorf("hash new password: %w", err)
	}

	changedAt := time.Now().UTC()
	if err := s.users.UpdatePassword(ctx, user.ID, hashed, "argon2id", changedAt); err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return ErrUserNotFound
		}
		return fmt.Errorf("update password: %w", err)
	}

	return nil
}

// CreateUserInput captures the payload for creating a user (admin function).
type CreateUserInput struct {
	Username string
	Email    string
	Phone    *string
	Password string
	Status   domain.UserStatus
}

// UpdateUserInput captures the payload for updating a user.
type UpdateUserInput struct {
	ID       string
	Username *string
	Email    *string
	Phone    *string
	Status   *domain.UserStatus
}

// ListUsersInput captures filters for listing users.
type ListUsersInput struct {
	Status   domain.UserStatus
	IsActive *bool
	Limit    int
	Offset   int
}

// ListUsersResult includes users and pagination metadata.
type ListUsersResult struct {
	Users  []domain.User
	Total  int
	Limit  int
	Offset int
}

// CreateUserAdmin creates a new user (admin-only function).
func (s *UserService) CreateUserAdmin(ctx context.Context, actorID string, input CreateUserInput) (*domain.User, error) {
	actorID = strings.TrimSpace(actorID)
	if actorID == "" {
		return nil, fmt.Errorf("actor id is required")
	}

	// Verify actor has permission
	if s.permissions != nil {
		actorPerms, err := s.permissions.ListByUser(ctx, actorID)
		if err != nil {
			return nil, fmt.Errorf("list actor permissions: %w", err)
		}

		hasPermission := false
		for _, perm := range actorPerms {
			if perm.Name == PermissionUserManage {
				hasPermission = true
				break
			}
		}

		if !hasPermission {
			return nil, ErrPermissionDenied
		}
	}

	// Validate input
	username := strings.TrimSpace(input.Username)
	if username == "" {
		return nil, fmt.Errorf("username is required")
	}

	email := strings.TrimSpace(input.Email)
	password := strings.TrimSpace(input.Password)
	if password == "" {
		return nil, fmt.Errorf("password is required")
	}

	// Validate password
	if err := s.passwordValidator.Validate(password); err != nil {
		return nil, fmt.Errorf("password validation failed: %w", err)
	}

	// Hash password
	passwordHash, err := security.HashPassword(password)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}

	now := time.Now().UTC()
	user := domain.User{
		ID:                 uuid.NewString(),
		Username:           username,
		Email:              email,
		Phone:              input.Phone,
		PasswordHash:       passwordHash,
		PasswordAlgo:       "argon2id",
		Status:             input.Status,
		IsActive:           true,
		RegisteredAt:       now,
		LastPasswordChange: now,
	}

	if user.Status == "" {
		user.Status = domain.UserStatusActive
	}

	if err := s.users.Create(ctx, user); err != nil {
		return nil, fmt.Errorf("create user: %w", err)
	}

	return &user, nil
}

// GetUser retrieves a user by ID.
func (s *UserService) GetUser(ctx context.Context, userID string) (*domain.User, error) {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return nil, fmt.Errorf("user id is required")
	}

	user, err := s.users.GetByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("get user: %w", err)
	}

	return user, nil
}

// UpdateUser modifies an existing user.
func (s *UserService) UpdateUser(ctx context.Context, actorID string, input UpdateUserInput) (*domain.User, error) {
	actorID = strings.TrimSpace(actorID)
	if actorID == "" {
		return nil, fmt.Errorf("actor id is required")
	}

	userID := strings.TrimSpace(input.ID)
	if userID == "" {
		return nil, fmt.Errorf("user id is required")
	}

	// Verify actor has permission
	if s.permissions != nil {
		actorPerms, err := s.permissions.ListByUser(ctx, actorID)
		if err != nil {
			return nil, fmt.Errorf("list actor permissions: %w", err)
		}

		hasPermission := false
		for _, perm := range actorPerms {
			if perm.Name == PermissionUserManage {
				hasPermission = true
				break
			}
		}

		if !hasPermission {
			return nil, ErrPermissionDenied
		}
	}

	// Get existing user
	user, err := s.users.GetByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("get user: %w", err)
	}
	originalStatus := user.Status

	// Update fields if provided
	if input.Username != nil {
		trimmed := strings.TrimSpace(*input.Username)
		if trimmed == "" {
			return nil, fmt.Errorf("username cannot be empty")
		}
		user.Username = trimmed
	}

	if input.Email != nil {
		user.Email = strings.TrimSpace(*input.Email)
	}

	if input.Phone != nil {
		user.Phone = input.Phone
	}

	if input.Status != nil {
		user.Status = *input.Status
	}

	if err := s.users.Update(ctx, *user); err != nil {
		return nil, fmt.Errorf("update user: %w", err)
	}

	if originalStatus != domain.UserStatusDisabled && user.Status == domain.UserStatusDisabled {
		if err := s.bumpUserSessions(ctx, user.ID, sessionReasonUserDisabled); err != nil {
			return nil, err
		}
	}

	return user, nil
}

// DeleteUser soft deletes a user by ID.
func (s *UserService) DeleteUser(ctx context.Context, actorID, userID string) error {
	actorID = strings.TrimSpace(actorID)
	if actorID == "" {
		return fmt.Errorf("actor id is required")
	}

	userID = strings.TrimSpace(userID)
	if userID == "" {
		return fmt.Errorf("user id is required")
	}

	// Verify actor has permission
	if s.permissions != nil {
		actorPerms, err := s.permissions.ListByUser(ctx, actorID)
		if err != nil {
			return fmt.Errorf("list actor permissions: %w", err)
		}

		hasPermission := false
		for _, perm := range actorPerms {
			if perm.Name == PermissionUserManage {
				hasPermission = true
				break
			}
		}

		if !hasPermission {
			return ErrPermissionDenied
		}
	}

	if err := s.users.SoftDelete(ctx, userID); err != nil {
		return fmt.Errorf("delete user: %w", err)
	}

	if err := s.bumpUserSessions(ctx, userID, sessionReasonUserDisabled); err != nil {
		return err
	}

	return nil
}

// ListUsers returns users with optional filtering and pagination.
func (s *UserService) ListUsers(ctx context.Context, input ListUsersInput) (*ListUsersResult, error) {
	filter := port.UserFilter{
		Status:   input.Status,
		IsActive: input.IsActive,
		Limit:    input.Limit,
		Offset:   input.Offset,
	}

	users, err := s.users.List(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}

	total, err := s.users.Count(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("count users: %w", err)
	}

	return &ListUsersResult{
		Users:  users,
		Total:  total,
		Limit:  input.Limit,
		Offset: input.Offset,
	}, nil
}

// AssignRolesToUserInput captures the payload for assigning roles to a user.
type AssignRolesToUserInput struct {
	UserID  string
	RoleIDs []string
}

// AssignRoles links roles to a user.
func (s *UserService) AssignRoles(ctx context.Context, actorID string, input AssignRolesToUserInput) error {
	actorID = strings.TrimSpace(actorID)
	if actorID == "" {
		return fmt.Errorf("actor id is required")
	}

	userID := strings.TrimSpace(input.UserID)
	if userID == "" {
		return fmt.Errorf("user id is required")
	}

	// Verify actor has permission
	if s.permissions != nil {
		actorPerms, err := s.permissions.ListByUser(ctx, actorID)
		if err != nil {
			return fmt.Errorf("list actor permissions: %w", err)
		}

		hasPermission := false
		for _, perm := range actorPerms {
			if perm.Name == PermissionRoleAssign {
				hasPermission = true
				break
			}
		}

		if !hasPermission {
			return ErrPermissionDenied
		}
	}

	// Verify user exists
	if _, err := s.users.GetByID(ctx, userID); err != nil {
		return fmt.Errorf("get user: %w", err)
	}

	// Filter to unique, non-empty role IDs
	uniqueRoleIDs := make([]string, 0, len(input.RoleIDs))
	seen := make(map[string]struct{}, len(input.RoleIDs))

	for _, roleID := range input.RoleIDs {
		trimmed := strings.TrimSpace(roleID)
		if trimmed == "" {
			continue
		}
		if _, exists := seen[trimmed]; exists {
			continue
		}
		seen[trimmed] = struct{}{}
		uniqueRoleIDs = append(uniqueRoleIDs, trimmed)
	}

	if err := s.users.AssignRoles(ctx, userID, uniqueRoleIDs); err != nil {
		return fmt.Errorf("assign roles: %w", err)
	}

	requiresReauth := false
	roleAssignments := make([]domain.RoleAssignment, 0, len(uniqueRoleIDs))

	if s.roles != nil && len(uniqueRoleIDs) > 0 {
		for _, roleID := range uniqueRoleIDs {
			role, err := s.roles.GetByID(ctx, roleID)
			if err != nil {
				if errors.Is(err, repository.ErrNotFound) {
					continue
				}
				return fmt.Errorf("get role %s: %w", roleID, err)
			}

			if !requiresReauth && s.sessionManager != nil {
				perms, perr := s.roles.GetRolePermissions(ctx, roleID)
				if perr != nil {
					return fmt.Errorf("get role permissions %s: %w", roleID, perr)
				}
				if permissionsRequireForcedReauth(perms) {
					requiresReauth = true
				}
			}

			roleAssignments = append(roleAssignments, domain.RoleAssignment{
				RoleID:   role.ID,
				RoleName: role.Name,
			})
		}
	}

	// Publish RolesAssigned event if event publisher is available
	if s.events != nil && len(roleAssignments) > 0 {
		event := domain.RolesAssignedEvent{
			EventID:    uuid.NewString(),
			UserID:     userID,
			RolesAdded: roleAssignments,
			AssignedBy: actorID,
			AssignedAt: time.Now().UTC(),
		}

		// Fire-and-forget: don't fail operation if event publishing fails
		_ = s.events.PublishRolesAssigned(ctx, event)
	}

	if requiresReauth {
		if err := s.bumpUserSessions(ctx, userID, sessionReasonElevatedPermissions); err != nil {
			return err
		}
	}

	return nil
}

// RevokeRolesFromUserInput captures the payload for revoking roles from a user.
type RevokeRolesFromUserInput struct {
	UserID  string
	RoleIDs []string
}

// RevokeRoles removes roles from a user.
func (s *UserService) RevokeRoles(ctx context.Context, actorID string, input RevokeRolesFromUserInput) error {
	actorID = strings.TrimSpace(actorID)
	if actorID == "" {
		return fmt.Errorf("actor id is required")
	}

	userID := strings.TrimSpace(input.UserID)
	if userID == "" {
		return fmt.Errorf("user id is required")
	}

	// Verify actor has permission
	if s.permissions != nil {
		actorPerms, err := s.permissions.ListByUser(ctx, actorID)
		if err != nil {
			return fmt.Errorf("list actor permissions: %w", err)
		}

		hasPermission := false
		for _, perm := range actorPerms {
			if perm.Name == PermissionRoleAssign {
				hasPermission = true
				break
			}
		}

		if !hasPermission {
			return ErrPermissionDenied
		}
	}

	// Verify user exists
	if _, err := s.users.GetByID(ctx, userID); err != nil {
		return fmt.Errorf("get user: %w", err)
	}

	// Filter to unique, non-empty role IDs
	uniqueRoleIDs := make([]string, 0, len(input.RoleIDs))
	seen := make(map[string]struct{}, len(input.RoleIDs))

	for _, roleID := range input.RoleIDs {
		trimmed := strings.TrimSpace(roleID)
		if trimmed == "" {
			continue
		}
		if _, exists := seen[trimmed]; exists {
			continue
		}
		seen[trimmed] = struct{}{}
		uniqueRoleIDs = append(uniqueRoleIDs, trimmed)
	}

	if err := s.users.RevokeRoles(ctx, userID, uniqueRoleIDs); err != nil {
		return fmt.Errorf("revoke roles: %w", err)
	}

	roleAssignments := make([]domain.RoleAssignment, 0, len(uniqueRoleIDs))
	if s.roles != nil && len(uniqueRoleIDs) > 0 {
		for _, roleID := range uniqueRoleIDs {
			role, err := s.roles.GetByID(ctx, roleID)
			if err != nil {
				if errors.Is(err, repository.ErrNotFound) {
					continue
				}
				return fmt.Errorf("get role %s: %w", roleID, err)
			}
			roleAssignments = append(roleAssignments, domain.RoleAssignment{
				RoleID:   role.ID,
				RoleName: role.Name,
			})
		}
	}

	if err := s.bumpUserSessions(ctx, userID, sessionReasonRolesRevoked); err != nil {
		return err
	}

	// Publish RolesRevoked event if event publisher is available
	if s.events != nil && len(roleAssignments) > 0 {
		event := domain.RolesRevokedEvent{
			EventID:      uuid.NewString(),
			UserID:       userID,
			RolesRemoved: roleAssignments,
			RevokedBy:    actorID,
			RevokedAt:    time.Now().UTC(),
			Reason:       "admin_action",
		}

		// Fire-and-forget: don't fail operation if event publishing fails
		_ = s.events.PublishRolesRevoked(ctx, event)
	}

	return nil
}
