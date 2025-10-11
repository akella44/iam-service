package usecase

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/arklim/social-platform-iam/internal/core/domain"
	"github.com/arklim/social-platform-iam/internal/core/port"
	"github.com/arklim/social-platform-iam/internal/infra/security"
	"github.com/arklim/social-platform-iam/internal/repository"
)

const PermissionUserPasswordChangeAny = "user:password:change:any"

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
	passwordValidator *security.PasswordValidator
}

// NewUserService constructs UserService.
func NewUserService(users port.UserRepository, permissions port.PermissionRepository, validator *security.PasswordValidator) *UserService {
	if validator == nil {
		validator = security.DefaultPasswordValidator()
	}
	return &UserService{users: users, permissions: permissions, passwordValidator: validator}
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
