package usecase

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/arklim/social-platform-iam/internal/core/domain"
	"github.com/arklim/social-platform-iam/internal/infra/security"
	"github.com/arklim/social-platform-iam/internal/repository"
)

type userRepoMock struct {
	user         domain.User
	updateCalled bool
	updateID     string
	updateHash   string
	updateAlgo   string
	updateAt     time.Time
}

func (m *userRepoMock) Create(context.Context, domain.User) error {
	return errors.New("unexpected call: Create")
}

func (m *userRepoMock) GetByID(_ context.Context, id string) (*domain.User, error) {
	if m.user.ID == "" || m.user.ID != id {
		return nil, repository.ErrNotFound
	}
	copy := m.user
	return &copy, nil
}

func (m *userRepoMock) GetByIdentifier(context.Context, string) (*domain.User, error) {
	return nil, errors.New("unexpected call: GetByIdentifier")
}

func (m *userRepoMock) UpdateStatus(context.Context, string, domain.UserStatus) error {
	return errors.New("unexpected call: UpdateStatus")
}

func (m *userRepoMock) UpdatePassword(_ context.Context, id string, hash string, algo string, changedAt time.Time) error {
	m.updateCalled = true
	m.updateID = id
	m.updateHash = hash
	m.updateAlgo = algo
	m.updateAt = changedAt
	return nil
}

type permissionRepoMock struct {
	userPermissions map[string][]domain.Permission
	listErr         error
}

func (m *permissionRepoMock) Create(context.Context, domain.Permission) error {
	return errors.New("unexpected call: Create permission")
}

func (m *permissionRepoMock) GetByName(context.Context, string) (*domain.Permission, error) {
	return nil, errors.New("unexpected call: GetByName")
}

func (m *permissionRepoMock) ListByRole(context.Context, string) ([]domain.Permission, error) {
	return nil, errors.New("unexpected call: ListByRole")
}

func (m *permissionRepoMock) ListByUser(_ context.Context, userID string) ([]domain.Permission, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	return m.userPermissions[userID], nil
}

func TestUserServiceChangePasswordSelfSuccess(t *testing.T) {
	currentHash, err := security.HashPassword("Current-123")
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}

	repo := &userRepoMock{user: domain.User{ID: "user-1", PasswordHash: currentHash}}
	service := NewUserService(repo, nil, security.DefaultPasswordValidator())

	if err := service.ChangePassword(context.Background(), "user-1", ChangePasswordInput{
		CurrentPassword: "Current-123",
		NewPassword:     "Newpass456",
	}); err != nil {
		t.Fatalf("ChangePassword returned error: %v", err)
	}

	if !repo.updateCalled {
		t.Fatalf("expected UpdatePassword to be called")
	}
	if repo.updateID != "user-1" {
		t.Fatalf("expected update for user user-1, got %s", repo.updateID)
	}
	if repo.updateAlgo != "argon2id" {
		t.Fatalf("expected argon2id algorithm, got %s", repo.updateAlgo)
	}
	if repo.updateAt.IsZero() {
		t.Fatalf("expected last_password_change timestamp to be set")
	}

	if ok, err := security.VerifyPassword("Newpass456", repo.updateHash); err != nil || !ok {
		t.Fatalf("expected stored hash to match new password")
	}
	if ok, err := security.VerifyPassword("Current-123", repo.updateHash); err != nil {
		t.Fatalf("verify old password against new hash failed: %v", err)
	} else if ok {
		t.Fatalf("expected new hash to differ from current password")
	}
}

func TestUserServiceChangePasswordOtherNoPermission(t *testing.T) {
	currentHash, err := security.HashPassword("Secret123")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	repo := &userRepoMock{user: domain.User{ID: "user-2", PasswordHash: currentHash}}
	perms := &permissionRepoMock{userPermissions: map[string][]domain.Permission{}}
	service := NewUserService(repo, perms, security.DefaultPasswordValidator())

	err = service.ChangePassword(context.Background(), "admin", ChangePasswordInput{
		TargetUserID:    "user-2",
		CurrentPassword: "Secret123",
		NewPassword:     "NewSecret456",
	})
	if !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("expected ErrPermissionDenied, got %v", err)
	}
	if repo.updateCalled {
		t.Fatalf("expected UpdatePassword not to be called")
	}
}

func TestUserServiceChangePasswordOtherWithPermission(t *testing.T) {
	currentHash, err := security.HashPassword("Secret123")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	repo := &userRepoMock{user: domain.User{ID: "user-2", PasswordHash: currentHash}}
	perms := &permissionRepoMock{userPermissions: map[string][]domain.Permission{
		"admin": {{Name: PermissionUserPasswordChangeAny}},
	}}

	service := NewUserService(repo, perms, security.DefaultPasswordValidator())

	if err := service.ChangePassword(context.Background(), "admin", ChangePasswordInput{
		TargetUserID:    "user-2",
		CurrentPassword: "",
		NewPassword:     "NewSecret456",
	}); err != nil {
		t.Fatalf("ChangePassword returned error: %v", err)
	}

	if !repo.updateCalled {
		t.Fatalf("expected UpdatePassword to be called")
	}
	if repo.updateID != "user-2" {
		t.Fatalf("expected update for user-2, got %s", repo.updateID)
	}
}

func TestUserServiceChangePasswordInvalidCurrent(t *testing.T) {
	hash, err := security.HashPassword("Correct123")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	repo := &userRepoMock{user: domain.User{ID: "user-1", PasswordHash: hash}}
	service := NewUserService(repo, nil, security.DefaultPasswordValidator())

	err = service.ChangePassword(context.Background(), "user-1", ChangePasswordInput{
		CurrentPassword: "Wrong123",
		NewPassword:     "Newpass456",
	})
	if !errors.Is(err, ErrCurrentPasswordInvalid) {
		t.Fatalf("expected ErrCurrentPasswordInvalid, got %v", err)
	}
	if repo.updateCalled {
		t.Fatalf("expected UpdatePassword not to be called")
	}
}

func TestUserServiceChangePasswordSamePassword(t *testing.T) {
	hash, err := security.HashPassword("Samepass123")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	repo := &userRepoMock{user: domain.User{ID: "user-1", PasswordHash: hash}}
	service := NewUserService(repo, nil, security.DefaultPasswordValidator())

	err = service.ChangePassword(context.Background(), "user-1", ChangePasswordInput{
		CurrentPassword: "Samepass123",
		NewPassword:     "Samepass123",
	})
	if !errors.Is(err, ErrNewPasswordInvalid) {
		t.Fatalf("expected ErrNewPasswordInvalid, got %v", err)
	}
	if repo.updateCalled {
		t.Fatalf("expected UpdatePassword not to be called")
	}
}

func TestUserServiceChangePasswordSelfMissingCurrent(t *testing.T) {
	hash, err := security.HashPassword("CurrentPass123")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	repo := &userRepoMock{user: domain.User{ID: "user-1", PasswordHash: hash}}
	service := NewUserService(repo, nil, security.DefaultPasswordValidator())

	err = service.ChangePassword(context.Background(), "user-1", ChangePasswordInput{
		CurrentPassword: "",
		NewPassword:     "Newpass456",
	})
	if !errors.Is(err, ErrCurrentPasswordRequired) {
		t.Fatalf("expected ErrCurrentPasswordRequired, got %v", err)
	}
	if repo.updateCalled {
		t.Fatalf("expected UpdatePassword not to be called")
	}
}

func TestUserServiceChangePasswordPolicyViolation(t *testing.T) {
	hash, err := security.HashPassword("Validpass123")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	repo := &userRepoMock{user: domain.User{ID: "user-1", PasswordHash: hash}}
	service := NewUserService(repo, nil, security.DefaultPasswordValidator())

	err = service.ChangePassword(context.Background(), "user-1", ChangePasswordInput{
		CurrentPassword: "Validpass123",
		NewPassword:     "short",
	})
	if !errors.Is(err, ErrNewPasswordInvalid) {
		t.Fatalf("expected ErrNewPasswordInvalid, got %v", err)
	}
	if repo.updateCalled {
		t.Fatalf("expected UpdatePassword not to be called")
	}
}
