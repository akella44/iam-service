package usecase

import (
	"context"
	"errors"
	"testing"

	"github.com/arklim/social-platform-iam/internal/core/domain"
	"github.com/arklim/social-platform-iam/internal/infra/security"
)

// rejectingPasswordPolicy always rejects passwords with the provided error.
type rejectingPasswordPolicy struct{ err error }

func (p rejectingPasswordPolicy) Validate(string, domain.PasswordContext) error {
	if p.err != nil {
		return p.err
	}
	return errors.New("password rejected")
}

func TestRegistrationService_RegisterUser_WeakPasswordRejected(t *testing.T) {
	t.Helper()

	userRepo := &mockUserRepository{}
	tokenRepo := &mockTokenRepository{}

	policyErr := errors.New("weak password")
	service := NewRegistrationService(userRepo, tokenRepo, rejectingPasswordPolicy{err: policyErr}, nil)

	_, _, err := service.RegisterUser(context.Background(), "dave", "dave@example.com", "", "weakpass")
	if err == nil {
		t.Fatalf("expected error for weak password")
	}
	if !errors.Is(err, ErrPasswordPolicyViolation) {
		t.Fatalf("expected ErrPasswordPolicyViolation, got %v", err)
	}

	if userRepo.createCalls != 0 {
		t.Fatalf("expected no user to be created when password rejected")
	}
	if tokenRepo.createCalls != 0 {
		t.Fatalf("expected no verification token when password rejected")
	}
}

func TestRegistrationService_RegisterUser_PreventsPasswordReuse(t *testing.T) {
	t.Helper()

	hashed, err := security.HashPassword("ReuseMe123!")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	userRepo := &mockUserRepository{
		listHistoryResult: []domain.UserPasswordHistory{{PasswordHash: hashed}},
	}
	tokenRepo := &mockTokenRepository{}

	service := NewRegistrationService(userRepo, tokenRepo, security.NewPasswordPolicy(), nil)

	_, _, err = service.RegisterUser(context.Background(), "erin", "erin@example.com", "", "ReuseMe123!")
	if err == nil {
		t.Fatalf("expected error when reusing password")
	}
	if !errors.Is(err, ErrPasswordPolicyViolation) {
		t.Fatalf("expected ErrPasswordPolicyViolation, got %v", err)
	}

	if userRepo.createCalls != 0 {
		t.Fatalf("expected Create not to be called on password reuse")
	}
	if tokenRepo.createCalls != 0 {
		t.Fatalf("expected CreateVerification not to run on password reuse")
	}
}
