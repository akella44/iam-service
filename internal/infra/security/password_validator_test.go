package security

import (
	"errors"
	"testing"
)

func TestDefaultPasswordValidatorSuccess(t *testing.T) {
	validator := DefaultPasswordValidator()

	if err := validator.Validate("StrongPass123"); err != nil {
		t.Fatalf("expected password to pass validation, got %v", err)
	}
}

func TestDefaultPasswordValidatorViolations(t *testing.T) {
	validator := DefaultPasswordValidator()

	if err := validator.Validate("short1"); err == nil {
		t.Fatalf("expected validation error for short password")
	} else {
		var vErr *PasswordValidationError
		if !errors.As(err, &vErr) {
			t.Fatalf("expected PasswordValidationError, got %T", err)
		}
		if vErr.Code != "min_length" {
			t.Fatalf("expected min_length code, got %s", vErr.Code)
		}
	}

	if err := validator.Validate("LongPassword"); err == nil {
		t.Fatalf("expected validation error for missing digit")
	} else {
		var vErr *PasswordValidationError
		if !errors.As(err, &vErr) {
			t.Fatalf("expected PasswordValidationError, got %T", err)
		}
		if vErr.Code != "digit" {
			t.Fatalf("expected digit code, got %s", vErr.Code)
		}
	}
}

func TestCustomPasswordValidator(t *testing.T) {
	validator := NewPasswordValidator(
		MinLengthRule(4),
		RequireSymbolRule(),
		RequireDifferentFrom("existing"),
	)

	if err := validator.Validate("existing"); err == nil {
		t.Fatalf("expected validation error when new password equals comparator")
	}

	if err := validator.Validate("diff"); err == nil {
		t.Fatalf("expected validation error for missing symbol")
	}

	if err := validator.Validate("diff!"); err != nil {
		t.Fatalf("expected password to pass custom validation, got %v", err)
	}
}
