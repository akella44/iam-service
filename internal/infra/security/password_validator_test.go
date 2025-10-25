package security

import (
	"errors"
	"testing"

	zxcvbn "github.com/nbutton23/zxcvbn-go"
)

func TestDefaultPasswordValidatorSuccess(t *testing.T) {
	validator := DefaultPasswordValidator()

	password := "C0mplex!Passphrase#2025"
	if strength := zxcvbn.PasswordStrength(password, nil); strength.Score < defaultMinZxcvbnScore {
		t.Fatalf("test password unexpectedly weak: score=%d", strength.Score)
	}
	if err := validator.Validate(password); err != nil {
		t.Fatalf("expected password to pass validation, got %v", err)
	}
}

func TestDefaultPasswordValidatorViolations(t *testing.T) {
	validator := DefaultPasswordValidator()

	assertViolation := func(password, expectedCode string) {
		err := validator.Validate(password)
		if err == nil {
			t.Fatalf("expected validation error for %s", expectedCode)
		}
		var vErr *PasswordValidationError
		if !errors.As(err, &vErr) {
			t.Fatalf("expected PasswordValidationError, got %T", err)
		}
		if vErr.Code != expectedCode {
			t.Fatalf("expected %s code, got %s", expectedCode, vErr.Code)
		}
	}

	assertViolation("Short1!", "min_length")
	assertViolation("lowercasepassword", "character_classes")
	assertViolation("Password123", "weak_password")
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
