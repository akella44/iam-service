package security

import (
	"fmt"
	"unicode"
)

// PasswordValidationError represents a single password policy violation.
type PasswordValidationError struct {
	Code    string
	Message string
}

// Error implements error for PasswordValidationError.
func (e *PasswordValidationError) Error() string {
	if e == nil {
		return ""
	}
	return e.Message
}

// PasswordRule validates a password according to a specific policy rule.
type PasswordRule interface {
	Validate(password string) error
}

// PasswordRuleFunc adapts a function to be used as a PasswordRule.
type PasswordRuleFunc func(password string) error

// Validate executes the underlying rule function.
func (f PasswordRuleFunc) Validate(password string) error {
	return f(password)
}

// PasswordValidator applies a sequence of password rules.
type PasswordValidator struct {
	rules []PasswordRule
}

// NewPasswordValidator constructs a validator with the provided rules.
func NewPasswordValidator(rules ...PasswordRule) *PasswordValidator {
	copied := make([]PasswordRule, len(rules))
	copy(copied, rules)
	return &PasswordValidator{rules: copied}
}

// Validate executes all rules and returns the first encountered violation.
func (v *PasswordValidator) Validate(password string) error {
	if v == nil {
		return fmt.Errorf("password validator not configured")
	}
	for _, rule := range v.rules {
		if err := rule.Validate(password); err != nil {
			return err
		}
	}
	return nil
}

// DefaultPasswordValidator returns the built-in validator used by the application.
func DefaultPasswordValidator() *PasswordValidator {
	return NewPasswordValidator(
		MinLengthRule(8),
		RequireLetterRule(),
		RequireDigitRule(),
	)
}

// MinLengthRule ensures the password has at least min characters.
func MinLengthRule(min int) PasswordRule {
	return PasswordRuleFunc(func(password string) error {
		if len([]rune(password)) < min {
			return &PasswordValidationError{
				Code:    "min_length",
				Message: fmt.Sprintf("password must be at least %d characters long", min),
			}
		}
		return nil
	})
}

// RequireLetterRule ensures the password contains at least one unicode letter.
func RequireLetterRule() PasswordRule {
	return PasswordRuleFunc(func(password string) error {
		for _, r := range password {
			if unicode.IsLetter(r) {
				return nil
			}
		}
		return &PasswordValidationError{
			Code:    "letter",
			Message: "password must include at least one letter",
		}
	})
}

// RequireDigitRule ensures the password contains at least one digit.
func RequireDigitRule() PasswordRule {
	return PasswordRuleFunc(func(password string) error {
		for _, r := range password {
			if unicode.IsDigit(r) {
				return nil
			}
		}
		return &PasswordValidationError{
			Code:    "digit",
			Message: "password must include at least one digit",
		}
	})
}

// RequireSymbolRule ensures the password contains at least one symbol (punctuation/mark).
func RequireSymbolRule() PasswordRule {
	return PasswordRuleFunc(func(password string) error {
		for _, r := range password {
			if unicode.IsSymbol(r) || unicode.IsPunct(r) {
				return nil
			}
		}
		return &PasswordValidationError{
			Code:    "symbol",
			Message: "password must include at least one symbol",
		}
	})
}

// RequireDifferentFrom ensures the new password differs from the provided comparator.
func RequireDifferentFrom(comparator string) PasswordRule {
	return PasswordRuleFunc(func(password string) error {
		if password == comparator {
			return &PasswordValidationError{
				Code:    "different",
				Message: "new password must be different from current password",
			}
		}
		return nil
	})
}
