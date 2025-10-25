package security

import (
	"fmt"

	"github.com/arklim/social-platform-iam/internal/core/domain"
)

const (
	defaultMinPasswordLength   = 10
	defaultMinCharacterClasses = 3
	defaultMinZxcvbnScore      = 3
)

// DefaultPasswordValidator returns the built-in validator enforcing the service password policy
// with length, character class, and zxcvbn strength checks.
func DefaultPasswordValidator() *PasswordValidator {
	return NewPasswordValidator(
		MinLengthRule(defaultMinPasswordLength),
		RequireCharacterClassesRule(defaultMinCharacterClasses),
		RequirePasswordStrengthRule(defaultMinZxcvbnScore),
	)
}

// NewPasswordValidatorWithContext allows callers to include additional user inputs (e.g. email) for strength checking.
func NewPasswordValidatorWithContext(userInputs ...string) *PasswordValidator {
	return NewPasswordValidator(
		MinLengthRule(defaultMinPasswordLength),
		RequireCharacterClassesRule(defaultMinCharacterClasses),
		RequirePasswordStrengthRule(defaultMinZxcvbnScore, userInputs...),
	)
}

// PasswordPolicy adapts the password validator to the domain-level policy interface.
type PasswordPolicy struct {
	factory func(inputs []string) *PasswordValidator
}

// NewPasswordPolicy builds a policy that accounts for contextual user inputs when validating passwords.
func NewPasswordPolicy() *PasswordPolicy {
	return &PasswordPolicy{
		factory: func(inputs []string) *PasswordValidator {
			return NewPasswordValidatorWithContext(inputs...)
		},
	}
}

// NewPasswordPolicyFromValidator wraps an existing validator instance without contextual enhancements.
func NewPasswordPolicyFromValidator(validator *PasswordValidator) *PasswordPolicy {
	if validator == nil {
		validator = DefaultPasswordValidator()
	}
	return &PasswordPolicy{
		factory: func(_ []string) *PasswordValidator {
			return validator
		},
	}
}

// Validate applies the configured validator to ensure the password meets policy requirements.
func (p *PasswordPolicy) Validate(password string, ctx domain.PasswordContext) error {
	if p == nil || p.factory == nil {
		return fmt.Errorf("password policy not configured")
	}

	inputs := make([]string, 0, 3)
	if trimmed := ctx.Username; trimmed != "" {
		inputs = append(inputs, trimmed)
	}
	if trimmed := ctx.Email; trimmed != "" {
		inputs = append(inputs, trimmed)
	}
	if ctx.Phone != nil && *ctx.Phone != "" {
		inputs = append(inputs, *ctx.Phone)
	}

	validator := p.factory(inputs)
	if validator == nil {
		return fmt.Errorf("password validator not configured")
	}

	return validator.Validate(password)
}
