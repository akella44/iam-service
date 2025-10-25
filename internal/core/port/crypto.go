package port

import "github.com/arklim/social-platform-iam/internal/core/domain"

// PasswordPolicyValidator enforces password strength requirements.
type PasswordPolicyValidator interface {
	Validate(password string, ctx domain.PasswordContext) error
}

// Argon2Params captures tunable parameters for the Argon2id hashing algorithm.
type Argon2Params struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

// PasswordHasher hashes and verifies secrets using the configured algorithm.
type PasswordHasher interface {
	Hash(password string) (string, error)
	Verify(password string, encoded string) (bool, error)
}

// ConfigurablePasswordHasher allows runtime adjustment of Argon2id parameters.
type ConfigurablePasswordHasher interface {
	PasswordHasher
	Configure(params Argon2Params) error
	Parameters() Argon2Params
}
