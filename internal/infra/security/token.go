package security

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// GenerateNumericCode returns a random numeric string of the given length.
func GenerateNumericCode(length int) (string, error) {
	if length <= 0 {
		return "", fmt.Errorf("length must be positive")
	}

	buf := make([]byte, length)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate code: %w", err)
	}

	digits := make([]byte, length)
	for i, b := range buf {
		digits[i] = '0' + (b % 10)
	}

	return string(digits), nil
}

// GenerateSecureToken returns a base64 URL-safe random string using the specified number of random bytes.
func GenerateSecureToken(byteLength int) (string, error) {
	if byteLength <= 0 {
		return "", fmt.Errorf("length must be positive")
	}

	buf := make([]byte, byteLength)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// HashToken calculates a SHA-256 hash of the provided value.
func HashToken(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

// TokenGenerator creates and signs JWTs.
type TokenGenerator struct {
	keyProvider KeyProvider
	kid         string
}

// NewTokenGenerator creates a new TokenGenerator.
func NewTokenGenerator(keyProvider KeyProvider, kid string) (*TokenGenerator, error) {
	return &TokenGenerator{
		keyProvider: keyProvider,
		kid:         kid,
	}, nil
}

// GetKID returns the Key ID used for signing.
func (t *TokenGenerator) GetKID() string {
	return t.kid
}
