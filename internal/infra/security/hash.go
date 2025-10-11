package security

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	saltLength          = 16
	argonTime    uint32 = 1
	argonMemory  uint32 = 64 * 1024
	argonThreads uint8  = 4
	argonKeyLen  uint32 = 32
)

// HashPassword generates Argon2id hash for the provided password.
// The resulting string is encoded as "salt:hash" with both components base64-encoded.
func HashPassword(password string) (string, error) {
	salt := make([]byte, saltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}

	hash := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	encodedSalt := base64.StdEncoding.EncodeToString(salt)
	encodedHash := base64.StdEncoding.EncodeToString(hash)

	return fmt.Sprintf("%s:%s", encodedSalt, encodedHash), nil
}

// VerifyPassword compares the provided password against a stored Argon2id hash.
func VerifyPassword(password, encoded string) (bool, error) {
	if password == "" || encoded == "" {
		return false, nil
	}

	parts := strings.Split(encoded, ":")
	if len(parts) != 2 {
		return false, fmt.Errorf("invalid password hash format")
	}

	salt, err := base64.StdEncoding.DecodeString(parts[0])
	if err != nil {
		return false, fmt.Errorf("decode salt: %w", err)
	}

	storedHash, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return false, fmt.Errorf("decode hash: %w", err)
	}

	computed := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, uint32(len(storedHash)))

	if subtle.ConstantTimeCompare(computed, storedHash) == 1 {
		return true, nil
	}

	return false, nil
}
