package security

import (
	"encoding/base64"
	"strings"
	"testing"

	"golang.org/x/crypto/argon2"
)

func TestHashPasswordAndVerifySuccess(t *testing.T) {
	password := "correct horse battery staple"

	encoded, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword returned error: %v", err)
	}

	if encoded == "" {
		t.Fatal("HashPassword returned empty string")
	}

	parts := strings.Split(encoded, "$")
	if len(parts) != 5 {
		t.Fatalf("unexpected hash format: %q", encoded)
	}
	if parts[0] != argon2Variant {
		t.Fatalf("unexpected variant: %s", parts[0])
	}
	if parts[1] != argon2Version {
		t.Fatalf("unexpected version: %s", parts[1])
	}

	ok, err := VerifyPassword(password, encoded)
	if err != nil {
		t.Fatalf("VerifyPassword returned error: %v", err)
	}

	if !ok {
		t.Fatal("VerifyPassword returned false for correct password")
	}
}

func TestVerifyPasswordIncorrectPassword(t *testing.T) {
	password := "correct horse battery staple"
	wrongPassword := "Tr0ub4dor&3"

	encoded, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword returned error: %v", err)
	}

	ok, err := VerifyPassword(wrongPassword, encoded)
	if err != nil {
		t.Fatalf("VerifyPassword returned error: %v", err)
	}

	if ok {
		t.Fatal("VerifyPassword returned true for incorrect password")
	}
}

func TestVerifyPasswordInvalidFormat(t *testing.T) {
	if _, err := VerifyPassword("password", "invalid-format"); err == nil {
		t.Fatal("VerifyPassword expected to return error for invalid format")
	}
}

func TestVerifyPasswordEmptyInputs(t *testing.T) {
	ok, err := VerifyPassword("", "")
	if err != nil {
		t.Fatalf("VerifyPassword returned error for empty inputs: %v", err)
	}

	if ok {
		t.Fatal("VerifyPassword should return false for empty inputs")
	}
}

func TestVerifyPasswordLegacyFormat(t *testing.T) {
	password := "correct horse battery staple"
	salt := make([]byte, 16)
	for i := range salt {
		salt[i] = byte(i)
	}

	legacyHash := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)

	encoded := base64.StdEncoding.EncodeToString(salt) + ":" + base64.StdEncoding.EncodeToString(legacyHash)

	ok, err := VerifyPassword(password, encoded)
	if err != nil {
		t.Fatalf("VerifyPassword failed to parse legacy format: %v", err)
	}

	if !ok {
		t.Fatal("VerifyPassword did not validate legacy hash")
	}
}

func TestConfigureArgon2OverridesDefaults(t *testing.T) {
	original := CurrentArgon2Config()
	newCfg := Argon2Config{
		Memory:      128 * 1024,
		Iterations:  4,
		Parallelism: 2,
		SaltLength:  24,
		KeyLength:   48,
	}

	if err := ConfigureArgon2(newCfg); err != nil {
		t.Fatalf("ConfigureArgon2 returned error: %v", err)
	}

	encoded, err := HashPassword("change-me")
	if err != nil {
		t.Fatalf("HashPassword returned error: %v", err)
	}

	parts := strings.Split(encoded, "$")
	if !strings.Contains(parts[2], "m=131072") || !strings.Contains(parts[2], "t=4") || !strings.Contains(parts[2], "p=2") {
		t.Fatalf("encoded hash does not reflect configured parameters: %s", parts[2])
	}

	if err := ConfigureArgon2(original); err != nil {
		t.Fatalf("failed to restore original config: %v", err)
	}
}
