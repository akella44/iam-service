package security

import (
	"strings"
	"testing"
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

	if strings.Count(encoded, ":") != 1 {
		t.Fatalf("hash %q is not in expected 'salt:hash' format", encoded)
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
