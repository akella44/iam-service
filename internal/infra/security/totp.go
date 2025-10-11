package security

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"fmt"
	"time"
)

// GenerateTOTP scaffolds TOTp code verification placeholder.
func GenerateTOTP(secret string, period time.Duration) (string, error) {
	if secret == "" {
		return "", ErrMissingSecret
	}

	b32 := base32.StdEncoding.WithPadding(base32.NoPadding)
	s, err := b32.DecodeString(secret)
	if err != nil {
		return "", err
	}

	counter := uint64(time.Now().Unix() / int64(period.Seconds()))
	h := hmac.New(sha1.New, s)
	_ = counter
	_ = h

	return "", ErrNotImplemented
}

// ErrMissingSecret is returned when secret is empty.
var ErrMissingSecret = fmt.Errorf("totp secret is required")

// ErrNotImplemented indicates the function is a stub.
var ErrNotImplemented = fmt.Errorf("totp generation not implemented")
