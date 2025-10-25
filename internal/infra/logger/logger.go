package logger

import (
	"context"
	"regexp"
	"strings"
	"sync"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	lg   *zap.Logger
	once sync.Once
)

// New returns a singleton zap.Logger configured for structured logging.
func New(env string) (*zap.Logger, error) {
	var err error
	once.Do(func() {
		cfg := zap.NewProductionConfig()
		if env != "production" {
			cfg = zap.NewDevelopmentConfig()
			cfg.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
		}

		lg, err = cfg.Build()
	})

	return lg, err
}

// WithContext attaches request scoped fields to the logger.
func WithContext(ctx context.Context) *zap.Logger {
	if lg == nil {
		lz, _ := zap.NewDevelopment()
		return lz
	}

	if ctx == nil {
		return lg
	}

	return lg.With(zap.String("request_id", requestIDFromContext(ctx)))
}

func requestIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	if val, ok := ctx.Value(RequestIDKey{}).(string); ok {
		return val
	}
	return ""
}

// RequestIDKey is used to store a request identifier on the context.
type RequestIDKey struct{}

// PII Masking Functions (T014)

var (
	emailRegex = regexp.MustCompile(`^([^@]{1,3})[^@]*(@.+)$`)
	phoneRegex = regexp.MustCompile(`^(\+?\d{1,3})(\d{4,})(\d{4})$`)
)

// MaskEmail masks email addresses, showing first 3 characters and domain
// Example: john.doe@example.com -> joh***@example.com
func MaskEmail(email string) string {
	if email == "" {
		return ""
	}

	matches := emailRegex.FindStringSubmatch(email)
	if len(matches) == 3 {
		return matches[1] + "***" + matches[2]
	}

	// Fallback: just mask everything before @
	parts := strings.SplitN(email, "@", 2)
	if len(parts) == 2 {
		return "***@" + parts[1]
	}

	return "***"
}

// MaskPhone masks phone numbers, showing country code and last 4 digits
// Example: +1234567890 -> +123***7890
func MaskPhone(phone string) string {
	if phone == "" {
		return ""
	}

	matches := phoneRegex.FindStringSubmatch(phone)
	if len(matches) == 4 {
		return matches[1] + "***" + matches[3]
	}

	// Fallback: show last 4 digits only
	if len(phone) > 4 {
		return "***" + phone[len(phone)-4:]
	}

	return "***"
}

// MaskIP performs partial IP masking, showing first 2 octets for IPv4
// Example: 192.168.1.100 -> 192.168.*.*
// For IPv6, shows first 4 groups
// Example: 2001:0db8:85a3:0000:0000:8a2e:0370:7334 -> 2001:0db8:85a3:0000:*:*:*:*
func MaskIP(ip string) string {
	if ip == "" {
		return ""
	}

	// IPv4 masking
	if strings.Contains(ip, ".") {
		parts := strings.Split(ip, ".")
		if len(parts) == 4 {
			return parts[0] + "." + parts[1] + ".*.*"
		}
	}

	// IPv6 masking
	if strings.Contains(ip, ":") {
		parts := strings.Split(ip, ":")
		if len(parts) >= 4 {
			return strings.Join(parts[:4], ":") + ":*:*:*:*"
		}
	}

	return "***"
}

// MaskString generic masking for arbitrary sensitive strings
// Shows first and last 2 characters with *** in between
// Example: "secret123" -> "se***23"
func MaskString(s string) string {
	if s == "" {
		return ""
	}

	length := len(s)
	if length <= 4 {
		return "***"
	}

	return s[:2] + "***" + s[length-2:]
}
