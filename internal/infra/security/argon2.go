package security

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/crypto/argon2"
)

const (
	argon2Variant = "argon2id"
	argon2Version = "v=19"
)

var (
	errInvalidHashFormat = errors.New("argon2: invalid encoded hash format")
	errInvalidConfig     = errors.New("argon2: invalid configuration")
)

// Argon2Config defines tunable parameters for Argon2id password hashing.
type Argon2Config struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

var (
	defaultArgon2Config = Argon2Config{
		Memory:      64 * 1024,
		Iterations:  3,
		Parallelism: 4,
		SaltLength:  16,
		KeyLength:   32,
	}

	activeArgon2Config = defaultArgon2Config
	argon2ConfigMu     sync.RWMutex
)

// DefaultArgon2Config returns the library default Argon2id configuration.
func DefaultArgon2Config() Argon2Config {
	return defaultArgon2Config
}

// CurrentArgon2Config returns the currently active Argon2 configuration.
func CurrentArgon2Config() Argon2Config {
	argon2ConfigMu.RLock()
	defer argon2ConfigMu.RUnlock()
	return activeArgon2Config
}

// ConfigureArgon2 sets the active Argon2 configuration after validation.
func ConfigureArgon2(cfg Argon2Config) error {
	if err := validateArgon2Config(cfg); err != nil {
		return err
	}

	argon2ConfigMu.Lock()
	activeArgon2Config = cfg
	argon2ConfigMu.Unlock()
	return nil
}

func validateArgon2Config(cfg Argon2Config) error {
	if cfg.Memory < 8*1024 {
		return fmt.Errorf("%w: memory must be at least 8192", errInvalidConfig)
	}
	if cfg.Iterations == 0 {
		return fmt.Errorf("%w: iterations must be greater than zero", errInvalidConfig)
	}
	if cfg.Parallelism == 0 {
		return fmt.Errorf("%w: parallelism must be greater than zero", errInvalidConfig)
	}
	if cfg.SaltLength < 8 {
		return fmt.Errorf("%w: salt length must be at least 8 bytes", errInvalidConfig)
	}
	if cfg.KeyLength < 16 {
		return fmt.Errorf("%w: key length must be at least 16 bytes", errInvalidConfig)
	}
	return nil
}

// HashPassword generates an Argon2id hash for the provided password.
// The returned value embeds the parameters, salt, and hash in a portable format.
func HashPassword(password string) (string, error) {
	cfg := CurrentArgon2Config()

	salt := make([]byte, cfg.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("argon2: generate salt: %w", err)
	}

	sum := argon2.IDKey([]byte(password), salt, cfg.Iterations, cfg.Memory, cfg.Parallelism, cfg.KeyLength)

	encodedSalt := base64.RawStdEncoding.EncodeToString(salt)
	encodedHash := base64.RawStdEncoding.EncodeToString(sum)

	// Format: argon2id$v=19$m=<memory>,t=<iterations>,p=<parallelism>$<salt>$<hash>
	encoded := strings.Join([]string{
		argon2Variant,
		argon2Version,
		fmt.Sprintf("m=%d,t=%d,p=%d", cfg.Memory, cfg.Iterations, cfg.Parallelism),
		encodedSalt,
		encodedHash,
	}, "$")

	return encoded, nil
}

// VerifyPassword compares the provided password against the stored Argon2 hash.
func VerifyPassword(password, encoded string) (bool, error) {
	if password == "" || encoded == "" {
		return false, nil
	}

	params, salt, expected, err := decodeArgon2Hash(encoded)
	if err != nil {
		return false, err
	}

	computed := argon2.IDKey([]byte(password), salt, params.Iterations, params.Memory, params.Parallelism, uint32(len(expected)))
	return subtle.ConstantTimeCompare(computed, expected) == 1, nil
}

func decodeArgon2Hash(encoded string) (Argon2Config, []byte, []byte, error) {
	if strings.Contains(encoded, "$") {
		return decodeStructuredHash(encoded)
	}

	// Legacy format: salt:hash using default parameters.
	parts := strings.Split(encoded, ":")
	if len(parts) != 2 {
		return Argon2Config{}, nil, nil, errInvalidHashFormat
	}

	salt, err := base64.StdEncoding.DecodeString(parts[0])
	if err != nil {
		return Argon2Config{}, nil, nil, fmt.Errorf("argon2: decode salt: %w", err)
	}

	hash, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return Argon2Config{}, nil, nil, fmt.Errorf("argon2: decode hash: %w", err)
	}

	legacy := Argon2Config{
		Memory:      64 * 1024,
		Iterations:  1,
		Parallelism: 4,
	}
	return legacy, salt, hash, nil
}

func decodeStructuredHash(encoded string) (Argon2Config, []byte, []byte, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 5 {
		return Argon2Config{}, nil, nil, errInvalidHashFormat
	}

	if parts[0] != argon2Variant {
		return Argon2Config{}, nil, nil, fmt.Errorf("argon2: unexpected variant %q", parts[0])
	}

	// We accept any version string but require v=19 when provided.
	if parts[1] != argon2Version {
		return Argon2Config{}, nil, nil, fmt.Errorf("argon2: unsupported version %q", parts[1])
	}

	memory, iterations, parallelism, err := parseArgon2Params(parts[2])
	if err != nil {
		return Argon2Config{}, nil, nil, err
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil {
		return Argon2Config{}, nil, nil, fmt.Errorf("argon2: decode salt: %w", err)
	}

	hash, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return Argon2Config{}, nil, nil, fmt.Errorf("argon2: decode hash: %w", err)
	}

	cfg := Argon2Config{
		Memory:      memory,
		Iterations:  iterations,
		Parallelism: parallelism,
		SaltLength:  uint32(len(salt)),
		KeyLength:   uint32(len(hash)),
	}

	if err := validateArgon2Config(cfg); err != nil {
		return Argon2Config{}, nil, nil, err
	}

	return cfg, salt, hash, nil
}

func parseArgon2Params(segment string) (uint32, uint32, uint8, error) {
	entries := strings.Split(segment, ",")
	if len(entries) != 3 {
		return 0, 0, 0, errInvalidHashFormat
	}

	var (
		memory      uint32
		iterations  uint32
		parallelism uint8
		err         error
	)

	for _, entry := range entries {
		kv := strings.Split(entry, "=")
		if len(kv) != 2 {
			return 0, 0, 0, errInvalidHashFormat
		}

		key := kv[0]
		value := kv[1]

		switch key {
		case "m":
			var v uint64
			v, err = strconv.ParseUint(value, 10, 32)
			memory = uint32(v)
		case "t":
			var v uint64
			v, err = strconv.ParseUint(value, 10, 32)
			iterations = uint32(v)
		case "p":
			var v uint64
			v, err = strconv.ParseUint(value, 10, 8)
			parallelism = uint8(v)
		default:
			return 0, 0, 0, errInvalidHashFormat
		}

		if err != nil {
			return 0, 0, 0, fmt.Errorf("argon2: parse %s: %w", key, err)
		}
	}

	return memory, iterations, parallelism, nil
}
