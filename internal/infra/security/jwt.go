package security

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	uuid "github.com/google/uuid"
)

// ErrKeyIDMissing indicates no kid is associated with the supplied key.
var ErrKeyIDMissing = errors.New("jwt: missing key identifier")

// ErrKeyNotRegistered indicates a supplied kid is unknown to the JWT manager.
var ErrKeyNotRegistered = errors.New("jwt: key not registered")

// JWTManager coordinates signing key retrieval and JWKS generation.
type JWTManager struct {
	KeyProvider KeyProvider
	mu          sync.RWMutex
	publicKeys  map[string]*rsa.PublicKey
}

// NewJWTManager constructs a JWTManager for the supplied key provider.
func NewJWTManager(provider KeyProvider) *JWTManager {
	mgr := &JWTManager{
		KeyProvider: provider,
		publicKeys:  make(map[string]*rsa.PublicKey),
	}

	if enumerator, ok := provider.(interface {
		ListVerificationKeys() map[string]*rsa.PublicKey
	}); ok {
		for kid, key := range enumerator.ListVerificationKeys() {
			_ = mgr.RegisterPublicKey(kid, key)
		}
	}

	return mgr
}

// RegisterPublicKey associates a kid with a public key for JWKS publication and future lookup.
func (m *JWTManager) RegisterPublicKey(kid string, key *rsa.PublicKey) error {
	kid = strings.TrimSpace(kid)
	if kid == "" {
		return ErrKeyIDMissing
	}
	if key == nil {
		return fmt.Errorf("jwt: public key for %s is nil", kid)
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.publicKeys[kid] = key
	return nil
}

// UnregisterPublicKey removes the supplied kid from the JWKS catalogue.
func (m *JWTManager) UnregisterPublicKey(kid string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.publicKeys, strings.TrimSpace(kid))
}

// GetSigningKey retrieves the active signing key from the provider.
func (m *JWTManager) GetSigningKey() (*rsa.PrivateKey, error) {
	if m.KeyProvider == nil {
		return nil, fmt.Errorf("jwt: key provider not configured")
	}
	return m.KeyProvider.GetSigningKey()
}

// GetVerificationKey retrieves a public key by kid.
func (m *JWTManager) GetVerificationKey(kid string) (*rsa.PublicKey, error) {
	kid = strings.TrimSpace(kid)
	if kid == "" {
		return nil, ErrKeyIDMissing
	}

	m.mu.RLock()
	key, ok := m.publicKeys[kid]
	m.mu.RUnlock()
	if ok {
		return key, nil
	}

	if m.KeyProvider != nil {
		fetched, err := m.KeyProvider.GetVerificationKey(kid)
		if err == nil {
			_ = m.RegisterPublicKey(kid, fetched)
			return fetched, nil
		}
	}

	return nil, fmt.Errorf("%w: %s", ErrKeyNotRegistered, kid)
}

// JWKS produces the JSON Web Key Set for registered keys.
func (m *JWTManager) JWKS() ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if len(m.publicKeys) == 0 {
		return json.Marshal(struct {
			Keys []any `json:"keys"`
		}{Keys: []any{}})
	}

	keys := make([]map[string]string, 0, len(m.publicKeys))
	for kid, key := range m.publicKeys {
		if key == nil {
			continue
		}
		keys = append(keys, buildJWK(kid, key))
	}

	payload := map[string]any{"keys": keys}
	return json.Marshal(payload)
}

func buildJWK(kid string, key *rsa.PublicKey) map[string]string {
	return map[string]string{
		"kty": "RSA",
		"use": "sig",
		"alg": "RS256",
		"kid": kid,
		"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	}
}

// AccessTokenClaims augments registered claims with RBAC and session context.
type AccessTokenClaims struct {
	Roles          []string `json:"roles,omitempty"`
	UserID         string   `json:"uid"`
	SessionID      string   `json:"sid,omitempty"`
	SessionVersion int64    `json:"sv,omitempty"`
	jwt.RegisteredClaims
}

// AccessTokenOptions configures creation of access token claims.
type AccessTokenOptions struct {
	UserID         string
	SessionID      string
	SessionVersion int64
	Roles          []string
	Issuer         string
	Audience       []string
	Subject        string
	TTL            time.Duration
	IssuedAt       time.Time
	NotBefore      time.Time
	JTI            string
}

const defaultAccessTokenTTL = 15 * time.Minute

// NewAccessTokenClaims constructs standardized access token claims.
func NewAccessTokenClaims(opts AccessTokenOptions) (*AccessTokenClaims, error) {
	userID := strings.TrimSpace(opts.UserID)
	if userID == "" {
		return nil, fmt.Errorf("jwt: user id is required")
	}
	issuer := strings.TrimSpace(opts.Issuer)
	if issuer == "" {
		return nil, fmt.Errorf("jwt: issuer is required")
	}

	now := opts.IssuedAt
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}

	validFrom := opts.NotBefore
	if validFrom.IsZero() {
		validFrom = now
	} else {
		validFrom = validFrom.UTC()
	}

	ttl := opts.TTL
	if ttl <= 0 {
		ttl = defaultAccessTokenTTL
	}

	jti := strings.TrimSpace(opts.JTI)
	if jti == "" {
		jti = uuid.NewString()
	}

	roles := normalizeRoles(opts.Roles)
	sessionID := strings.TrimSpace(opts.SessionID)
	sessionVersion := opts.SessionVersion
	claims := &AccessTokenClaims{
		Roles:          roles,
		UserID:         userID,
		SessionID:      sessionID,
		SessionVersion: sessionVersion,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   strings.TrimSpace(opts.Subject),
			Issuer:    issuer,
			Audience:  opts.Audience,
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(validFrom),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			ID:        jti,
		},
	}

	return claims, nil
}

// SignAccessToken signs the provided claims using the active signing key and kid.
func (m *JWTManager) SignAccessToken(kid string, claims *AccessTokenClaims) (string, error) {
	if claims == nil {
		return "", fmt.Errorf("jwt: access token claims required")
	}
	kid = strings.TrimSpace(kid)
	if kid == "" {
		return "", ErrKeyIDMissing
	}

	signingKey, err := m.GetSigningKey()
	if err != nil {
		return "", fmt.Errorf("jwt: get signing key: %w", err)
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid

	signed, err := token.SignedString(signingKey)
	if err != nil {
		return "", fmt.Errorf("jwt: sign token: %w", err)
	}

	return signed, nil
}

func normalizeRoles(input []string) []string {
	if len(input) == 0 {
		return nil
	}

	seen := make(map[string]struct{}, len(input))
	result := make([]string, 0, len(input))
	for _, role := range input {
		role = strings.TrimSpace(role)
		if role == "" {
			continue
		}
		if _, exists := seen[role]; exists {
			continue
		}
		seen[role] = struct{}{}
		result = append(result, role)
	}

	if len(result) == 0 {
		return nil
	}

	return result
}
