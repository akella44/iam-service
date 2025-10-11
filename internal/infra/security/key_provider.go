package security

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

var (
	ErrSigningKeyNotImplemented = errors.New("signing key not implemented in production mode")
	ErrKeyNotFound              = errors.New("key not found")
)

// KeyProvider defines the interface for providing cryptographic keys.
type KeyProvider interface {
	GetSigningKey() (*rsa.PrivateKey, error)
	GetVerificationKey(kid string) (*rsa.PublicKey, error)
}

// DevKeyProvider implements KeyProvider for development environment.
// It reads keys from a directory specified by an environment variable.
type DevKeyProvider struct {
	keys map[string]*rsa.PublicKey
	// For development, we'll just use the first key found as the signing key.
	signingKey *rsa.PrivateKey
}

// NewDevKeyProvider creates a new DevKeyProvider.
func NewDevKeyProvider(keyDir string) (*DevKeyProvider, error) {
	files, err := os.ReadDir(keyDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read key directory: %w", err)
	}

	provider := &DevKeyProvider{
		keys: make(map[string]*rsa.PublicKey),
	}

	for _, file := range files {
		if file.IsDir() {
			continue
		}

		path := filepath.Join(keyDir, file.Name())
		keyData, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("failed to read key file %s: %w", path, err)
		}

		// Try to parse as private key first
		block, _ := pem.Decode(keyData)
		if block == nil {
			return nil, fmt.Errorf("failed to decode PEM block from %s", path)
		}

		// Try PKCS#1 format (RSA PRIVATE KEY)
		if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
			if provider.signingKey == nil {
				provider.signingKey = key
			}
			kid := strings.TrimSuffix(file.Name(), filepath.Ext(file.Name()))
			provider.keys[kid] = &key.PublicKey
			continue
		}

		// Try PKCS#8 format (PRIVATE KEY)
		if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
			if rsaKey, ok := key.(*rsa.PrivateKey); ok {
				if provider.signingKey == nil {
					provider.signingKey = rsaKey
				}
				kid := strings.TrimSuffix(file.Name(), filepath.Ext(file.Name()))
				provider.keys[kid] = &rsaKey.PublicKey
				continue
			}
		}

		// Try to parse as public key (PKCS#1)
		if key, err := x509.ParsePKCS1PublicKey(block.Bytes); err == nil {
			kid := strings.TrimSuffix(file.Name(), filepath.Ext(file.Name()))
			provider.keys[kid] = key
			continue
		}

		// Try to parse as public key (PKIX/X.509)
		if key, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
			if rsaKey, ok := key.(*rsa.PublicKey); ok {
				kid := strings.TrimSuffix(file.Name(), filepath.Ext(file.Name()))
				provider.keys[kid] = rsaKey
				continue
			}
		}

		return nil, fmt.Errorf("failed to parse key from file %s", path)
	}

	if provider.signingKey == nil {
		return nil, errors.New("no private key found for signing")
	}

	return provider, nil
}

// GetSigningKey returns the private key for signing tokens.
func (p *DevKeyProvider) GetSigningKey() (*rsa.PrivateKey, error) {
	return p.signingKey, nil
}

// GetVerificationKey returns the public key for verifying tokens.
func (p *DevKeyProvider) GetVerificationKey(kid string) (*rsa.PublicKey, error) {
	key, ok := p.keys[kid]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrKeyNotFound, kid)
	}
	return key, nil
}

// ProdKeyProvider implements KeyProvider for production environment.
type ProdKeyProvider struct{}

// NewProdKeyProvider creates a new ProdKeyProvider.
func NewProdKeyProvider() (*ProdKeyProvider, error) {
	// In a real production scenario, this would fetch keys from a secure vault.
	// For this task, it's a stub.
	return &ProdKeyProvider{}, nil
}

// GetSigningKey returns an error as signing is not implemented in production mode directly.
func (p *ProdKeyProvider) GetSigningKey() (*rsa.PrivateKey, error) {
	return nil, ErrSigningKeyNotImplemented
}

// GetVerificationKey would fetch the public key from a trusted source.
func (p *ProdKeyProvider) GetVerificationKey(kid string) (*rsa.PublicKey, error) {
	// This should be implemented to fetch public keys from a JWKS endpoint or a similar mechanism.
	return nil, fmt.Errorf("verification for kid %s not implemented", kid)
}

// NewKeyProvider creates a KeyProvider based on the environment.
func NewKeyProvider(env, keyDir string) (KeyProvider, error) {
	switch env {
	case "development":
		return NewDevKeyProvider(keyDir)
	case "production":
		return NewProdKeyProvider()
	default:
		return nil, fmt.Errorf("unknown environment: %s", env)
	}
}
