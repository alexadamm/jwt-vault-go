package algorithms

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"
	"fmt"
)

var (
	ErrInvalidSignature     = errors.New("invalid signature format")
	ErrUnsupportedAlgorithm = errors.New("unsupported algorithm")
	ErrInvalidKeyType       = errors.New("invalid key type")
)

// Algorithm defines how different signing algorithms process signatures
type Algorithm interface {
	// Name returns the algorithm name (e.g., "ES256", "RS256")
	Name() string

	// Hash returns the hash function used by the algorithm
	Hash() crypto.Hash

	// VaultKeyType returns the required Vault Transit key type
	// Examples: "ecdsa-p256", "rsa-2048"
	VaultKeyType() string

	// SigningParams returns algorithm-specific Vault signing parameters
	// Including base params (prehashed, hash_algorithm) and algorithm specific ones
	// All algorithms use marshaling_algorithm=jws
	SigningParams() map[string]interface{}

	// Verify verifies the signature against the message using given public key
	// Key must be *ecdsa.PublicKey or *rsa.PublicKey matching the algorithm
	Verify(message, signature []byte, key interface{}) error

	// KeyCheck validates the key type for verification
	// Returns ErrInvalidKeyType if key type doesn't match algorithm
	KeyCheck(key interface{}) error
}

// KeyType represents supported key types
type KeyType int

const (
	KeyTypeECDSA KeyType = iota
	KeyTypeRSA
)

// BaseAlgorithm provides common functionality for all algorithms
type BaseAlgorithm struct {
	name      string
	hash      crypto.Hash
	vaultType string
	keyType   KeyType
	keySize   int // Size in bytes for signature components
}

func (b *BaseAlgorithm) Name() string {
	return b.name
}

func (b *BaseAlgorithm) Hash() crypto.Hash {
	return b.hash
}

func (b *BaseAlgorithm) VaultKeyType() string {
	return b.vaultType
}

func (b *BaseAlgorithm) SigningParams() map[string]interface{} {
	return map[string]interface{}{
		"prehashed":            true,
		"hash_algorithm":       fmt.Sprintf("sha2-%d", b.hash.Size()*8),
		"marshaling_algorithm": "jws",
	}
}

func (b *BaseAlgorithm) KeyCheck(key interface{}) error {
	switch b.keyType {
	case KeyTypeECDSA:
		if _, ok := key.(*ecdsa.PublicKey); !ok {
			return ErrInvalidKeyType
		}
	case KeyTypeRSA:
		if _, ok := key.(*rsa.PublicKey); !ok {
			return ErrInvalidKeyType
		}
	}
	return nil
}
