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
	VaultKeyType() string

	// SigningParams returns algorithm-specific Vault signing parameters
	SigningParams() map[string]interface{}

	// ProcessVaultSignature converts a Vault signature to JWT format
	ProcessVaultSignature(rawSignature string) ([]byte, error)

	// ProcessRawSignature converts raw signature bytes to JWT format
	ProcessRawSignature(signature []byte) ([]byte, error)

	// Verify verifies the signature against the message
	Verify(message, signature []byte, key interface{}) error

	// KeyCheck validates the key type for verification
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
		"prehashed":      true,
		"hash_algorithm": fmt.Sprintf("sha2-%d", b.hash.Size()*8),
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
