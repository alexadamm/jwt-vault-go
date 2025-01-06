package algorithms

import (
	"crypto"
	"crypto/ecdsa"
	"fmt"
	"math/big"
)

// ECDSASignature represents the R and S components of an ECDSA signature
type ECDSASignature struct {
	R, S *big.Int
}

// ECDSAAlgorithm implements the Algorithm interface for ECDSA signatures
type ECDSAAlgorithm struct {
	BaseAlgorithm
	curve ellipticCurve
}

type ellipticCurve struct {
	name    string // P-256, P-384, P-521
	bitSize int
	keySize int // Size in bytes for R and S components
}

var (
	// Predefined curves
	p256 = ellipticCurve{name: "P-256", bitSize: 256, keySize: 32}
	p384 = ellipticCurve{name: "P-384", bitSize: 384, keySize: 48}
	p521 = ellipticCurve{name: "P-521", bitSize: 521, keySize: 66}
)

// NewECDSAAlgorithm creates a new ECDSA algorithm instance
func NewECDSAAlgorithm(name string, hash crypto.Hash, curve ellipticCurve) Algorithm {
	return &ECDSAAlgorithm{
		BaseAlgorithm: BaseAlgorithm{
			name:      name,
			hash:      hash,
			vaultType: fmt.Sprintf("ecdsa-p%d", curve.bitSize),
			keyType:   KeyTypeECDSA,
			keySize:   curve.keySize,
		},
		curve: curve,
	}
}

// Verify verifies an ECDSA signature in raw R||S format
func (e *ECDSAAlgorithm) Verify(message, signature []byte, key interface{}) error {
	if err := e.KeyCheck(key); err != nil {
		return err
	}

	ecKey, _ := key.(*ecdsa.PublicKey)

	// Check signature length
	expectedLen := e.keySize * 2
	if len(signature) != expectedLen {
		return ErrInvalidSignature
	}

	// Split signature into R and S
	r := new(big.Int).SetBytes(signature[:e.keySize])
	s := new(big.Int).SetBytes(signature[e.keySize:])

	// Hash the message if needed
	var hash []byte
	if e.hash != crypto.Hash(0) {
		h := e.hash.New()
		h.Write(message)
		hash = h.Sum(nil)
	} else {
		hash = message
	}

	// Verify signature
	if !ecdsa.Verify(ecKey, hash, r, s) {
		return ErrInvalidSignature
	}

	return nil
}

// SigningParams returns algorithm-specific Vault signing parameters
func (e *ECDSAAlgorithm) SigningParams() map[string]interface{} {
	params := e.BaseAlgorithm.SigningParams()
	return params
}

// Register predefined ECDSA algorithms
func init() {
	Register(NewECDSAAlgorithm("ES256", crypto.SHA256, p256))
	Register(NewECDSAAlgorithm("ES384", crypto.SHA384, p384))
	Register(NewECDSAAlgorithm("ES512", crypto.SHA512, p521))
}
