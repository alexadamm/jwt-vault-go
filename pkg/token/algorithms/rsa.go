package algorithms

import (
	"crypto"
	"crypto/rsa"
	"fmt"
)

// RSAAlgorithm implements the Algorithm interface for RSA signatures
type RSAAlgorithm struct {
	BaseAlgorithm
	padding    padding
	saltLength int8
}

type padding int

const (
	paddingPKCS1v15 padding = iota
	paddingPSS
)

// NewRSAAlgorithm creates a new RSA algorithm instance
// Supports both PKCS1v15 (RS*) and PSS (PS*) padding
// Required Vault key types based on hash size:
// - SHA-256: rsa-2048
// - SHA-384: rsa-3072
// - SHA-512: rsa-4096
func NewRSAAlgorithm(name string, hash crypto.Hash, pad padding) Algorithm {
	var vaultType string
	// Map RSA key size based on hash size
	keySize := "2048" // Default to 2048 for SHA-256
	var saltLength int8
	saltLength = 32
	switch hash {
	case crypto.SHA384:
		keySize = "3072"
		saltLength = 48
	case crypto.SHA512:
		keySize = "4096"
		saltLength = 64
	}

	// Set Vault key type based on padding
	switch pad {
	case paddingPKCS1v15:
		vaultType = fmt.Sprintf("rsa-%s", keySize)
	case paddingPSS:
		vaultType = fmt.Sprintf("rsa-%s", keySize)
	}

	return &RSAAlgorithm{
		BaseAlgorithm: BaseAlgorithm{
			name:      name,
			hash:      hash,
			vaultType: vaultType,
			keyType:   KeyTypeRSA,
		},
		padding:    pad,
		saltLength: saltLength,
	}
}

// Verify verifies an RSA signature
func (r *RSAAlgorithm) Verify(message, signature []byte, key interface{}) error {
	if err := r.KeyCheck(key); err != nil {
		return err
	}

	rsaKey, _ := key.(*rsa.PublicKey)

	// Hash the message
	h := r.hash.New()
	h.Write(message)
	digest := h.Sum(nil)

	var err error
	switch r.padding {
	case paddingPKCS1v15:
		err = rsa.VerifyPKCS1v15(rsaKey, r.hash, digest, signature)
	case paddingPSS:
		opts := &rsa.PSSOptions{
			Hash:       r.hash,
			SaltLength: rsa.PSSSaltLengthEqualsHash,
		}
		err = rsa.VerifyPSS(rsaKey, r.hash, digest, signature, opts)
	}

	if err != nil {
		return ErrInvalidSignature
	}

	return nil
}

// SigningParams returns algorithm-specific Vault signing parameters
func (r *RSAAlgorithm) SigningParams() map[string]interface{} {
	params := r.BaseAlgorithm.SigningParams()

	// Add RSA-specific signature algorithm
	switch r.padding {
	case paddingPKCS1v15:
		params["signature_algorithm"] = "pkcs1v15"
	case paddingPSS:
		params["signature_algorithm"] = "pss"
		params["salt_length"] = r.saltLength
	}

	return params
}

// Register predefined RSA algorithms
func init() {
	// Register RSASSA-PKCS1-v1_5 algorithms
	Register(NewRSAAlgorithm("RS256", crypto.SHA256, paddingPKCS1v15))
	Register(NewRSAAlgorithm("RS384", crypto.SHA384, paddingPKCS1v15))
	Register(NewRSAAlgorithm("RS512", crypto.SHA512, paddingPKCS1v15))

	// Register RSASSA-PSS algorithms
	Register(NewRSAAlgorithm("PS256", crypto.SHA256, paddingPSS))
	Register(NewRSAAlgorithm("PS384", crypto.SHA384, paddingPSS))
	Register(NewRSAAlgorithm("PS512", crypto.SHA512, paddingPSS))
}
