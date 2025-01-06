package algorithms

import (
	"crypto"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"strings"
)

// RSAAlgorithm implements the Algorithm interface for RSA signatures
type RSAAlgorithm struct {
	BaseAlgorithm
	padding padding
}

type padding int

const (
	paddingPKCS1v15 padding = iota
	paddingPSS
)

// NewRSAAlgorithm creates a new RSA algorithm instance
func NewRSAAlgorithm(name string, hash crypto.Hash, pad padding) Algorithm {
	var vaultType string
	// Map RSA key size based on hash size
	keySize := "2048" // Default to 2048 for SHA-256
	switch hash {
	case crypto.SHA384:
		keySize = "3072"
	case crypto.SHA512:
		keySize = "4096"
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
		padding: pad,
	}
}

// ProcessVaultSignature processes RSA signatures from Vault
func (r *RSAAlgorithm) ProcessVaultSignature(rawSignature string) ([]byte, error) {
	// Split version:keyid:signature format from Vault
	parts := strings.Split(rawSignature, ":")
	if len(parts) < 3 {
		return nil, ErrInvalidSignature
	}

	// The last part contains the base64-encoded signature
	signatureBase64 := parts[len(parts)-1]
	signature, err := base64.StdEncoding.DecodeString(signatureBase64)
	if err != nil {
		return nil, fmt.Errorf("error decoding signature: %w", err)
	}

	return signature, nil
}

// ProcessRawSignature for RSA just returns the signature as is
// RSA signatures don't need special processing unlike ECDSA
func (r *RSAAlgorithm) ProcessRawSignature(signature []byte) ([]byte, error) {
	return signature, nil
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
