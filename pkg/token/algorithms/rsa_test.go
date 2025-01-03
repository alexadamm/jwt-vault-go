package algorithms

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"testing"
)

func TestRSAProcessSignature(t *testing.T) {
	algorithms := []struct {
		name    string
		hash    crypto.Hash
		padding padding
	}{
		{"RS256", crypto.SHA256, paddingPKCS1v15},
		{"PS256", crypto.SHA256, paddingPSS},
		{"RS384", crypto.SHA384, paddingPKCS1v15},
		{"PS384", crypto.SHA384, paddingPSS},
		{"RS512", crypto.SHA512, paddingPKCS1v15},
		{"PS512", crypto.SHA512, paddingPSS},
	}

	for _, alg := range algorithms {
		t.Run(alg.name, func(t *testing.T) {
			// Generate test key pair
			privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Fatalf("Failed to generate key: %v", err)
			}

			// Create test message and hash it
			message := []byte("test message")
			hash := alg.hash.New()
			hash.Write(message)
			hashed := hash.Sum(nil)

			// Sign message
			var signature []byte
			switch alg.padding {
			case paddingPKCS1v15:
				signature, err = rsa.SignPKCS1v15(rand.Reader, privateKey, alg.hash, hashed)
			case paddingPSS:
				opts := &rsa.PSSOptions{
					Hash:       alg.hash,
					SaltLength: rsa.PSSSaltLengthEqualsHash,
				}
				signature, err = rsa.SignPSS(rand.Reader, privateKey, alg.hash, hashed, opts)
			}
			if err != nil {
				t.Fatalf("Failed to sign message: %v", err)
			}

			// Create mock Vault signature
			mockVaultSig := "v1:key1:" + base64.StdEncoding.EncodeToString(signature)

			rsaAlg := NewRSAAlgorithm(alg.name, alg.hash, alg.padding)

			t.Run("Process Vault Signature", func(t *testing.T) {
				processed, err := rsaAlg.ProcessVaultSignature(mockVaultSig)
				if err != nil {
					t.Errorf("ProcessVaultSignature failed: %v", err)
				}

				// Verify the processed signature
				err = rsaAlg.Verify(message, processed, &privateKey.PublicKey)
				if err != nil {
					t.Errorf("Signature verification failed: %v", err)
				}
			})

			t.Run("Process Raw Signature", func(t *testing.T) {
				processed, err := rsaAlg.ProcessRawSignature(signature)
				if err != nil {
					t.Errorf("ProcessRawSignature failed: %v", err)
				}

				// Verify the processed signature
				err = rsaAlg.Verify(message, processed, &privateKey.PublicKey)
				if err != nil {
					t.Errorf("Signature verification failed: %v", err)
				}
			})

			t.Run("Invalid Key Type", func(t *testing.T) {
				err = rsaAlg.Verify(message, signature, "not a key")
				if err != ErrInvalidKeyType {
					t.Errorf("Expected ErrInvalidKeyType, got %v", err)
				}
			})

			t.Run("Invalid Signature", func(t *testing.T) {
				err = rsaAlg.Verify(message, []byte("invalid"), &privateKey.PublicKey)
				if err != ErrInvalidSignature {
					t.Errorf("Expected ErrInvalidSignature, got %v", err)
				}
			})
		})
	}
}

func TestRSAAlgorithmRegistration(t *testing.T) {
	algorithms := []struct {
		name      string
		hash      crypto.Hash
		vaultType string
	}{
		{"RS256", crypto.SHA256, "rsa-256-pkcs1v15"},
		{"RS384", crypto.SHA384, "rsa-384-pkcs1v15"},
		{"RS512", crypto.SHA512, "rsa-512-pkcs1v15"},
		{"PS256", crypto.SHA256, "rsa-256-pss"},
		{"PS384", crypto.SHA384, "rsa-384-pss"},
		{"PS512", crypto.SHA512, "rsa-512-pss"},
	}

	for _, expected := range algorithms {
		t.Run(expected.name, func(t *testing.T) {
			alg, err := Get(expected.name)
			if err != nil {
				t.Fatalf("Failed to get algorithm %s: %v", expected.name, err)
			}

			if alg.Name() != expected.name {
				t.Errorf("Expected name %s, got %s", expected.name, alg.Name())
			}
			if alg.Hash() != expected.hash {
				t.Errorf("Expected hash %v, got %v", expected.hash, alg.Hash())
			}
			if alg.VaultKeyType() != expected.vaultType {
				t.Errorf("Expected vault type %s, got %s", expected.vaultType, alg.VaultKeyType())
			}
		})
	}
}
