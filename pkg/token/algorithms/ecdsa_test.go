package algorithms

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"encoding/base64"
	"testing"
)

func TestECDSAProcessSignature(t *testing.T) {
	alg := NewECDSAAlgorithm("ES256", crypto.SHA256, p256)

	// Generate a test key pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Create a test message and sign it
	message := []byte("test message")
	hash := crypto.SHA256.New()
	hash.Write(message)
	hashed := hash.Sum(nil)

	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hashed)
	if err != nil {
		t.Fatalf("Failed to sign message: %v", err)
	}

	// Create DER signature
	signature, err := asn1.Marshal(ECDSASignature{R: r, S: s})
	if err != nil {
		t.Fatalf("Failed to marshal signature: %v", err)
	}

	// Create mock Vault signature format
	mockVaultSig := "v1:key1:" + base64.StdEncoding.EncodeToString(signature)

	t.Run("Process Vault Signature", func(t *testing.T) {
		processed, err := alg.ProcessVaultSignature(mockVaultSig)
		if err != nil {
			t.Errorf("ProcessVaultSignature failed: %v", err)
		}

		if len(processed) != 64 { // For ES256, R and S are 32 bytes each
			t.Errorf("Expected processed signature length of 64, got %d", len(processed))
		}
	})

	t.Run("Process Raw Signature", func(t *testing.T) {
		processed, err := alg.ProcessRawSignature(signature)
		if err != nil {
			t.Errorf("ProcessRawSignature failed: %v", err)
		}

		if len(processed) != 64 {
			t.Errorf("Expected processed signature length of 64, got %d", len(processed))
		}
	})

	t.Run("Verify Signature", func(t *testing.T) {
		processed, err := alg.ProcessRawSignature(signature)
		if err != nil {
			t.Fatalf("Failed to process signature: %v", err)
		}

		err = alg.Verify(message, processed, &privateKey.PublicKey)
		if err != nil {
			t.Errorf("Signature verification failed: %v", err)
		}
	})

	t.Run("Invalid Key Type", func(t *testing.T) {
		err = alg.Verify(message, []byte("invalid"), "not a key")
		if err != ErrInvalidKeyType {
			t.Errorf("Expected ErrInvalidKeyType, got %v", err)
		}
	})
}

func TestECDSAAlgorithmRegistration(t *testing.T) {
	algorithms := map[string]struct {
		name      string
		hash      crypto.Hash
		keySize   int
		vaultType string
	}{
		"ES256": {"ES256", crypto.SHA256, 32, "ecdsa-p-256"},
		"ES384": {"ES384", crypto.SHA384, 48, "ecdsa-p-384"},
		"ES512": {"ES512", crypto.SHA512, 66, "ecdsa-p-521"},
	}

	for name, expected := range algorithms {
		t.Run(name, func(t *testing.T) {
			alg, err := Get(name)
			if err != nil {
				t.Fatalf("Failed to get algorithm %s: %v", name, err)
			}

			if alg.Name() != expected.name {
				t.Errorf("Expected name %s, got %s", expected.name, alg.Name())
			}
			if alg.Hash() != expected.hash {
				t.Errorf("Expected hash %v, got %v", expected.hash, alg.Hash())
			}
		})
	}
}
