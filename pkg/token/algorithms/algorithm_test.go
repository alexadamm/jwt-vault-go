package algorithms

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

func TestBaseAlgorithm(t *testing.T) {
	base := &BaseAlgorithm{
		name:      "TEST256",
		hash:      crypto.SHA256,
		vaultType: "test-type",
		keyType:   KeyTypeECDSA,
		keySize:   32,
	}

	t.Run("Name", func(t *testing.T) {
		if name := base.Name(); name != "TEST256" {
			t.Errorf("Expected name TEST256, got %s", name)
		}
	})

	t.Run("Hash", func(t *testing.T) {
		if hash := base.Hash(); hash != crypto.SHA256 {
			t.Errorf("Expected hash SHA256, got %v", hash)
		}
	})

	t.Run("VaultKeyType", func(t *testing.T) {
		if vType := base.VaultKeyType(); vType != "test-type" {
			t.Errorf("Expected vault type test-type, got %s", vType)
		}
	})

	t.Run("SigningParams", func(t *testing.T) {
		params := base.SigningParams()
		
		if params["prehashed"] != true {
			t.Error("Expected prehashed=true in signing params")
		}

		if params["hash_algorithm"] != "sha2-256" {
			t.Errorf("Expected hash_algorithm=sha2-256, got %v", params["hash_algorithm"])
		}

		if params["marshaling_algorithm"] != "jws" {
			t.Errorf("Expected marshaling_algorithm=jws, got %v", params["marshaling_algorithm"])
		}
	})

	t.Run("KeyCheck ECDSA", func(t *testing.T) {
		ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("Failed to generate ECDSA key: %v", err)
		}
		if err := base.KeyCheck(&ecKey.PublicKey); err != nil {
			t.Errorf("Expected no error for ECDSA key, got %v", err)
		}
	})

	t.Run("KeyCheck RSA", func(t *testing.T) {
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("Failed to generate RSA key: %v", err)
		}
		base.keyType = KeyTypeRSA
		if err := base.KeyCheck(&rsaKey.PublicKey); err != nil {
			t.Errorf("Expected no error for RSA key, got %v", err)
		}
	})

	t.Run("KeyCheck Wrong Type", func(t *testing.T) {
		// Test ECDSA key with RSA type
		ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		base.keyType = KeyTypeRSA
		if err := base.KeyCheck(&ecKey.PublicKey); err != ErrInvalidKeyType {
			t.Errorf("Expected ErrInvalidKeyType for wrong key type, got %v", err)
		}

		// Test RSA key with ECDSA type
		rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
		base.keyType = KeyTypeECDSA
		if err := base.KeyCheck(&rsaKey.PublicKey); err != ErrInvalidKeyType {
			t.Errorf("Expected ErrInvalidKeyType for wrong key type, got %v", err)
		}
	})
}

// Mock key types for testing
type mockECDSAKey struct {
	*ecdsa.PublicKey
}

type mockRSAKey struct {
	*rsa.PublicKey
}
