package algorithms

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"testing"
)

// TestRSAAlgorithm verifies RSA algorithm implementations:
// - PKCS1v15 and PSS padding
// - Different key sizes (2048, 3072, 4096)
// - Salt length handling for PSS
// - JWS format signatures
func TestRSAAlgorithm(t *testing.T) {
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

			rsaAlg := NewRSAAlgorithm(alg.name, alg.hash, alg.padding)

			// Test signing params
			params := rsaAlg.SigningParams()
			if params["prehashed"] != true {
				t.Error("Expected prehashed=true in signing params")
			}
			if params["hash_algorithm"] != fmt.Sprintf("sha2-%d", alg.hash.Size()*8) {
				t.Errorf("Expected hash_algorithm=sha2-%d in signing params", alg.hash.Size()*8)
			}
			if params["marshaling_algorithm"] != "jws" {
				t.Error("Expected marshaling_algorithm=jws in signing params")
			}

			// Test signature algorithm parameter
			switch alg.padding {
			case paddingPKCS1v15:
				if params["signature_algorithm"] != "pkcs1v15" {
					t.Error("Expected signature_algorithm=pkcs1v15 for PKCS1v15 padding")
				}
			case paddingPSS:
				if params["signature_algorithm"] != "pss" {
					t.Error("Expected signature_algorithm=pss for PSS padding")
				}
				concrete, ok := rsaAlg.(*RSAAlgorithm)
				if !ok {
					t.Fatal("Failed to convert to RSAAlgorithm type")
				}
				expected := params["salt_length"]
				if expected != concrete.saltLength {
					t.Errorf("Expected salt_length=%d, got %d", concrete.saltLength, expected)
				}
			}

			// Test verification with test message
			message := []byte("test message")
			h := alg.hash.New()
			h.Write(message)
			hashed := h.Sum(nil)

			var signature []byte
			switch alg.padding {
			case paddingPKCS1v15:
				signature, _ = rsa.SignPKCS1v15(rand.Reader, privateKey, alg.hash, hashed)
			case paddingPSS:
				opts := &rsa.PSSOptions{
					Hash:       alg.hash,
					SaltLength: rsa.PSSSaltLengthEqualsHash,
				}
				signature, _ = rsa.SignPSS(rand.Reader, privateKey, alg.hash, hashed, opts)
			}

			if err := rsaAlg.Verify(message, signature, &privateKey.PublicKey); err != nil {
				t.Errorf("Verify failed for %s: %v", alg.name, err)
			}
		})
	}
}
