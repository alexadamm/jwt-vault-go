package algorithms

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

func TestECDSAAlgorithm(t *testing.T) {
	alg := NewECDSAAlgorithm("ES256", crypto.SHA256, p256)

	// Generate a test key pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Test cases
	tests := []struct {
		name    string
		message []byte
		setup   func() []byte
		wantErr bool
	}{
		{
			name:    "Valid Signature",
			message: []byte("test message"),
			setup: func() []byte {
				h := crypto.SHA256.New()
				h.Write([]byte("test message"))
				hashed := h.Sum(nil)
				r, s, _ := ecdsa.Sign(rand.Reader, privateKey, hashed)

				// Create signature in R||S format as expected by verification
				signature := make([]byte, 64)
				copy(signature[0:32], r.Bytes())
				copy(signature[32:64], s.Bytes())
				return signature
			},
			wantErr: false,
		},
		{
			name:    "Invalid Signature Length",
			message: []byte("test message"),
			setup: func() []byte {
				return []byte("invalid")
			},
			wantErr: true,
		},
		{
			name:    "Invalid Key Type",
			message: []byte("test message"),
			setup: func() []byte {
				return make([]byte, 64)
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signature := tt.setup()
			var key interface{} = &privateKey.PublicKey
			if tt.name == "Invalid Key Type" {
				key = "not a key"
			}

			err := alg.Verify(tt.message, signature, key)
			if (err != nil) != tt.wantErr {
				t.Errorf("Verify() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}

	t.Run("SigningParams", func(t *testing.T) {
		params := alg.SigningParams()
		if params["prehashed"] != true {
			t.Error("Expected prehashed=true in signing params")
		}
		if params["hash_algorithm"] != "sha2-256" {
			t.Error("Expected hash_algorithm=sha2-256 in signing params")
		}
		if params["marshaling_algorithm"] != "jws" {
			t.Error("Expected marshaling_algorithm=jws in signing params")
		}
	})
}
