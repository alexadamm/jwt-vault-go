package vault

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/alexadamm/jwt-vault-go/pkg/token/algorithms"
	"github.com/hashicorp/vault/api"
)

// TestVaultClient verifies Vault client operations:
// - Transit key management
// - Signing with JWS format
// - Public key retrieval
// - Multiple algorithm support
// Requires Vault setup as described in jwt_test.go
func TestVaultClient(t *testing.T) {
	if os.Getenv("VAULT_ADDR") == "" {
		t.Skip("Skipping vault integration test (VAULT_ADDR not set)")
	}

	testCases := []struct {
		name        string
		algorithm   string
		keyType     string
		transitPath string
		wantKeyType interface{}
	}{
		{
			name:        "ECDSA P-256",
			algorithm:   "ES256",
			keyType:     "ecdsa-p256",
			transitPath: "jwt-test-es256",
			wantKeyType: &ecdsa.PublicKey{},
		},
		{
			name:        "ECDSA P-384",
			algorithm:   "ES384",
			keyType:     "ecdsa-p384",
			transitPath: "jwt-test-es384",
			wantKeyType: &ecdsa.PublicKey{},
		},
		{
			name:        "RSA 2048",
			algorithm:   "RS256",
			keyType:     "rsa-2048",
			transitPath: "jwt-test-rs256",
			wantKeyType: &rsa.PublicKey{},
		},
		{
			name:        "RSA 4096 PSS",
			algorithm:   "PS512",
			keyType:     "rsa-4096",
			transitPath: "jwt-test-ps512",
			wantKeyType: &rsa.PublicKey{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := Config{
				Address:     os.Getenv("VAULT_ADDR"),
				Token:       os.Getenv("VAULT_TOKEN"),
				TransitPath: tc.transitPath,
			}

			// Create test key if it doesn't exist
			setupTestKey(t, config, tc.keyType)

			// Get algorithm
			algorithm, err := algorithms.Get(tc.algorithm)
			if err != nil {
				t.Fatalf("Failed to get algorithm: %v", err)
			}

			client, err := NewClient(config, algorithm)
			if err != nil {
				t.Fatalf("Failed to create vault client: %v", err)
			}

			t.Run("Get Key Version", func(t *testing.T) {
				version, err := client.GetCurrentKeyVersion()
				if err != nil {
					t.Errorf("Failed to get key version: %v", err)
				}
				if version < 1 {
					t.Error("Invalid key version")
				}
			})

			t.Run("Get Public Key", func(t *testing.T) {
				ctx := context.Background()
				key, err := client.GetPublicKey(ctx, "1")
				if err != nil {
					t.Errorf("Failed to get public key: %v", err)
				}

				switch tc.wantKeyType.(type) {
				case *ecdsa.PublicKey:
					if _, ok := key.(*ecdsa.PublicKey); !ok {
						t.Errorf("Expected ECDSA key, got %T", key)
					}
				case *rsa.PublicKey:
					if _, ok := key.(*rsa.PublicKey); !ok {
						t.Errorf("Expected RSA key, got %T", key)
					}
				}
			})

			t.Run("Sign Data", func(t *testing.T) {
				ctx := context.Background()
				data := []byte("test data")
				signature, err := client.SignData(ctx, data)
				if err != nil {
					t.Errorf("Failed to sign data: %v", err)
				}

				// Should be base64url encoded
				if _, err := base64.RawURLEncoding.DecodeString(signature); err != nil {
					t.Errorf("Invalid base64url signature: %v", err)
				}
			})

			t.Run("Rotate Key", func(t *testing.T) {
				ctx := context.Background()
				initialVersion := client.keyVersion
				err := client.RotateKey(ctx)
				if err != nil {
					t.Errorf("Failed to rotate key: %v", err)
				}
				if client.keyVersion <= initialVersion {
					t.Error("Key version did not increase after rotation")
				}
			})
		})
	}
}

func setupTestKey(t *testing.T, config Config, keyType string) {
	client, err := api.NewClient(&api.Config{
		Address: config.Address,
	})
	if err != nil {
		t.Fatalf("Failed to create vault client: %v", err)
	}
	client.SetToken(config.Token)

	// Enable transit engine if not enabled
	err = client.Sys().Mount("transit", &api.MountInput{
		Type: "transit",
	})
	if err != nil {
		// Ignore if the mount already exists
		if !strings.Contains(err.Error(), "path is already in use") {
			t.Fatalf("Failed to mount transit engine: %v", err)
		}
	}

	// Create key if it doesn't exist
	path := fmt.Sprintf("transit/keys/%s", config.TransitPath)
	_, err = client.Logical().Write(path, map[string]interface{}{
		"type": keyType,
	})
	if err != nil {
		t.Fatalf("Failed to create test key: %v", err)
	}
}
