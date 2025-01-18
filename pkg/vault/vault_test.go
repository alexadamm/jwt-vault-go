package vault

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
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
				// Use a fixed version for testing
				const testVersion int64 = 1
				signature, err := client.SignData(ctx, data, testVersion)
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

				// Get initial version
				initialVersion, err := client.GetCurrentKeyVersion()
				if err != nil {
					t.Fatalf("Failed to get initial version: %v", err)
				}

				// Rotate key
				err = client.RotateKey(ctx)
				if err != nil {
					t.Errorf("Failed to rotate key: %v", err)
				}

				// Get new version and verify it increased
				newVersion, err := client.GetCurrentKeyVersion()
				if err != nil {
					t.Fatalf("Failed to get new version: %v", err)
				}
				if newVersion <= initialVersion {
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

// mockVaultClient implements vaultClientInterface for testing
type mockVaultClient struct {
	logical *mockLogical
}

func (m *mockVaultClient) Logical() logicalInterface {
	return m.logical
}

// mockLogical implements logicalInterface for testing
type mockLogical struct {
	readFn  func(string) (*api.Secret, error)
	writeFn func(string, map[string]interface{}) (*api.Secret, error)
}

func (m *mockLogical) Read(path string) (*api.Secret, error) {
	if m.readFn != nil {
		return m.readFn(path)
	}
	return nil, nil
}

func (m *mockLogical) Write(path string, data map[string]interface{}) (*api.Secret, error) {
	if m.writeFn != nil {
		return m.writeFn(path, data)
	}
	return nil, nil
}

func TestVaultClientErrors(t *testing.T) {
	t.Run("Key Read Error", func(t *testing.T) {
		mock := &mockVaultClient{
			logical: &mockLogical{
				readFn: func(path string) (*api.Secret, error) {
					return nil, fmt.Errorf("read error")
				},
			},
		}

		client := &Client{
			client:      mock,
			transitPath: "test-key",
			hash:        crypto.SHA256,
		}

		_, err := client.GetCurrentKeyVersion()
		if err == nil {
			t.Error("Expected error from GetCurrentKeyVersion")
		}
		if err.Error() != "failed to read key info: read error" {
			t.Errorf("Unexpected error: %v", err)
		}
	})

	t.Run("Invalid Key Type", func(t *testing.T) {
		alg, _ := algorithms.Get("ES256")
		mock := &mockVaultClient{
			logical: &mockLogical{
				readFn: func(path string) (*api.Secret, error) {
					keyInfo := KeyInfo{
						Type:      "wrong-type",
						KeyBits:   256,
						LatestVer: 1,
					}
					data, _ := json.Marshal(keyInfo)
					var rawData map[string]interface{}
					if err := json.Unmarshal(data, &rawData); err != nil {
						t.Fatalf("Failed to unmarshal key info: %v", err)
					}
					return &api.Secret{Data: rawData}, nil
				},
			},
		}

		client := &Client{
			client:      mock,
			transitPath: "test-key",
			keyType:     alg.VaultKeyType(), // Set the expected key type
			hash:        crypto.SHA256,
			algorithm:   alg,
		}

		err := client.validateKeyType()
		if err == nil {
			t.Error("Expected error from validateKeyType")
		}
		if err.Error() != "key type mismatch: expected ecdsa-p256, got wrong-type" {
			t.Errorf("Unexpected error: %v", err)
		}
	})

	t.Run("Sign Error", func(t *testing.T) {
		alg, _ := algorithms.Get("ES256")
		mock := &mockVaultClient{
			logical: &mockLogical{
				writeFn: func(path string, data map[string]interface{}) (*api.Secret, error) {
					return nil, fmt.Errorf("signing error")
				},
			},
		}

		client := &Client{
			client:      mock,
			transitPath: "test-key",
			hash:        crypto.SHA256,
			algorithm:   alg,
			keyType:     alg.VaultKeyType(),
		}

		// Use a fixed version for testing
		const testVersion int64 = 1
		_, err := client.SignData(context.Background(), []byte("test data"), testVersion)
		if err == nil {
			t.Error("Expected error from SignData")
		}
		if err.Error() != "failed to sign data: signing error" {
			t.Errorf("Unexpected error: %v", err)
		}
	})

	t.Run("Invalid Signature Response", func(t *testing.T) {
		alg, _ := algorithms.Get("ES256")
		mock := &mockVaultClient{
			logical: &mockLogical{
				writeFn: func(path string, data map[string]interface{}) (*api.Secret, error) {
					return &api.Secret{
						Data: map[string]interface{}{
							"not_signature": "invalid",
						},
					}, nil
				},
			},
		}

		client := &Client{
			client:      mock,
			transitPath: "test-key",
			hash:        crypto.SHA256,
			algorithm:   alg,
			keyType:     alg.VaultKeyType(),
		}

		// Use a fixed version for testing
		const testVersion int64 = 1
		_, err := client.SignData(context.Background(), []byte("test data"), testVersion)
		if err == nil {
			t.Error("Expected error from SignData")
		}
		if err.Error() != "signature not found in Vault response" {
			t.Errorf("Unexpected error: %v", err)
		}
	})

	t.Run("Invalid Signature Format", func(t *testing.T) {
		alg, _ := algorithms.Get("ES256")
		mock := &mockVaultClient{
			logical: &mockLogical{
				writeFn: func(path string, data map[string]interface{}) (*api.Secret, error) {
					return &api.Secret{
						Data: map[string]interface{}{
							"signature": "invalid-format",
						},
					}, nil
				},
			},
		}

		client := &Client{
			client:      mock,
			transitPath: "test-key",
			hash:        crypto.SHA256,
			algorithm:   alg,
			keyType:     alg.VaultKeyType(),
		}

		// Use a fixed version for testing
		const testVersion int64 = 1
		_, err := client.SignData(context.Background(), []byte("test data"), testVersion)
		if err == nil {
			t.Error("Expected error from SignData")
		}
		if err.Error() != "invalid signature format" {
			t.Errorf("Unexpected error: %v", err)
		}
	})

	t.Run("Rotate Error", func(t *testing.T) {
		alg, _ := algorithms.Get("ES256")
		mock := &mockVaultClient{
			logical: &mockLogical{
				writeFn: func(path string, data map[string]interface{}) (*api.Secret, error) {
					return nil, fmt.Errorf("rotation error")
				},
			},
		}

		client := &Client{
			client:      mock,
			transitPath: "test-key",
			hash:        crypto.SHA256,
			algorithm:   alg,
			keyType:     alg.VaultKeyType(),
		}

		err := client.RotateKey(context.Background())
		if err == nil {
			t.Error("Expected error from RotateKey")
		}
		if err.Error() != "failed to rotate key: rotation error" {
			t.Errorf("Unexpected error: %v", err)
		}
	})
}
