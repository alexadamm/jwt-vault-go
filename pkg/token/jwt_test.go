package token

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/alexadamm/jwt-vault-go/pkg/jwks"
	"github.com/hashicorp/vault/api"
)

type TestClaims struct {
	StandardClaims
	Name string `json:"name"`
	Role string `json:"role"`
}

// TestJWTVault tests the full JWT lifecycle for each supported algorithm
// Requires a running Vault instance with:
// - Transit engine enabled
// - Test keys created:
//   - jwt-test-es256 (type: ecdsa-p256)
//   - jwt-test-rs256 (type: rsa-2048)
//   - jwt-test-ps256 (type: rsa-2048)
//
// Environment variables:
// - VAULT_ADDR: Vault server address
// - VAULT_TOKEN: Token with transit engine permissions
func TestJWTVault(t *testing.T) {
	if os.Getenv("VAULT_ADDR") == "" || os.Getenv("VAULT_TOKEN") == "" {
		t.Skip("Skipping vault integration test (VAULT_ADDR or VAULT_TOKEN not set)")
	}

	setupVaultForTest(t)

	ctx := context.Background()

	for _, alg := range []string{"ES256", "RS256", "PS256"} {
		t.Run(alg, func(t *testing.T) {
			// Create key for this algorithm
			transitPath := fmt.Sprintf("jwt-test-%s", strings.ToLower(alg))
			keyType := getKeyTypeForAlg(alg)
			createTransitKey(t, transitPath, keyType)

			jv, err := New(Config{
				VaultAddr:      os.Getenv("VAULT_ADDR"),
				VaultToken:     os.Getenv("VAULT_TOKEN"),
				TransitKeyPath: transitPath,
				Algorithm:      alg,
			})
			if err != nil {
				t.Fatalf("Failed to create JWTVault: %v", err)
			}

			t.Run("Sign and Verify Token", func(t *testing.T) {
				claims := TestClaims{
					StandardClaims: StandardClaims{
						Issuer:    "test",
						Subject:   "user123",
						IssuedAt:  time.Now().Unix(),
						ExpiresAt: time.Now().Add(time.Hour).Unix(),
					},
					Name: "Test User",
					Role: "admin",
				}

				token, err := jv.Sign(ctx, claims)
				if err != nil {
					t.Fatalf("Failed to sign token: %v", err)
				}

				// Check JWT format
				parts := strings.Split(token, ".")
				if len(parts) != 3 {
					t.Fatalf("Expected JWT format (header.payload.signature), got %d parts", len(parts))
				}

				verified, err := jv.Verify(ctx, token)
				if err != nil {
					t.Fatalf("Failed to verify token: %v", err)
				}

				// Convert verified claims back to TestClaims
				claimsJSON, err := json.Marshal(verified.Claims)
				if err != nil {
					t.Fatalf("Failed to marshal verified claims: %v", err)
				}

				var verifiedClaims TestClaims
				if err := json.Unmarshal(claimsJSON, &verifiedClaims); err != nil {
					t.Fatalf("Failed to unmarshal verified claims: %v", err)
				}

				if verifiedClaims.Name != claims.Name {
					t.Errorf("Expected name %q, got %q", claims.Name, verifiedClaims.Name)
				}
				if verifiedClaims.Role != claims.Role {
					t.Errorf("Expected role %q, got %q", claims.Role, verifiedClaims.Role)
				}
			})

			t.Run("Verify Expired Token", func(t *testing.T) {
				claims := TestClaims{
					StandardClaims: StandardClaims{
						ExpiresAt: time.Now().Add(-time.Hour).Unix(),
					},
				}

				token, err := jv.Sign(ctx, claims)
				if err != nil {
					t.Fatalf("Failed to sign token: %v", err)
				}

				_, err = jv.Verify(ctx, token)
				if err != ErrTokenExpired {
					t.Errorf("Expected ErrTokenExpired, got %v", err)
				}
			})

			t.Run("Verify Not Yet Valid Token", func(t *testing.T) {
				claims := TestClaims{
					StandardClaims: StandardClaims{
						NotBefore: time.Now().Add(time.Hour).Unix(),
					},
				}

				token, err := jv.Sign(ctx, claims)
				if err != nil {
					t.Fatalf("Failed to sign token: %v", err)
				}

				_, err = jv.Verify(ctx, token)
				if err != ErrTokenNotValidYet {
					t.Errorf("Expected ErrTokenNotValidYet, got %v", err)
				}
			})

			t.Run("Invalid Token", func(t *testing.T) {
				_, err := jv.Verify(ctx, "invalid.token.format")
				if err == nil {
					t.Error("Expected error for invalid token format")
				}
			})

			t.Run("Key Rotation", func(t *testing.T) {
				// Create and verify a token with current key
				claims := TestClaims{
					StandardClaims: StandardClaims{
						ExpiresAt: time.Now().Add(time.Hour).Unix(),
					},
				}

				oldToken, err := jv.Sign(ctx, claims)
				if err != nil {
					t.Fatalf("Failed to sign token: %v", err)
				}

				// Rotate key
				if err := jv.RotateKey(ctx); err != nil {
					t.Fatalf("Failed to rotate key: %v", err)
				}

				// Create new token with rotated key
				newToken, err := jv.Sign(ctx, claims)
				if err != nil {
					t.Fatalf("Failed to sign token with new key: %v", err)
				}

				// Both tokens should still verify
				if _, err := jv.Verify(ctx, oldToken); err != nil {
					t.Errorf("Failed to verify old token: %v", err)
				}
				if _, err := jv.Verify(ctx, newToken); err != nil {
					t.Errorf("Failed to verify new token: %v", err)
				}
			})
		})
	}
}

// setupVaultForTest initializes Vault for integration tests:
// - Ensures transit engine is mounted
// - Creates required test keys
// - Sets up proper permissions
// Required environment variables:
// - VAULT_ADDR: Address of Vault server
// - VAULT_TOKEN: Token with transit permissions
func setupVaultForTest(t *testing.T) {
	client, err := api.NewClient(&api.Config{
		Address: os.Getenv("VAULT_ADDR"),
	})
	if err != nil {
		t.Fatalf("Failed to create Vault client: %v", err)
	}
	client.SetToken(os.Getenv("VAULT_TOKEN"))

	// Enable transit engine
	err = client.Sys().Mount("transit", &api.MountInput{
		Type: "transit",
	})
	if err != nil {
		// Ignore if already mounted
		if !strings.Contains(err.Error(), "path is already in use") {
			t.Fatalf("Failed to mount transit engine: %v", err)
		}
	}
}

// createTransitKey creates a transit key in Vault
// Parameters:
// - transitPath: Key path in transit engine
// - keyType: Vault key type (e.g., "ecdsa-p256", "rsa-2048")
// Handles "already exists" errors appropriately
func createTransitKey(t *testing.T, transitPath, keyType string) {
	client, err := api.NewClient(&api.Config{
		Address: os.Getenv("VAULT_ADDR"),
	})
	if err != nil {
		t.Fatalf("Failed to create Vault client: %v", err)
	}
	client.SetToken(os.Getenv("VAULT_TOKEN"))

	path := fmt.Sprintf("transit/keys/%s", transitPath)
	_, err = client.Logical().Write(path, map[string]interface{}{
		"type": keyType,
	})
	if err != nil && !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("Failed to create key %s: %v", transitPath, err)
	}
}

// getKeyTypeForAlg maps JWT algorithm names to Vault key types
// Returns appropriate key type for each supported algorithm:
// - ES256 -> ecdsa-p256
// - RS256/PS256 -> rsa-2048
// Used for test setup and validation
func getKeyTypeForAlg(alg string) string {
	switch alg {
	case "ES256":
		return "ecdsa-p256"
	case "RS256":
		return "rsa-2048"
	case "PS256":
		return "rsa-2048"
	default:
		return ""
	}
}

// mockJWKSCache implements JWKSCacheInterface for testing
type mockJWKSCache struct {
	getKeyFunc      func(ctx context.Context, kid string) (interface{}, error)
	getKeyWithType  func(ctx context.Context, kid string) (interface{}, jwks.KeyType, error)
}

func (m *mockJWKSCache) GetKey(ctx context.Context, kid string) (interface{}, error) {
	if m.getKeyFunc != nil {
		return m.getKeyFunc(ctx, kid)
	}
	return nil, nil
}

func (m *mockJWKSCache) GetKeyWithType(ctx context.Context, kid string) (interface{}, jwks.KeyType, error) {
	if m.getKeyWithType != nil {
		return m.getKeyWithType(ctx, kid)
	}
	return nil, 0, nil
}

func TestJWTClaims(t *testing.T) {
	// Create a mock JWKS cache for testing
	mockCache := &mockJWKSCache{
		getKeyFunc: func(ctx context.Context, kid string) (interface{}, error) {
			return nil, nil // Key not needed for claims tests
		},
	}

	jv := &jwtVault{
		jwksCache: mockCache,
		config: Config{
			TransitKeyPath: "test-key",
		},
	}

	t.Run("Invalid Token Format", func(t *testing.T) {
		invalidTokens := []string{
			"",                    // Empty token
			"single.part",        // One part
			"two.parts",          // Two parts
			"too.many.parts.here", // Four parts
			"invalid.*.parts",    // Invalid characters
		}

		for _, token := range invalidTokens {
			_, err := jv.Verify(context.Background(), token)
			if err != ErrInvalidToken {
				t.Errorf("Expected ErrInvalidToken for %q, got %v", token, err)
			}
		}
	})

	t.Run("Invalid Base64 Header", func(t *testing.T) {
		token := "invalid_base64.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature"
		_, err := jv.Verify(context.Background(), token)
		if err != ErrInvalidToken {
			t.Errorf("Expected ErrInvalidToken, got %v", err)
		}
	})

	t.Run("Invalid Base64 Claims", func(t *testing.T) {
		header := base64.RawURLEncoding.EncodeToString([]byte(`{"typ":"JWT","alg":"ES256","kid":"test-key:1"}`))
		token := header + ".invalid_base64.signature"
		_, err := jv.Verify(context.Background(), token)
		if err != ErrInvalidClaims {
			t.Errorf("Expected ErrInvalidClaims, got %v", err)
		}
	})

	t.Run("Invalid Header JSON", func(t *testing.T) {
		invalidJSON := base64.RawURLEncoding.EncodeToString([]byte(`{"typ":JWT`)) // Invalid JSON
		claims := base64.RawURLEncoding.EncodeToString([]byte(`{}`))
		token := invalidJSON + "." + claims + ".signature"
		_, err := jv.Verify(context.Background(), token)
		if err != ErrInvalidToken {
			t.Errorf("Expected ErrInvalidToken, got %v", err)
		}
	})

	t.Run("Invalid Claims JSON", func(t *testing.T) {
		header := base64.RawURLEncoding.EncodeToString([]byte(`{"typ":"JWT","alg":"ES256","kid":"test-key:1"}`))
		invalidClaims := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":123`)) // Invalid JSON
		token := header + "." + invalidClaims + ".signature"
		_, err := jv.Verify(context.Background(), token)
		if err != ErrInvalidClaims {
			t.Errorf("Expected ErrInvalidClaims, got %v", err)
		}
	})

	t.Run("Invalid Header Type", func(t *testing.T) {
		header := base64.RawURLEncoding.EncodeToString([]byte(`{"typ":"NOT-JWT","alg":"ES256","kid":"test-key:1"}`))
		claims := base64.RawURLEncoding.EncodeToString([]byte(`{}`))
		token := header + "." + claims + ".signature"
		_, err := jv.Verify(context.Background(), token)
		if err != ErrInvalidToken {
			t.Errorf("Expected ErrInvalidToken, got %v", err)
		}
	})

	t.Run("Missing KID", func(t *testing.T) {
		header := base64.RawURLEncoding.EncodeToString([]byte(`{"typ":"JWT","alg":"ES256"}`))
		claims := base64.RawURLEncoding.EncodeToString([]byte(`{}`))
		token := header + "." + claims + ".signature"
		_, err := jv.Verify(context.Background(), token)
		if err != ErrMissingKID {
			t.Errorf("Expected ErrMissingKID, got %v", err)
		}
	})

	t.Run("Claims Time Validation", func(t *testing.T) {
		header := base64.RawURLEncoding.EncodeToString([]byte(`{"typ":"JWT","alg":"ES256","kid":"test-key:1"}`))
		testCases := []struct {
			name    string
			claims  StandardClaims
			wantErr error
		}{
			{
				name: "Expired Token",
				claims: StandardClaims{
					ExpiresAt: time.Now().Add(-time.Hour).Unix(),
				},
				wantErr: ErrTokenExpired,
			},
			{
				name: "Not Yet Valid",
				claims: StandardClaims{
					NotBefore: time.Now().Add(time.Hour).Unix(),
				},
				wantErr: ErrTokenNotValidYet,
			},
			{
				name: "Used Before Issued",
				claims: StandardClaims{
					IssuedAt: time.Now().Add(time.Hour).Unix(),
				},
				wantErr: ErrTokenUsedBeforeIssued,
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				claimsJSON, _ := json.Marshal(tc.claims)
				claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)
				token := header + "." + claimsB64 + ".signature"
				_, err := jv.Verify(context.Background(), token)
				if err != tc.wantErr {
					t.Errorf("Expected %v, got %v", tc.wantErr, err)
				}
			})
		}
	})
}
