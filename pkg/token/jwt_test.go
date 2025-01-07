package token

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/vault/api"
)

type TestClaims struct {
	StandardClaims
	Name string `json:"name"`
	Role string `json:"role"`
}

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
