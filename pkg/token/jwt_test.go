package token

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

type TestClaims struct {
	StandardClaims
	Name string `json:"name"`
	Role string `json:"role"`
}

func TestJWTVault(t *testing.T) {
	if os.Getenv("VAULT_ADDR") == "" {
		t.Skip("Skipping vault integration test (VAULT_ADDR not set)")
	}
	ctx := context.Background()

	jv, err := New(Config{
		VaultAddr:      os.Getenv("VAULT_ADDR"),
		VaultToken:     os.Getenv("VAULT_TOKEN"),
		TransitKeyPath: "jwt-test",
		Algorithm:      "ES256", // Using ES256 as default test algorithm
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

		// Token should be in proper JWT format (header.payload.signature)
		parts := strings.Split(token, ".")
		if len(parts) != 3 {
			t.Errorf("Expected JWT format with 3 parts, got %d parts", len(parts))
		}

		// Verify token
		verified, err := jv.Verify(ctx, token)
		if err != nil {
			t.Fatalf("Failed to verify token: %v", err)
		}

		// Verify claims
		var verifiedClaims TestClaims
		claimsJSON, _ := json.Marshal(verified.Claims)
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
}
