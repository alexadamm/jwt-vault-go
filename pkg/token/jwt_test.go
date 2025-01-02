package token

import (
	"context"
	"encoding/json"
	"os"
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

	t.Run("Verify Invalid Token", func(t *testing.T) {
		_, err := jv.Verify(ctx, "invalid.token.format")
		if err != ErrInvalidToken {
			t.Errorf("Expected ErrInvalidToken, got %v", err)
		}
	})

	t.Run("Health Check", func(t *testing.T) {
		status, err := jv.Health(ctx)
		if err != nil {
			t.Fatalf("Health check failed: %v", err)
		}
		if !status.Healthy {
			t.Error("Expected healthy status")
		}
	})
}
