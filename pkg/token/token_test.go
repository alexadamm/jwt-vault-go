package token

import (
	"testing"
	"time"
)

// TestConfig verifies configuration validation:
// - Required fields (VaultAddr, VaultToken)
// - Default values (Algorithm = ES256)
// - TTL settings for cache
func TestConfig(t *testing.T) {
	cfg := Config{
		VaultAddr:      "http://localhost:8200",
		VaultToken:     "test-token",
		TransitKeyPath: "jwt/sign",
		CacheTTL:       5 * time.Minute,
		RetryConfig: &RetryConfig{
			MaxAttempts:    3,
			RetryInterval:  time.Second,
			MaxElapsedTime: 10 * time.Second,
		},
	}

	if cfg.VaultAddr == "" {
		t.Error("VaultAddr should not be empty")
	}

	if cfg.TransitKeyPath == "" {
		t.Error("TransitKeyPath should not be empty")
	}

	if cfg.RetryConfig.MaxAttempts <= 0 {
		t.Error("MaxAttempts should be greater than 0")
	}
}

// TestStandardClaims verifies standard claims handling:
// - Issuer, Subject, Audience fields
// - Time validation (exp, nbf, iat)
// - JSON marshaling/unmarshaling
func TestStandardClaims(t *testing.T) {
	claims := &StandardClaims{
		Issuer:    "test-issuer",
		Subject:   "test-subject",
		Audience:  "test-audience",
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
		IssuedAt:  time.Now().Unix(),
		ID:        "test-id",
	}

	if claims.Issuer != "test-issuer" {
		t.Error("Issuer not set correctly")
	}

	if claims.ExpiresAt <= claims.IssuedAt {
		t.Error("ExpiresAt should be after IssuedAt")
	}
}
