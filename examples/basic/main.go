package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/alexadamm/jwt-vault-go/pkg/token"
)

type CustomClaims struct {
	token.StandardClaims
	UserID   string   `json:"user_id"`
	Username string   `json:"username"`
	Roles    []string `json:"roles"`
}

func main() {
	// Initialize JWT-Vault
	jv, err := token.New(token.Config{
		VaultAddr:      "http://localhost:8200",
		VaultToken:     "dev-token",
		TransitKeyPath: "jwt-key",
		CacheTTL:       5 * time.Minute,
	})
	if err != nil {
		log.Fatalf("Failed to initialize JWT-Vault: %v", err)
	}

	// Create claims
	claims := CustomClaims{
		StandardClaims: token.StandardClaims{
			Issuer:    "my-app",
			Subject:   "user-123",
			IssuedAt:  time.Now().Unix(),
			ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
		},
		UserID:   "user-123",
		Username: "johndoe",
		Roles:    []string{"user", "admin"},
	}

	// Sign token
	ctx := context.Background()
	token, err := jv.Sign(ctx, claims)
	if err != nil {
		log.Fatalf("Failed to sign token: %v", err)
	}
	fmt.Printf("Generated Token: %s\n", token)

	// Verify token
	verified, err := jv.Verify(ctx, token)
	if err != nil {
		log.Fatalf("Failed to verify token: %v", err)
	}

	fmt.Printf("\nVerified Token Info:\n")
	fmt.Printf("Subject: %s\n", verified.StandardClaims.Subject)
	fmt.Printf("Issuer: %s\n", verified.StandardClaims.Issuer)
	fmt.Printf("Expires: %s\n", time.Unix(verified.StandardClaims.ExpiresAt, 0))

	// Check health
	health, err := jv.Health(ctx)
	if err != nil {
		log.Fatalf("Health check failed: %v", err)
	}
	fmt.Printf("\nHealth Status: %v\n", health.Message)
}
