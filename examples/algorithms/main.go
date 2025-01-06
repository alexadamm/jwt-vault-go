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
	// Example of using different algorithms
	algorithms := []string{"ES256", "ES384", "ES512", "RS256", "RS384", "RS512"}

	for _, alg := range algorithms {
		fmt.Printf("\nTesting algorithm: %s\n", alg)
		fmt.Printf("------------------------\n")

		// Initialize JWT-Vault with specific algorithm
		jv, err := token.New(token.Config{
			VaultAddr:      "http://localhost:8200",
			VaultToken:     "dev-token",
			TransitKeyPath: fmt.Sprintf("jwt-key-%s", alg),
			Algorithm:      alg,
		})
		if err != nil {
			log.Fatalf("Failed to initialize JWT-Vault with %s: %v", alg, err)
		}

		// Create claims
		claims := CustomClaims{
			StandardClaims: token.StandardClaims{
				Issuer:    fmt.Sprintf("%s-test", alg),
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
		signedToken, err := jv.Sign(ctx, claims)
		if err != nil {
			log.Fatalf("Failed to sign token with %s: %v", alg, err)
		}
		fmt.Printf("Generated Token (%s):\n%s\n\n", alg, signedToken)

		// Verify token
		verified, err := jv.Verify(ctx, signedToken)
		if err != nil {
			log.Fatalf("Failed to verify %s token: %v", alg, err)
		}

		fmt.Printf("Verified Token Info (%s):\n", alg)
		fmt.Printf("Subject: %s\n", verified.StandardClaims.Subject)
		fmt.Printf("Issuer: %s\n", verified.StandardClaims.Issuer)
		fmt.Printf("Expires: %s\n", time.Unix(verified.StandardClaims.ExpiresAt, 0))
	}
}
