package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/alexadamm/jwt-vault-go/pkg/token"
)

func main() {
	jv, err := token.New(token.Config{
		VaultAddr:      "http://localhost:8200",
		VaultToken:     "dev-token",
		TransitKeyPath: "jwt-key",
	})
	if err != nil {
		log.Fatalf("Failed to initialize JWT-Vault: %v", err)
	}

	ctx := context.Background()

	// Create and sign a token with the current key
	claims := map[string]interface{}{
		"sub": "user-123",
		"exp": time.Now().Add(time.Hour).Unix(),
	}

	oldToken, err := jv.Sign(ctx, claims)
	if err != nil {
		log.Fatalf("Failed to sign token: %v", err)
	}
	fmt.Printf("Token before rotation:\n%s\n\n", oldToken)

	// Rotate the key
	fmt.Println("Rotating key...")
	if err := jv.RotateKey(ctx); err != nil {
		log.Fatalf("Failed to rotate key: %v", err)
	}

	// Create a new token with the rotated key
	newToken, err := jv.Sign(ctx, claims)
	if err != nil {
		log.Fatalf("Failed to sign token with new key: %v", err)
	}
	fmt.Printf("Token after rotation:\n%s\n\n", newToken)

	// Verify both tokens still work
	fmt.Println("Verifying old token...")
	if _, err := jv.Verify(ctx, oldToken); err != nil {
		log.Fatalf("Failed to verify old token: %v", err)
	}
	fmt.Println("Old token still valid!")

	fmt.Println("\nVerifying new token...")
	if _, err := jv.Verify(ctx, newToken); err != nil {
		log.Fatalf("Failed to verify new token: %v", err)
	}
	fmt.Println("New token valid!")
}
