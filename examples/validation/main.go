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

	// Test Case 1: Valid Token
	fmt.Println("Test Case 1: Valid Token")
	validToken, err := createToken(jv, ctx, time.Hour)
	if err != nil {
		log.Fatal(err)
	}
	verifyToken(jv, ctx, validToken)

	// Test Case 2: Expired Token
	fmt.Println("\nTest Case 2: Expired Token")
	expiredToken, err := createToken(jv, ctx, -1*time.Hour)
	if err != nil {
		log.Fatal(err)
	}
	verifyToken(jv, ctx, expiredToken)

	// Test Case 3: Invalid Format
	fmt.Println("\nTest Case 3: Invalid Format")
	verifyToken(jv, ctx, "invalid.token.format")

	// Test Case 4: Modified Token
	fmt.Println("\nTest Case 4: Modified Token")
	modifiedToken := validToken + "modified"
	verifyToken(jv, ctx, modifiedToken)
}

func createToken(jv token.JWTVault, ctx context.Context, expiration time.Duration) (string, error) {
	claims := map[string]interface{}{
		"sub": "user-123",
		"exp": time.Now().Add(expiration).Unix(),
	}

	return jv.Sign(ctx, claims)
}

func verifyToken(jv token.JWTVault, ctx context.Context, tokenString string) {
	verified, err := jv.Verify(ctx, tokenString)
	if err != nil {
		fmt.Printf("Verification failed: %v\n", err)
		return
	}
	fmt.Printf("Token verified successfully: %+v\n", verified.StandardClaims)
}
