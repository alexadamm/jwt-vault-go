package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/alexadamm/jwt-vault-go/pkg/token"
)

// UserClaims demonstrates nested custom claims
type UserClaims struct {
	token.StandardClaims
	User     User     `json:"user"`
	Metadata Metadata `json:"metadata"`
}

type User struct {
	ID       string   `json:"id"`
	Username string   `json:"username"`
	Roles    []string `json:"roles"`
}

type Metadata struct {
	DeviceID  string    `json:"device_id"`
	IP        string    `json:"ip"`
	LastLogin time.Time `json:"last_login"`
}

func main() {
	jv, err := token.New(token.Config{
		VaultAddr:      "http://localhost:8200",
		VaultToken:     "dev-token",
		TransitKeyPath: "jwt-key",
	})
	if err != nil {
		log.Fatalf("Failed to initialize JWT-Vault: %v", err)
	}

	// Create complex custom claims
	claims := UserClaims{
		StandardClaims: token.StandardClaims{
			Issuer:    "custom-claims-example",
			Subject:   "user-123",
			IssuedAt:  time.Now().Unix(),
			ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
		},
		User: User{
			ID:       "user-123",
			Username: "johndoe",
			Roles:    []string{"admin", "user"},
		},
		Metadata: Metadata{
			DeviceID:  "device-456",
			IP:        "192.168.1.1",
			LastLogin: time.Now(),
		},
	}

	// Sign token
	ctx := context.Background()
	token, err := jv.Sign(ctx, claims)
	if err != nil {
		log.Fatalf("Failed to sign token: %v", err)
	}

	fmt.Printf("Generated Token:\n%s\n\n", token)

	// Verify and parse claims
	verified, err := jv.Verify(ctx, token)
	if err != nil {
		log.Fatalf("Failed to verify token: %v", err)
	}

	fmt.Printf("Verified Standard Claims:\n")
	fmt.Printf("Issuer: %s\n", verified.StandardClaims.Issuer)
	fmt.Printf("Subject: %s\n", verified.StandardClaims.Subject)
	fmt.Printf("IssuedAt: %v\n", time.Unix(verified.StandardClaims.IssuedAt, 0))
	fmt.Printf("ExpiresAt: %v\n", time.Unix(verified.StandardClaims.ExpiresAt, 0))
}
