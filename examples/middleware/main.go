package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/alexadamm/jwt-vault-go/pkg/token"
)

var jwtVault token.JWTVault

func main() {
	var err error
	jwtVault, err = token.New(token.Config{
		VaultAddr:      "http://localhost:8200",
		VaultToken:     "dev-token",
		TransitKeyPath: "jwt-key",
	})
	if err != nil {
		log.Fatalf("Failed to initialize JWT-Vault: %v", err)
	}

	// Protected endpoint
	http.Handle("/api/protected", jwtAuthMiddleware(http.HandlerFunc(protectedHandler)))

	// Login endpoint for demo
	http.HandleFunc("/api/login", loginHandler)

	fmt.Println("Server running on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func jwtAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract token from Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Authorization header required", http.StatusUnauthorized)
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			http.Error(w, "Invalid authorization format", http.StatusUnauthorized)
			return
		}

		// Verify token
		verified, err := jwtVault.Verify(r.Context(), parts[1])
		if err != nil {
			http.Error(w, fmt.Sprintf("Invalid token: %v", err), http.StatusUnauthorized)
			return
		}

		// Add claims to request context
		ctx := context.WithValue(r.Context(), "claims", verified.Claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func protectedHandler(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value("claims")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "Protected resource accessed successfully",
		"claims":  claims,
	})
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Demo claims - in real world, verify credentials first
	claims := map[string]interface{}{
		"sub":  "user-123",
		"name": "John Doe",
		"exp":  time.Now().Add(time.Hour).Unix(),
	}

	// Sign token
	token, err := jwtVault.Sign(r.Context(), claims)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to create token: %v", err), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{
		"token": token,
	})
}
