package token

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/alexadamm/jwt-vault-go/pkg/jwks"
	"github.com/alexadamm/jwt-vault-go/pkg/vault"
)

// DefaultConfig provides default configuration values
var DefaultConfig = Config{
	CacheTTL: 5 * time.Minute,
	RetryConfig: &RetryConfig{
		MaxAttempts:    3,
		RetryInterval:  time.Second,
		MaxElapsedTime: 10 * time.Second,
	},
}

// jwtVault implements the JWTVault interface
type jwtVault struct {
	vaultClient *vault.Client
	jwksCache   *jwks.Cache
	config      Config
}

// New creates a new JWTVault instance
func New(config Config) (JWTVault, error) {
	// Apply defaults for unset values
	if config.CacheTTL == 0 {
		config.CacheTTL = DefaultConfig.CacheTTL
	}
	if config.RetryConfig == nil {
		config.RetryConfig = DefaultConfig.RetryConfig
	}

	// Initialize Vault client
	vaultClient, err := vault.NewClient(vault.Config{
		Address:     config.VaultAddr,
		Token:       config.VaultToken,
		TransitPath: config.TransitKeyPath,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to initialize vault client: %w", err)
	}

	// Initialize JWKS cache
	jwksCache := jwks.NewCache(jwks.Config{
		MaxAge:          config.CacheTTL,
		CleanupInterval: config.CacheTTL / 2,
		KeyFetchFunc:    vaultClient.GetPublicKey,
	})

	return &jwtVault{
		vaultClient: vaultClient,
		jwksCache:   jwksCache,
		config:      config,
	}, nil
}

// Sign creates a new JWT with the provided claims
func (j *jwtVault) Sign(ctx context.Context, claims interface{}) (string, error) {
	// Create the header
	keyVersion, err := j.vaultClient.GetCurrentKeyVersion()
	if err != nil {
		return "", fmt.Errorf("failed to get key version: %w", err)
	}

	header := map[string]interface{}{
		"typ": "JWT",
		"alg": "ES256",
		"kid": fmt.Sprintf("%s:%d", j.config.TransitKeyPath, keyVersion),
	}

	// Encode header
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("failed to marshal header: %w", err)
	}
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)

	// Encode claims
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("failed to marshal claims: %w", err)
	}
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)

	// Create signing input
	signingInput := headerB64 + "." + claimsB64

	// Sign the data
	signature, err := j.vaultClient.SignData(ctx, []byte(signingInput))
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	signatureB64 := base64.RawURLEncoding.EncodeToString(signature)

	// Combine to form final token
	return fmt.Sprintf("%s.%s.%s", headerB64, claimsB64, signatureB64), nil
}

// Verify validates a JWT and returns the verified token
func (j *jwtVault) Verify(ctx context.Context, tokenString string) (*VerifiedToken, error) {
	// Split token
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, ErrInvalidToken
	}

	// Decode and parse header
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, ErrInvalidToken
	}

	var header struct {
		Typ string `json:"typ"`
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, ErrInvalidToken
	}

	// Validate header
	if header.Typ != "JWT" || header.Alg != "ES256" {
		return nil, ErrInvalidToken
	}
	if header.Kid == "" {
		return nil, ErrMissingKID
	}

	// Get the public key
	publicKey, err := j.jwksCache.GetKey(ctx, header.Kid)
	if err != nil {
		return nil, fmt.Errorf("failed to get public key: %w", err)
	}

	// Verify signature
	if err := verifySignature(parts, publicKey); err != nil {
		return nil, err
	}

	// Parse and validate claims
	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, ErrInvalidToken
	}

	var standardClaims StandardClaims
	if err := json.Unmarshal(claimsJSON, &standardClaims); err != nil {
		return nil, ErrInvalidClaims
	}

	// Validate expiry
	if standardClaims.ExpiresAt != 0 {
		if time.Unix(standardClaims.ExpiresAt, 0).Before(time.Now()) {
			return nil, ErrTokenExpired
		}
	}

	// Parse custom claims if present
	var customClaims interface{}
	if err := json.Unmarshal(claimsJSON, &customClaims); err != nil {
		return nil, ErrInvalidClaims
	}

	return &VerifiedToken{
		Raw:            tokenString,
		StandardClaims: &standardClaims,
		Claims:         customClaims,
	}, nil
}

// GetPublicKey retrieves a public key for the given key ID
func (j *jwtVault) GetPublicKey(ctx context.Context, kid string) (*ecdsa.PublicKey, error) {
	return j.jwksCache.GetKey(ctx, kid)
}

// RotateKey triggers a rotation of the signing key
func (j *jwtVault) RotateKey(ctx context.Context) error {
	return j.vaultClient.RotateKey(ctx)
}

// Health returns the current health status
func (j *jwtVault) Health(ctx context.Context) (*HealthStatus, error) {
	// Get current key version
	version, err := j.vaultClient.GetCurrentKeyVersion()
	if err != nil {
		return &HealthStatus{
			Healthy: false,
			Message: "Failed to get key version",
			Details: map[string]interface{}{
				"error": err.Error(),
			},
		}, nil
	}

	return &HealthStatus{
		Healthy: true,
		Message: "Service is healthy",
		Details: map[string]interface{}{
			"currentKeyVersion": version,
		},
	}, nil
}

// verifySignature verifies the ECDSA signature of a JWT
func verifySignature(parts []string, publicKey *ecdsa.PublicKey) error {
	// Decode signature
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return ErrInvalidSignature
	}

	// Split signature into r and s
	if len(signature) != 64 {
		return ErrInvalidSignature
	}

	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:])

	// Create hash of the signing input
	signingInput := parts[0] + "." + parts[1]
	hash := sha256.Sum256([]byte(signingInput))

	// Verify signature
	if !ecdsa.Verify(publicKey, hash[:], r, s) {
		return ErrInvalidSignature
	}

	return nil
}
