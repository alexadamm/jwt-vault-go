package token

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/alexadamm/jwt-vault-go/pkg/jwks"
	"github.com/alexadamm/jwt-vault-go/pkg/token/algorithms"
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
	algorithm   algorithms.Algorithm // Default algorithm
}

// New creates a new JWTVault instance
func New(config Config) (JWTVault, error) {
	// Get the algorithm from config or default to ES256
	alg := config.Algorithm
	if alg == "" {
		alg = "ES256"
	}

	algorithm, err := algorithms.Get(alg)
	if err != nil {
		return nil, fmt.Errorf("failed to get algorithm: %w", err)
	}

	// Initialize Vault client with the algorithm
	vaultClient, err := vault.NewClient(vault.Config{
		Address:     config.VaultAddr,
		Token:       config.VaultToken,
		TransitPath: config.TransitKeyPath,
		KeyType:     algorithm.VaultKeyType(),
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
		algorithm:   algorithm,
	}, nil
}

// Sign creates a new JWT with the provided claims
func (j *jwtVault) Sign(ctx context.Context, claims interface{}) (string, error) {
	keyVersion, err := j.vaultClient.GetCurrentKeyVersion()
	if err != nil {
		return "", fmt.Errorf("failed to get key version: %w", err)
	}

	header := map[string]interface{}{
		"typ": "JWT",
		"alg": j.algorithm.Name(),
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

	// Sign the data with Vault
	signatureRaw, err := j.vaultClient.SignData(ctx, []byte(signingInput))
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	// Process the signature according to the algorithm
	processedSignature, err := j.algorithm.ProcessVaultSignature(signatureRaw)
	if err != nil {
		return "", fmt.Errorf("failed to process signature: %w", err)
	}

	signatureB64 := base64.RawURLEncoding.EncodeToString(processedSignature)

	// Combine to form final token
	return fmt.Sprintf("%s.%s.%s", headerB64, claimsB64, signatureB64), nil
}

type ECDSASignature struct {
	R, S *big.Int
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
	if header.Typ != "JWT" {
		return nil, ErrInvalidToken
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
	if err := validateClaims(&standardClaims); err != nil {
		return nil, err
	}

	// Get the algorithm for verification
	algorithm, err := algorithms.Get(header.Alg)
	if err != nil {
		return nil, fmt.Errorf("unsupported algorithm: %w", err)
	}

	if header.Kid == "" {
		return nil, ErrMissingKID
	}

	// Get the public key
	publicKey, err := j.jwksCache.GetKey(ctx, header.Kid)
	if err != nil {
		return nil, fmt.Errorf("failed to get public key: %w", err)
	}

	// Decode signature
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, ErrInvalidSignature
	}

	// Verify signature
	signingInput := parts[0] + "." + parts[1]
	if err := algorithm.Verify([]byte(signingInput), signature, publicKey); err != nil {
		return nil, err
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
func (j *jwtVault) GetPublicKey(ctx context.Context, kid string) (interface{}, error) {
	key, err := j.jwksCache.GetKey(ctx, kid)
	if err != nil {
		return nil, fmt.Errorf("failed to get public key: %w", err)
	}

	// Validate key type matches the algorithm
	switch j.algorithm.Name() {
	case "ES256", "ES384", "ES512":
		if _, ok := key.(*ecdsa.PublicKey); !ok {
			return nil, fmt.Errorf("invalid key type: expected ECDSA, got %T", key)
		}
	case "RS256", "RS384", "RS512", "PS256", "PS384", "PS512":
		if _, ok := key.(*rsa.PublicKey); !ok {
			return nil, fmt.Errorf("invalid key type: expected RSA, got %T", key)
		}
	}

	return key, nil
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
