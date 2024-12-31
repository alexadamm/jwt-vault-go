package token

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"time"
)

// JWTVault is the main interface for JWT-Vault operations
type JWTVault interface {
	// Sign creates a new JWT with the provided claims
	Sign(ctx context.Context, claims interface{}) (string, error)

	// Verify validates a JWT and returns the verified token
	Verify(ctx context.Context, token string) (*VerifiedToken, error)

	// GetPublicKey retrieves a public key for the given key ID
	GetPublicKey(ctx context.Context, kid string) (*ecdsa.PublicKey, error)

	// RotateKey triggers a rotation of the signing key
	RotateKey(ctx context.Context) error

	// Health checks the health status of the JWT-Vault service
	Health(ctx context.Context) (*HealthStatus, error)
}

// Config holds the configuration for JWTVault
type Config struct {
	// VaultAddr is the address of the Vault server
	VaultAddr string

	// VaultToken is the token used to authenticate with Vault
	VaultToken string

	// TransitKeyPath is the path to the transit key in Vault
	TransitKeyPath string

	// CacheTTL is the TTL for the JWKS cache
	CacheTTL time.Duration

	// RetryConfig configures the retry behavior
	RetryConfig *RetryConfig

	// Optional metrics configuration
	Metrics *MetricsConfig
}

// RetryConfig configures the retry behavior
type RetryConfig struct {
	MaxAttempts    int
	RetryInterval  time.Duration
	MaxElapsedTime time.Duration
}

// MetricsConfig configures metrics collection
type MetricsConfig struct {
	Enabled bool
	// Additional metrics configuration can be added here
}

// VerifiedToken represents a verified JWT token
type VerifiedToken struct {
	// Raw is the original token string
	Raw string

	// Claims holds the parsed claims
	Claims interface{}

	// StandardClaims holds the standard JWT claims
	StandardClaims *StandardClaims
}

// StandardClaims represents the standard JWT claims
type StandardClaims struct {
	// Issuer identifies the principal that issued the JWT
	Issuer string `json:"iss,omitempty"`

	// Subject identifies the principal that is the subject of the JWT
	Subject string `json:"sub,omitempty"`

	// Audience identifies the recipients that the JWT is intended for
	Audience string `json:"aud,omitempty"`

	// ExpiresAt identifies the expiration time on or after which the JWT must not be accepted
	ExpiresAt int64 `json:"exp,omitempty"`

	// NotBefore identifies the time before which the JWT must not be accepted
	NotBefore int64 `json:"nbf,omitempty"`

	// IssuedAt identifies the time at which the JWT was issued
	IssuedAt int64 `json:"iat,omitempty"`

	// ID provides a unique identifier for the JWT
	ID string `json:"jti,omitempty"`
}

// HealthStatus represents the health check response
type HealthStatus struct {
	// Healthy indicates if the service is healthy
	Healthy bool

	// Message provides additional health status information
	Message string

	// Details contains detailed health check information
	Details map[string]interface{}
}

// Common errors
var (
	ErrInvalidToken     = errors.New("invalid token")
	ErrTokenExpired     = errors.New("token has expired")
	ErrInvalidSignature = errors.New("invalid token signature")
	ErrMissingKID       = errors.New("token is missing key ID (kid)")
	ErrInvalidClaims    = errors.New("invalid token claims")
	ErrKeyNotFound      = errors.New("signing key not found")
	ErrVaultUnreachable = errors.New("vault server is unreachable")
)
