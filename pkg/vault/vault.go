package vault

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/alexadamm/jwt-vault-go/pkg/token/algorithms"
	"github.com/hashicorp/vault/api"
)

// vaultClientInterface defines the methods we need from the Vault client
type vaultClientInterface interface {
	Logical() logicalInterface
}

// logicalInterface defines the methods we need from Logical
type logicalInterface interface {
	Read(path string) (*api.Secret, error)
	Write(path string, data map[string]interface{}) (*api.Secret, error)
}

// vaultClientAdapter adapts api.Client to our interface
type vaultClientAdapter struct {
	*api.Client
	logical logicalInterface
}

func newVaultClientAdapter(client *api.Client) *vaultClientAdapter {
	return &vaultClientAdapter{
		Client:  client,
		logical: &logicalAdapter{client.Logical()},
	}
}

func (a *vaultClientAdapter) Logical() logicalInterface {
	return a.logical
}

// logicalAdapter adapts api.Logical to our interface
type logicalAdapter struct {
	*api.Logical
}

func (a *logicalAdapter) Read(path string) (*api.Secret, error) {
	return a.Logical.Read(path)
}

func (a *logicalAdapter) Write(path string, data map[string]interface{}) (*api.Secret, error) {
	return a.Logical.Write(path, data)
}

// Client wraps HashiCorp Vault's Transit engine client
// Handles:
// - Signing operations with JWS format
// - Public key retrieval
// - Key version management
// - Key rotation
type Client struct {
	client      vaultClientInterface
	transitPath string
	keyVersion  int64
	keyType     string
	hash        crypto.Hash
	algorithm   algorithms.Algorithm
}

// Config holds configuration for the Vault client
type Config struct {
	// Address is the Vault server address (e.g., "http://localhost:8200")
	Address string

	// Token is the authentication token
	// Must have permissions for transit engine operations
	Token string

	// TransitKeyPath is the path to the transit key
	// Example: "jwt-key" for key at transit/keys/jwt-key
	TransitPath string
}

// KeyInfo represents Vault's key information
type KeyInfo struct {
	Type       string         `json:"type"`
	KeyBits    int            `json:"key_bits"`
	KeyParts   []string       `json:"key_parts"`
	Versions   map[string]Key `json:"keys"`
	LatestVer  int64          `json:"latest_version"`
	MinVersion int64          `json:"min_version"`
}

// Key represents a single key version in Vault
type Key struct {
	CreationTime string `json:"creation_time"`
	PublicKey    string `json:"public_key"`
}

// NewClient creates a new Vault client
func NewClient(config Config, algorithm algorithms.Algorithm) (*Client, error) {
	vaultConfig := api.DefaultConfig()
	vaultConfig.Address = config.Address

	apiClient, err := api.NewClient(vaultConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create vault client: %w", err)
	}

	apiClient.SetToken(config.Token)


	// Create adapter
	vaultClient := newVaultClientAdapter(apiClient)


	// Create client instance
	vc := &Client{
		client:      vaultClient,
		transitPath: config.TransitPath,
		keyType:     algorithm.VaultKeyType(),
		hash:        algorithm.Hash(),
		algorithm:   algorithm,
	}

	// Get initial key version
	version, err := vc.GetCurrentKeyVersion()
	if err != nil {
		return nil, err
	}
	vc.keyVersion = version

	// Validate key type matches configuration
	if err := vc.validateKeyType(); err != nil {
		return nil, err
	}

	return vc, nil
}

// validateKeyType checks if the existing key matches the configured type
func (c *Client) validateKeyType() error {
	path := fmt.Sprintf("transit/keys/%s", c.transitPath)
	secret, err := c.client.Logical().Read(path)
	if err != nil {
		return fmt.Errorf("failed to read key info: %w", err)
	}

	if secret == nil {
		return fmt.Errorf("key not found at path: %s", c.transitPath)
	}

	var keyInfo KeyInfo
	keyData, err := json.Marshal(secret.Data)
	if err != nil {
		return fmt.Errorf("failed to marshal key data: %w", err)
	}

	if err := json.Unmarshal(keyData, &keyInfo); err != nil {
		return fmt.Errorf("failed to unmarshal key info: %w", err)
	}

	if keyInfo.Type != c.keyType {
		return fmt.Errorf("key type mismatch: expected %s, got %s", c.keyType, keyInfo.Type)
	}

	return nil
}

// GetCurrentKeyVersion retrieves the current version of the transit key
func (c *Client) GetCurrentKeyVersion() (int64, error) {
	path := fmt.Sprintf("transit/keys/%s", c.transitPath)
	secret, err := c.client.Logical().Read(path)
	if err != nil {
		return 0, fmt.Errorf("failed to read key info: %w", err)
	}

	if secret == nil {
		return 0, fmt.Errorf("key not found at path: %s", c.transitPath)
	}

	var keyInfo KeyInfo
	keyData, err := json.Marshal(secret.Data)
	if err != nil {
		return 0, fmt.Errorf("failed to marshal key data: %w", err)
	}

	if err := json.Unmarshal(keyData, &keyInfo); err != nil {
		return 0, fmt.Errorf("failed to unmarshal key info: %w", err)
	}

	return keyInfo.LatestVer, nil
}

// GetPublicKey retrieves a public key for a specific version
// Version should be a string representing key version (e.g., "1")
// Returns *ecdsa.PublicKey or *rsa.PublicKey based on key type
func (c *Client) GetPublicKey(ctx context.Context, version string) (interface{}, error) {
	path := fmt.Sprintf("transit/keys/%s", c.transitPath)

	secret, err := c.client.Logical().Read(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read public key: %w", err)
	}

	var keyInfo KeyInfo
	keyData, err := json.Marshal(secret.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal key data: %w", err)
	}

	if err := json.Unmarshal(keyData, &keyInfo); err != nil {
		return nil, fmt.Errorf("failed to unmarshal key info: %w", err)
	}

	key, ok := keyInfo.Versions[version]
	if !ok {
		return nil, fmt.Errorf("version %s not found", version)
	}

	// Parse PEM-encoded public key
	block, _ := pem.Decode([]byte(key.PublicKey))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	// Validate key type
	switch c.keyType {
	case "ecdsa-p256", "ecdsa-p384", "ecdsa-p521":
		if _, ok := pub.(*ecdsa.PublicKey); !ok {
			return nil, fmt.Errorf("expected ECDSA key, got %T", pub)
		}
	case "rsa-2048", "rsa-3072", "rsa-4096":
		if _, ok := pub.(*rsa.PublicKey); !ok {
			return nil, fmt.Errorf("expected RSA key, got %T", pub)
		}
	}

	return pub, nil
}

// SignData signs data using the transit engine with algorithm-specific params
// Returns the signature in JWS format (base64url encoded)
// Uses marshaling_algorithm=jws for consistent JWT format
func (c *Client) SignData(ctx context.Context, data []byte) (string, error) {
	// Hash the input data first
	hash := c.hash.New()
	hash.Write(data)
	digest := hash.Sum(nil)

	input := base64.StdEncoding.EncodeToString(digest)
	path := fmt.Sprintf("transit/sign/%s", c.transitPath)

	// Prepare signing parameters
	params := c.algorithm.SigningParams()
	params["input"] = input

	secret, err := c.client.Logical().Write(path, params)
	if err != nil {
		return "", fmt.Errorf("failed to sign data: %w", err)
	}

	if secret == nil {
		return "", fmt.Errorf("no signature returned")
	}

	signature, ok := secret.Data["signature"].(string)
	if !ok {
		return "", fmt.Errorf("signature not found in Vault response")
	}

	parts := strings.Split(signature, ":")
	if len(parts) < 3 {
		return "", fmt.Errorf("invalid signature format")
	}

	return parts[2], nil
}

// RotateKey triggers a key rotation in the transit engine
// Creates a new version of the key while maintaining old versions
// Updates c.keyVersion to the new version number
func (c *Client) RotateKey(ctx context.Context) error {
	path := fmt.Sprintf("transit/keys/%s/rotate", c.transitPath)

	_, err := c.client.Logical().Write(path, nil)
	if err != nil {
		return fmt.Errorf("failed to rotate key: %w", err)
	}

	// Update current key version
	version, err := c.GetCurrentKeyVersion()
	if err != nil {
		return err
	}
	c.keyVersion = version

	return nil
}
