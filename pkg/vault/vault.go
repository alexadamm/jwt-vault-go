package vault

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"

	"github.com/hashicorp/vault/api"
)

// Client wraps HashiCorp Vault's Transit engine client
type Client struct {
	client      *api.Client
	transitPath string
	keyVersion  int64
}

// Config holds configuration for the Vault client
type Config struct {
	// Address is the Vault server address
	Address string

	// Token is the authentication token
	Token string

	// TransitPath is the path to the transit engine key
	TransitPath string
}

// NewClient creates a new Vault client
func NewClient(config Config) (*Client, error) {
	vaultConfig := api.DefaultConfig()
	vaultConfig.Address = config.Address

	client, err := api.NewClient(vaultConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create vault client: %w", err)
	}

	client.SetToken(config.Token)

	vc := &Client{
		client:      client,
		transitPath: config.TransitPath,
	}

	// Get initial key version
	version, err := vc.GetCurrentKeyVersion()
	if err != nil {
		return nil, err
	}
	vc.keyVersion = version

	return vc, nil
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

	latestVersion, ok := secret.Data["latest_version"].(json.Number)
	if !ok {
		return 0, fmt.Errorf("invalid version format")
	}

	version, err := latestVersion.Int64()
	if err != nil {
		return 0, fmt.Errorf("failed to parse version: %w", err)
	}

	return version, nil
}

// GetPublicKey retrieves a public key for a specific version
func (c *Client) GetPublicKey(ctx context.Context, version string) (*ecdsa.PublicKey, error) {
	path := fmt.Sprintf("transit/keys/%s", c.transitPath)

	secret, err := c.client.Logical().Read(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read public key: %w", err)
	}

	if secret == nil {
		return nil, fmt.Errorf("key not found")
	}

	keys, ok := secret.Data["keys"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid key data format")
	}

	keyData, ok := keys[version].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("version %s not found", version)
	}

	publicKey, ok := keyData["public_key"].(string)
	if !ok {
		return nil, fmt.Errorf("public key not found")
	}

	block, _ := pem.Decode([]byte(publicKey))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	ecKey, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key is not ECDSA")
	}

	return ecKey, nil
}

// SignData signs data using the transit engine
func (c *Client) SignData(ctx context.Context, data []byte) ([]byte, error) {
	input := base64.StdEncoding.EncodeToString(data)
	path := fmt.Sprintf("transit/sign/%s", c.transitPath)

	secret, err := c.client.Logical().Write(path, map[string]interface{}{
		"input": input,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to sign data: %w", err)
	}

	if secret == nil {
		return nil, fmt.Errorf("no signature returned")
	}

	signature, ok := secret.Data["signature"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid signature format")
	}

	return base64.StdEncoding.DecodeString(signature)
}

// RotateKey triggers a key rotation in the transit engine
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
