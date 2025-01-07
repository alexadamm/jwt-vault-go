# JWT-Vault-Go

JWT-Vault-Go is a Go library that provides seamless integration between JWT (JSON Web Tokens) and [HashiCorp Vault](https://github.com/hashicorp/vault) for secure token signing and verification.

## Features

- Multiple algorithm support (ECDSA, RSA, RSA-PSS)
- JWS signature format
- Automatic JWKS caching and rotation
- Thread-safe operations
- Built-in token validation
- Custom claims support
- Health checking
- Production-ready defaults

## Installation

```bash
go get github.com/alexadamm/jwt-vault-go
```

## Quick Start

```go
package main

import (
    "context"
    "fmt"
    "log"
    "time"

    "github.com/alexadamm/jwt-vault-go/pkg/token"
)

func main() {
    // Initialize JWT-Vault
    jv, err := token.New(token.Config{
        VaultAddr:      "http://localhost:8200",
        VaultToken:     "your-token",
        TransitKeyPath: "jwt-key",
        Algorithm:      "ES256",  // Select your preferred algorithm
    })
    if err != nil {
        log.Fatal(err)
    }

    // Create claims
    claims := map[string]interface{}{
        "sub": "1234567890",
        "name": "John Doe",
        "iat": time.Now().Unix(),
    }

    // Sign token
    token, err := jv.Sign(context.Background(), claims)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Token: %s\n", token)

    // Verify token
    verified, err := jv.Verify(context.Background(), token)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Verified Claims: %+v\n", verified.Claims)
}
```

## Supported Algorithms

| JWT Algorithm | Vault Key Type | Notes |
|--------------|---------------|-------|
| ES256        | ecdsa-p256    | ECDSA with P-256 curve |
| ES384        | ecdsa-p384    | ECDSA with P-384 curve |
| ES512        | ecdsa-p521    | ECDSA with P-521 curve |
| RS256        | rsa-2048      | RSA with PKCS1v15 padding |
| RS384        | rsa-3072      | RSA with PKCS1v15 padding |
| RS512        | rsa-4096      | RSA with PKCS1v15 padding |
| PS256        | rsa-2048      | RSA with PSS padding |
| PS384        | rsa-3072      | RSA with PSS padding |
| PS512        | rsa-4096      | RSA with PSS padding |

## Prerequisites
1. HashiCorp Vault server with Transit engine enabled
2. Transit key configured for your chosen algorithm

```bash
# Start Vault dev server (for testing)
vault server -dev

# In another terminal
export VAULT_ADDR='http://127.0.0.1:8200'
export VAULT_TOKEN='dev-token'

# Enable transit engine
vault secrets enable transit

# Create key for ES256
vault write -f transit/keys/jwt-key type=ecdsa-p256

# Or for RS256
vault write -f transit/keys/jwt-key type=rsa-2048

# Or for PS256
vault write -f transit/keys/jwt-key type=rsa-2048
```

## Configuration
```go
type Config struct {
    // VaultAddr is the address of the Vault server
    VaultAddr string

    // VaultToken is the token used to authenticate with Vault
    VaultToken string

    // TransitKeyPath is the path to the transit key in Vault
    TransitKeyPath string

    // Algorithm specifies the signing algorithm (e.g., "ES256", "RS256", "PS256")
    Algorithm string

    // CacheTTL is the TTL for the JWKS cache (default: 5m)
    CacheTTL time.Duration

    // RetryConfig configures the retry behavior
    RetryConfig *RetryConfig

    // Optional metrics configuration
    Metrics *MetricsConfig
}
```

## Key Rotation
JWT-Vault-Go supports automatic key rotation through Vault's Transit engine:
```go
// Rotate the signing key
err := jv.RotateKey(context.Background())
```

## Health Checking
```go
health, err := jv.Health(context.Background())
fmt.Printf("Health Status: %v\n", health.Message)
```

## Examples
See the [examples](examples) directory for more examples.

## Contributing
Contributions are welcome! Please read our [Contributing Guidelines](CONTRIBUTING.md) for details.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
