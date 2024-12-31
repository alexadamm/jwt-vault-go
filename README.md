# JWT-Vault-Go

JWT-Vault-Go is a Go library that provides seamless integration between JWT (JSON Web Tokens) and HashiCorp Vault for secure token signing and verification.

## Features

- JWT signing using Vault's Transit engine (ES256)
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

```
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

## Prerequisites
1. HashiCorp Vault server with Transit engine enabled
2. Transit key configured for ECDSA (ES256)

```
# Start Vault dev server (for testing)
vault server -dev

# In another terminal
export VAULT_ADDR='http://127.0.0.1:8200'
export VAULT_TOKEN='dev-token'

# Enable transit engine
vault secrets enable transit

# Create signing key
vault write -f transit/keys/jwt-key type=ecdsa-p256
```

## Configuration
```
type Config struct {
    // VaultAddr is the address of the Vault server
    VaultAddr string

    // VaultToken is the token used to authenticate with Vault
    VaultToken string

    // TransitKeyPath is the path to the transit key in Vault
    TransitKeyPath string

    // CacheTTL is the TTL for the JWKS cache (default: 5m)
    CacheTTL time.Duration

    // RetryConfig configures the retry behavior
    RetryConfig *RetryConfig

    // Optional metrics configuration
    Metrics *MetricsConfig
}
```

## Custom Claims
```
type CustomClaims struct {
    token.StandardClaims
    UserID   string   `json:"user_id"`
    Username string   `json:"username"`
    Roles    []string `json:"roles"`
}

claims := CustomClaims{
    StandardClaims: token.StandardClaims{
        Issuer:    "my-app",
        Subject:   "user-123",
        IssuedAt:  time.Now().Unix(),
        ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
    },
    UserID:   "user-123",
    Username: "johndoe",
    Roles:    []string{"user", "admin"},
}
```

## Key Rotation
JWT-Vault-Go supports automatic key rotation through Vault's Transit engine:
```
// Rotate the signing key
err := jv.RotateKey(context.Background())
if err != nil {
    log.Fatal(err)
}
```

## Health Checking
```
health, err := jv.Health(context.Background())
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Health Status: %v\n", health.Message)
```

## Examples
See the [https://github.com/alexadamm/jwt-vault-go/tree/main/examples](examples) directory for more examples.

## Contributing
Contributions are welcome! Please read our Contributing Guidelines for details.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
