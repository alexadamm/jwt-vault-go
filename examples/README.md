# JWT-Vault-Go Examples

This directory contains various examples demonstrating the usage of JWT-Vault-Go.

## Setup

Before running any example, make sure you have Vault running and configured:

```bash
# Start Vault dev server
vault server -dev

# In another terminal
export VAULT_ADDR='http://127.0.0.1:8200'
export VAULT_TOKEN='dev-token'

# Enable transit engine
vault secrets enable transit

# Create keys for different algorithms
vault write -f transit/keys/jwt-key-ES256 type=ecdsa-p256
vault write -f transit/keys/jwt-key-RS256 type=rsa-2048
vault write -f transit/keys/jwt-key-PS256 type=rsa-2048
```

## Examples

### Basic Usage
Basic JWT signing and verification with default settings (ES256).
```
go run examples/basic/main.go
```

### Algorithm Selection
Examples of using different signing algorithms (ECDSA, RSA, RSA-PSS).
```
go run examples/algorithms/main.go
```

### Custom Claims
Using custom claims structures with JWT-Vault-Go.
```
go run examples/custom-claims/main.go
```

### Key Rotation
Demonstrating key rotation functionality.
```
go run examples/key-rotation/main.go
```

### Middleware
Example of using JWT-Vault-Go in an HTTP middleware.
```
go run examples/middleware/main.go
```

### Validation
Examples of token validation and error handling.
```
go run examples/validation/main.go
```

## Adding New Examples

When adding new examples:

1. Create a new directory under `examples/`
2. Include a `main.go` file demonstrating the feature
3. Update this README with a description
4. Ensure the example includes proper error handling
5. Document any special setup requirements
