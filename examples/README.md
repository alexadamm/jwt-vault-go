# JWT-Vault-Go Examples

This directory contains example implementations of JWT-Vault-Go.

## Basic Example

The basic example demonstrates:
- Initializing JWT-Vault
- Creating custom claims
- Signing tokens
- Verifying tokens
- Health checking

To run the basic example:

```bash
# Start Vault dev server
vault server -dev

# In another terminal
export VAULT_ADDR='http://127.0.0.1:8200'
export VAULT_TOKEN='dev-token'

# Enable transit engine
vault secrets enable transit

# Create signing key
vault write -f transit/keys/jwt-key type=ecdsa-p256

# Run the example
cd examples/basic
go run main.go
