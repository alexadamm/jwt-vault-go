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

# Enable transit engine and create key
vault secrets enable transit
vault write -f transit/keys/jwt-key type=ecdsa-p256
