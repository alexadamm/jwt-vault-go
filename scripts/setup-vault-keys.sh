#!/bin/bash

# Default values
VAULT_ADDR=${VAULT_ADDR:-'http://127.0.0.1:8200'}
VAULT_TOKEN=${VAULT_TOKEN:-'dev-token'}
KEY_PREFIX=${KEY_PREFIX:-'jwt-key'}

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Export Vault environment variables
export VAULT_ADDR
export VAULT_TOKEN

echo -e "${YELLOW}Setting up Vault at ${VAULT_ADDR}${NC}"

# Check if vault is accessible
if ! vault status >/dev/null 2>&1; then
    echo "Error: Cannot connect to Vault at ${VAULT_ADDR}"
    echo "Make sure Vault is running and VAULT_ADDR/VAULT_TOKEN are correct"
    exit 1
fi

# Enable transit engine
echo -e "\n${YELLOW}Enabling transit secrets engine...${NC}"
vault secrets enable transit 2>/dev/null || true

# Create ECDSA keys
echo -e "\n${YELLOW}Creating ECDSA keys...${NC}"
for alg in "ES256:ecdsa-p256" "ES384:ecdsa-p384" "ES512:ecdsa-p521"; do
    IFS=":" read -r name type <<< "${alg}"
    echo -n "Creating ${KEY_PREFIX}-${name} (${type})... "
    if vault write -f "transit/keys/${KEY_PREFIX}-${name}" type="${type}" >/dev/null 2>&1; then
        echo -e "${GREEN}OK${NC}"
    else
        echo "already exists"
    fi
done

# Create RSA keys for PKCS1v15
echo -e "\n${YELLOW}Creating RSA keys (PKCS1v15)...${NC}"
for alg in "RS256:2048" "RS384:3072" "RS512:4096"; do
    IFS=":" read -r name size <<< "${alg}"
    echo -n "Creating ${KEY_PREFIX}-${name} (rsa-${size})... "
    if vault write -f "transit/keys/${KEY_PREFIX}-${name}" type="rsa-${size}" >/dev/null 2>&1; then
        echo -e "${GREEN}OK${NC}"
    else
        echo "already exists"
    fi
done

# Create RSA keys for PSS
echo -e "\n${YELLOW}Creating RSA keys (PSS)...${NC}"
for alg in "PS256:2048" "PS384:3072" "PS512:4096"; do
    IFS=":" read -r name size <<< "${alg}"
    echo -n "Creating ${KEY_PREFIX}-${name} (rsa-${size})... "
    if vault write -f "transit/keys/${KEY_PREFIX}-${name}" type="rsa-${size}" >/dev/null 2>&1; then
        echo -e "${GREEN}OK${NC}"
    else
        echo "already exists"
    fi
done

echo -e "\n${GREEN}Setup complete!${NC}"
echo "You can now use these keys with JWT-Vault-Go by setting:"
echo "- TransitKeyPath: \"${KEY_PREFIX}-[ALGORITHM]\""
echo "- Algorithm: \"[ALGORITHM]\""
echo "Example: ${KEY_PREFIX}-ES256 with Algorithm: \"ES256\""
