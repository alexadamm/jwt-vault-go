#!/bin/bash

# Default values
VAULT_ADDR=${VAULT_ADDR:-'http://127.0.0.1:8200'}
VAULT_TOKEN=${VAULT_TOKEN:-'dev-token'}
TEST_KEY_PREFIX="jwt-test"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# Export Vault environment variables
export VAULT_ADDR
export VAULT_TOKEN

echo -e "${YELLOW}Setting up test environment...${NC}"

# Check if vault is running
if ! vault status >/dev/null 2>&1; then
    echo -e "${RED}Error: Cannot connect to Vault at ${VAULT_ADDR}${NC}"
    echo "Start Vault in dev mode with:"
    echo "vault server -dev"
    exit 1
fi

# Enable transit engine
echo -e "\n${YELLOW}Enabling transit secrets engine...${NC}"
vault secrets enable transit 2>/dev/null || true

# Create test keys
echo -e "\n${YELLOW}Creating test keys...${NC}"

# Function to create test key
create_test_key() {
    local alg=$1
    local type=$2
    echo -n "Creating ${TEST_KEY_PREFIX}-${alg} (${type})... "
    if vault write -f "transit/keys/${TEST_KEY_PREFIX}-${alg,,}" type="${type}" >/dev/null 2>&1; then
        echo -e "${GREEN}OK${NC}"
    else
        echo "already exists"
    fi
}

# Create minimum required test keys
create_test_key "es256" "ecdsa-p256"
create_test_key "rs256" "rsa-2048"
create_test_key "ps256" "rsa-2048"

echo -e "\n${YELLOW}Running tests...${NC}"

# Run tests with race detection and coverage
go test -v -race -coverprofile=coverage.txt -covermode=atomic ./...
TEST_EXIT_CODE=$?

if [ $TEST_EXIT_CODE -eq 0 ]; then
    echo -e "\n${GREEN}All tests passed!${NC}"
    echo "Coverage report:"
    go tool cover -func=coverage.txt
else
    echo -e "\n${RED}Tests failed!${NC}"
fi

exit $TEST_EXIT_CODE
