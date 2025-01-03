#!/bin/bash
# note: requires VAULT_TOKEN and VAULT_ADDR to be set

# Rotate the jwt signing key
vault write -f transit/keys/jwt-key-ES256/rotate

CURRENT_VERSION=$(vault read -format=json transit/keys/jwt-key-ES256 | jq '.data.latest_version')

echo "Rotated JWT signing key to version ${CURRENT_VERSION}"

# Optional: clean up old versions (keep last 3)
if [ "$CURRENT_VERSION" -gt 3 ]; then
    MIN_VERSION=$((CURRENT_VERSION - 3))
    vault write transit/keys/jwt-key-ES256/trim min_available_version=$MIN_VERSION
    echo "Trimmed versions older than ${MIN_VERSION}"
fi
