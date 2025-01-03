#!/bin/sh

while ! nc -z localhost 8200; do   
    echo "Waiting for vault to start..."
    sleep 1
done

# Check if Vault is already initialized
if ! vault operator init -status; then
    echo "Initializing vault for the first time..."
    INIT_RESPONSE=$(vault operator init -format=json -key-shares=3 -key-threshold=2)
    
    echo "================ Vault Initial Configuration ================"
    echo "IMPORTANT: Save these keys and tokens securely!"
    echo
    echo "Root Token: $(echo "$INIT_RESPONSE" | jq -r '.root_token')"
    echo
    echo "Unseal Key 1: $(echo "$INIT_RESPONSE" | jq -r '.unseal_keys_b64[0]')"
    echo "Unseal Key 2: $(echo "$INIT_RESPONSE" | jq -r '.unseal_keys_b64[1]')"
    echo "Unseal Key 3: $(echo "$INIT_RESPONSE" | jq -r '.unseal_keys_b64[2]')"
    echo
    echo "========================================================"

    # Save to file for this demo (in production, handle these securely!)
    echo "$INIT_RESPONSE" > /vault/file/init.json
    
    # Get unseal keys and root token
    UNSEAL_KEY_1=$(echo "$INIT_RESPONSE" | jq -r '.unseal_keys_b64[0]')
    UNSEAL_KEY_2=$(echo "$INIT_RESPONSE" | jq -r '.unseal_keys_b64[1]')
    ROOT_TOKEN=$(echo "$INIT_RESPONSE" | jq -r '.root_token')
    
    # Unseal Vault
    vault operator unseal "$UNSEAL_KEY_1"
    vault operator unseal "$UNSEAL_KEY_2"
    
    # Login with root token
    vault login "$ROOT_TOKEN"

    echo "Enabling transit engine..."
    vault secrets enable transit
    
    echo "Creating jwt signing key..."
    vault write transit/keys/jwt-es256 type="ecdsa-p256"
    
    echo 'Creating signing policy...'
    vault policy write sign-policy /vault/config/policies/sign-policy.hcl
    
    echo 'Creating read policy...'
    vault policy write read-policy /vault/config/policies/read-policy.hcl
    
    # create tokens
    echo 'Generating tokens...'
    SIGN_TOKEN=$(vault token create -policy=sign-policy -format=json | jq -r '.auth.client_token')
    READ_TOKEN=$(vault token create -policy=read-policy -format=json | jq -r '.auth.client_token')
    
    # Save tokens to file
    echo "$SIGN_TOKEN" > /vault/file/sign_token
    echo "$READ_TOKEN" > /vault/file/read_token
    
    echo "================ Vault Configuration ================"
    echo "Vault URL: http://127.0.0.1:8200"
    echo "Sign Token: ${SIGN_TOKEN}"
    echo "Read Token: ${READ_TOKEN}"
    echo "=================================================="
else
    echo "Vault is already initialized, unsealing..."
    if [ -f "/vault/file/init.json" ]; then
        UNSEAL_KEY_1=$(jq -r '.unseal_keys_b64[0]' /vault/file/init.json)
        UNSEAL_KEY_2=$(jq -r '.unseal_keys_b64[1]' /vault/file/init.json)
        
        vault operator unseal "$UNSEAL_KEY_1"
        vault operator unseal "$UNSEAL_KEY_2"
    fi
fi

# Keep container running
tail -f /dev/null
