#!/bin/sh

while ! nc -z localhost 8200; do   
    echo "Waiting for vault to start..."
    sleep 1
done

# set token for initialization
export VAULT_TOKEN="dev-root-token"

echo "Enabling transit engine..."
vault secrets enable transit

echo "Creating jwt signing key..."
vault write transit/keys/jwt-es256 type="ecdsa-p256"

# create sign policy
echo 'Creating signing policy...'
vault policy write sign-policy /vault/config/policies/sign-policy.hcl

echo 'Creating read policy...'
vault policy write read-policy /vault/config/policies/read-policy.hcl

# create tokens
echo 'Generating tokens...'
SIGN_TOKEN=$(vault token create -policy=sign-policy -format=json | jq -r '.auth.client_token')
READ_TOKEN=$(vault token create -policy=read-policy -format=json | jq -r '.auth.client_token')

echo "================ Vault Configuration ================"
echo "Vault URL: http://127.0.0.1:8200"
echo "Sign Token: ${SIGN_TOKEN}"
echo "Read Token: ${READ_TOKEN}"
echo "=================================================="
