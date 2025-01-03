export VAULT_ADDR='http://127.0.0.1:8200'
export VAULT_TOKEN='your-root-token'

vault secrets enable transit

# Create ECDSA keys
echo "Creating ECDSA keys..."
vault write -f transit/keys/jwt-key-ES256 type=ecdsa-p256
vault write -f transit/keys/jwt-key-ES384 type=ecdsa-p384
vault write -f transit/keys/jwt-key-ES512 type=ecdsa-p521

# Create RSA keys for RSASSA-PKCS1-v1_5
echo "Creating RSA keys..."
vault write -f transit/keys/jwt-key-RS256 type=rsa-2048
vault write -f transit/keys/jwt-key-RS384 type=rsa-3072
vault write -f transit/keys/jwt-key-RS512 type=rsa-4096

# Create RSA keys for RSASSA-PSS
echo "Creating RSA-PSS keys..."
vault write transit/keys/jwt-key-PS256 type=rsa-2048 additional_config=pss
vault write transit/keys/jwt-key-PS384 type=rsa-3072 additional_config=pss
vault write transit/keys/jwt-key-PS512 type=rsa-4096 additional_config=pss

echo "All keys created successfully!"
