path "transit/sign/jwt-key-ES256" {
  capabilities = ["create", "update"]
}

path "transit/keys/jwt-key-ES256" {
  capabilities = ["read"]
}

path "transit/keys/jwt-key-ES256/rotate" {
  capabilities = ["update"]
}
