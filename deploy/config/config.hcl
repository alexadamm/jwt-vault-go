storage "file" {
  path = "/vault/file"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = true  # For development only. Enable TLS in production.
}

# JWT tokens typically use 1 hour expiry, but Vault leases should be longer
max_lease_ttl = "168h"      # 7 days
default_lease_ttl = "24h"   # 1 day

disable_mlock = true

api_addr = "http://0.0.0.0:8200"
