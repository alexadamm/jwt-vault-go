/*
Package vault provides a client for interacting with HashiCorp Vault's Transit engine.

The package handles signing operations and public key retrieval for JWT operations.
It supports multiple key types and algorithms through Vault's Transit engine.

Supported Key Types:
- ECDSA: P-256, P-384, P-521
- RSA: 2048, 3072, 4096 bits
- RSA-PSS: Same key sizes as RSA

Key Operations:
- Signing with JWS format
- Public key retrieval
- Key rotation
- Key version management

The client automatically handles:
- Signature marshaling (JWS format)
- Key type compatibility
- Version tracking
*/
package vault
