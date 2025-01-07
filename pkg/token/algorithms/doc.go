/*
Package algorithms implements JWT signing algorithm support for use with Vault's Transit engine.

The package provides a registry of supported algorithms and their implementations.
Each algorithm handles its specific signing parameters and verification logic.

Supported Algorithms:
- ECDSA
  - ES256 (P-256 + SHA-256)
  - ES384 (P-384 + SHA-384)
  - ES512 (P-521 + SHA-512)

- RSA PKCS1v15
  - RS256 (RSA-2048 + SHA-256)
  - RS384 (RSA-3072 + SHA-384)
  - RS512 (RSA-4096 + SHA-512)

- RSA-PSS
  - PS256 (RSA-2048 + SHA-256)
  - PS384 (RSA-3072 + SHA-384)
  - PS512 (RSA-4096 + SHA-512)

Each algorithm implementation:
- Provides appropriate Vault signing parameters
- Handles signature verification
- Specifies required key types
- Manages cryptographic operations
*/
package algorithms
