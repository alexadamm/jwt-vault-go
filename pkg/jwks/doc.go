/*
Package jwks provides JWKS (JSON Web Key Set) cache functionality for JWT verification.

The package implements caching and retrieval of public keys from HashiCorp Vault's Transit engine.
It supports both ECDSA and RSA keys, with automatic key rotation handling.

Basic usage:

	cache := jwks.NewCache(jwks.Config{
	    MaxAge:          5 * time.Minute,
	    CleanupInterval: time.Minute,
	    KeyFetchFunc:    vaultClient.GetPublicKey,
	})

	// Get key with type detection
	key, keyType, err := cache.GetKeyWithType(ctx, "key-id")

Keys are cached based on their ID and automatically refreshed based on MaxAge configuration.
*/
package jwks
