package token

import "errors"

// Common errors returned by JWT-Vault operations
var (
	// ErrInvalidToken is returned when the token format is invalid
	// This includes malformed base64, invalid number of segments, etc.
	ErrInvalidToken = errors.New("invalid token")

	// ErrTokenExpired is returned when the token's "exp" claim is in the past
	ErrTokenExpired = errors.New("token has expired")

	// ErrTokenNotValidYet is returned when the token's "nbf" claim is in the future
	ErrTokenNotValidYet = errors.New("token not valid yet")

	// ErrTokenUsedBeforeIssued is returned when the token's "iat" claim is in the future
	ErrTokenUsedBeforeIssued = errors.New("token used before issued")

	// ErrInvalidSignature is returned when signature verification fails
	ErrInvalidSignature = errors.New("invalid token signature")

	// ErrMissingKID is returned when the token header lacks a "kid" claim
	ErrMissingKID = errors.New("token is missing key ID (kid)")

	// ErrInvalidClaims is returned when claims fail to parse or validate
	ErrInvalidClaims = errors.New("invalid token claims")

	// ErrKeyNotFound is returned when the signing key is not found in Vault
	ErrKeyNotFound = errors.New("signing key not found")

	// ErrVaultUnreachable is returned when Vault server is not accessible
	ErrVaultUnreachable = errors.New("vault server is unreachable")

	// ErrUnsupportedAlgorithm is returned when the specified algorithm is not supported
	ErrUnsupportedAlgorithm = errors.New("unsupported signing algorithm")
)
