package token

import "errors"

// Common errors
var (
	ErrInvalidToken          = errors.New("invalid token")
	ErrTokenExpired          = errors.New("token has expired")
	ErrTokenNotValidYet      = errors.New("token not valid yet")
	ErrTokenUsedBeforeIssued = errors.New("token used before issued")
	ErrInvalidSignature      = errors.New("invalid token signature")
	ErrMissingKID            = errors.New("token is missing key ID (kid)")
	ErrInvalidClaims         = errors.New("invalid token claims")
	ErrKeyNotFound           = errors.New("signing key not found")
	ErrVaultUnreachable      = errors.New("vault server is unreachable")
	ErrUnsupportedAlgorithm  = errors.New("unsupported signing algorithm")
)
