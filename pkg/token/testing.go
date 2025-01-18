package token

import (
	"context"
)

// VaultClient interface for mocking
type VaultClient interface {
	GetCurrentKeyVersion() (int64, error)
	GetPublicKey(ctx context.Context, version string) (interface{}, error)
	SignData(ctx context.Context, data []byte, keyVersion int64) (string, error)
	RotateKey(ctx context.Context) error
}
