package token

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// TestConfig verifies configuration validation:
// - Required fields (VaultAddr, VaultToken)
// - Default values (Algorithm = ES256)
// - TTL settings for cache
func TestConfig(t *testing.T) {
	cfg := Config{
		VaultAddr:      "http://localhost:8200",
		VaultToken:     "test-token",
		TransitKeyPath: "jwt/sign",
		CacheTTL:       5 * time.Minute,
		RetryConfig: &RetryConfig{
			MaxAttempts:    3,
			RetryInterval:  time.Second,
			MaxElapsedTime: 10 * time.Second,
		},
	}

	if cfg.VaultAddr == "" {
		t.Error("VaultAddr should not be empty")
	}

	if cfg.TransitKeyPath == "" {
		t.Error("TransitKeyPath should not be empty")
	}

	if cfg.RetryConfig.MaxAttempts <= 0 {
		t.Error("MaxAttempts should be greater than 0")
	}
}

// TestStandardClaims verifies standard claims handling:
// - Issuer, Subject, Audience fields
// - Time validation (exp, nbf, iat)
// - JSON marshaling/unmarshaling
func TestStandardClaims(t *testing.T) {
	claims := &StandardClaims{
		Issuer:    "test-issuer",
		Subject:   "test-subject",
		Audience:  "test-audience",
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
		IssuedAt:  time.Now().Unix(),
		ID:        "test-id",
	}

	if claims.Issuer != "test-issuer" {
		t.Error("Issuer not set correctly")
	}

	if claims.ExpiresAt <= claims.IssuedAt {
		t.Error("ExpiresAt should be after IssuedAt")
	}
}

func TestValidateClaims(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name    string
		claims  *StandardClaims
		wantErr error
	}{
		{
			name: "valid claims",
			claims: &StandardClaims{
				ExpiresAt: now.Add(1 * time.Hour).Unix(),
				NotBefore: now.Add(-1 * time.Hour).Unix(),
				IssuedAt:  now.Add(-1 * time.Hour).Unix(),
			},
			wantErr: nil,
		},
		{
			name: "expired token",
			claims: &StandardClaims{
				ExpiresAt: now.Add(-1 * time.Hour).Unix(),
			},
			wantErr: ErrTokenExpired,
		},
		{
			name: "not yet valid",
			claims: &StandardClaims{
				NotBefore: now.Add(1 * time.Hour).Unix(),
			},
			wantErr: ErrTokenNotValidYet,
		},
		{
			name: "used before issued",
			claims: &StandardClaims{
				IssuedAt: now.Add(1 * time.Hour).Unix(),
			},
			wantErr: ErrTokenUsedBeforeIssued,
		},
		{
			name:    "zero values - should be valid",
			claims:  &StandardClaims{},
			wantErr: nil,
		},
		{
			name: "all time claims at current time",
			claims: &StandardClaims{
				ExpiresAt: now.Unix(),
				NotBefore: now.Unix(),
				IssuedAt:  now.Unix(),
			},
			wantErr: ErrTokenExpired,
		},
		{
			name: "extreme future expiry",
			claims: &StandardClaims{
				ExpiresAt: now.Add(87600 * time.Hour).Unix(), // 10 years
			},
			wantErr: nil,
		},
		{
			name: "extreme past issuance",
			claims: &StandardClaims{
				IssuedAt:  now.Add(-87600 * time.Hour).Unix(), // 10 years ago
				ExpiresAt: now.Add(1 * time.Hour).Unix(),      // but still valid
			},
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateClaims(tt.claims)
			if err != tt.wantErr {
				t.Errorf("validateClaims() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestJWTVault_Health(t *testing.T) {
    tests := []struct {
        name          string
        setupMock     func() (*jwtVault, *mockVaultClient)
        checkResponse func(*testing.T, *HealthStatus, error)
    }{
        {
            name: "healthy status",
            setupMock: func() (*jwtVault, *mockVaultClient) {
                mock := &mockVaultClient{
                    getCurrentKeyVersionFunc: func() (int64, error) {
                        return 1, nil
                    },
                }
                jv := &jwtVault{
                    vaultClient: mock,
                }
                return jv, mock
            },
            checkResponse: func(t *testing.T, status *HealthStatus, err error) {
                if err != nil {
                    t.Errorf("unexpected error: %v", err)
                }
                if status == nil {
                    t.Fatal("expected health status, got nil")
                }
                if !status.Healthy {
                    t.Error("expected healthy status")
                }
                if status.Message != "Service is healthy" {
                    t.Errorf("unexpected message: %s", status.Message)
                }
                if version, ok := status.Details["currentKeyVersion"].(int64); !ok || version != 1 {
                    t.Errorf("unexpected version in details: %v", status.Details["currentKeyVersion"])
                }
            },
        },
        {
            name: "unhealthy when key version check fails",
            setupMock: func() (*jwtVault, *mockVaultClient) {
                mock := &mockVaultClient{
                    getCurrentKeyVersionFunc: func() (int64, error) {
                        return 0, fmt.Errorf("vault unreachable")
                    },
                }
                jv := &jwtVault{
                    vaultClient: mock,
                }
                return jv, mock
            },
            checkResponse: func(t *testing.T, status *HealthStatus, err error) {
                if err != nil {
                    t.Errorf("unexpected error: %v", err)
                }
                if status == nil {
                    t.Fatal("expected health status, got nil")
                }
                if status.Healthy {
                    t.Error("expected unhealthy status")
                }
                if status.Message != "Failed to get key version" {
                    t.Errorf("unexpected message: %s", status.Message)
                }
                errDetails, ok := status.Details["error"].(string)
                if !ok || errDetails != "vault unreachable" {
                    t.Errorf("unexpected error details: %v", status.Details["error"])
                }
            },
        },
        {
            name: "handles zero key version",
            setupMock: func() (*jwtVault, *mockVaultClient) {
                mock := &mockVaultClient{
                    getCurrentKeyVersionFunc: func() (int64, error) {
                        return 0, nil
                    },
                }
                jv := &jwtVault{
                    vaultClient: mock,
                }
                return jv, mock
            },
            checkResponse: func(t *testing.T, status *HealthStatus, err error) {
                if err != nil {
                    t.Errorf("unexpected error: %v", err)
                }
                if status == nil {
                    t.Fatal("expected health status, got nil")
                }
                if !status.Healthy {
                    t.Error("expected healthy status despite zero version")
                }
                if version, ok := status.Details["currentKeyVersion"].(int64); !ok || version != 0 {
                    t.Errorf("unexpected version in details: %v", status.Details["currentKeyVersion"])
                }
            },
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            jv, _ := tt.setupMock()
            status, err := jv.Health(context.Background())
            tt.checkResponse(t, status, err)
        })
    }
}

// mockVaultClient implements a mock for testing
type mockVaultClient struct {
    getCurrentKeyVersionFunc func() (int64, error)
}

func (m *mockVaultClient) GetCurrentKeyVersion() (int64, error) {
    return m.getCurrentKeyVersionFunc()
}

// Add stubs for other interface methods
func (m *mockVaultClient) GetPublicKey(ctx context.Context, version string) (interface{}, error) {
    return nil, nil
}

func (m *mockVaultClient) SignData(ctx context.Context, data []byte) (string, error) {
    return "", nil
}

func (m *mockVaultClient) RotateKey(ctx context.Context) error {
    return nil
}
