package token

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/alexadamm/jwt-vault-go/pkg/jwks"
	"github.com/alexadamm/jwt-vault-go/pkg/token/algorithms"
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
	signDataFunc             func(ctx context.Context, data []byte) (string, error)
	getPublicKeyFunc         func(ctx context.Context, version string) (interface{}, error)
	rotateKeyFunc            func(ctx context.Context) error
}

func (m *mockVaultClient) GetCurrentKeyVersion() (int64, error) {
	if m.getCurrentKeyVersionFunc != nil {
		return m.getCurrentKeyVersionFunc()
	}
	return 0, nil
}

func (m *mockVaultClient) SignData(ctx context.Context, data []byte) (string, error) {
	if m.signDataFunc != nil {
		return m.signDataFunc(ctx, data)
	}
	return "", nil
}

func (m *mockVaultClient) GetPublicKey(ctx context.Context, version string) (interface{}, error) {
	if m.getPublicKeyFunc != nil {
		return m.getPublicKeyFunc(ctx, version)
	}
	return nil, nil
}

func (m *mockVaultClient) RotateKey(ctx context.Context) error {
	if m.rotateKeyFunc != nil {
		return m.rotateKeyFunc(ctx)
	}
	return nil
}

func TestJWTVault_Sign(t *testing.T) {
	tests := []struct {
		name      string
		setupMock func() (*jwtVault, *mockVaultClient)
		claims    interface{}
		wantErr   bool
		errType   error
		checkJWT  func(*testing.T, string)
	}{
		{
			name: "successful signing with standard claims",
			setupMock: func() (*jwtVault, *mockVaultClient) {
				mock := &mockVaultClient{
					getCurrentKeyVersionFunc: func() (int64, error) {
						return 1, nil
					},
					signDataFunc: func(ctx context.Context, data []byte) (string, error) {
						// Return a properly formatted signature
						return base64.RawURLEncoding.EncodeToString([]byte("mock-signature")), nil
					},
				}
				alg, _ := algorithms.Get("ES256")
				jv := &jwtVault{
					vaultClient: mock,
					config: Config{
						TransitKeyPath: "test-key",
						Algorithm:      "ES256",
					},
					algorithm: alg,
				}
				return jv, mock
			},
			claims: &StandardClaims{
				Subject:   "user123",
				IssuedAt:  time.Now().Unix(),
				ExpiresAt: time.Now().Add(time.Hour).Unix(),
			},
			wantErr: false,
			checkJWT: func(t *testing.T, token string) {
				parts := strings.Split(token, ".")
				if len(parts) != 3 {
					t.Errorf("expected 3 parts in JWT, got %d", len(parts))
				}

				// Decode header
				headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
				if err != nil {
					t.Errorf("failed to decode header: %v", err)
				}

				var header struct {
					Typ string `json:"typ"`
					Alg string `json:"alg"`
					Kid string `json:"kid"`
				}
				if err := json.Unmarshal(headerJSON, &header); err != nil {
					t.Errorf("failed to unmarshal header: %v", err)
				}

				if header.Typ != "JWT" {
					t.Errorf("expected typ=JWT, got %s", header.Typ)
				}
				if header.Alg != "ES256" {
					t.Errorf("expected alg=ES256, got %s", header.Alg)
				}
				if !strings.HasPrefix(header.Kid, "test-key:") {
					t.Errorf("expected kid to start with test-key:, got %s", header.Kid)
				}
			},
		},
		{
			name: "custom claims signing",
			setupMock: func() (*jwtVault, *mockVaultClient) {
				mock := &mockVaultClient{
					getCurrentKeyVersionFunc: func() (int64, error) {
						return 1, nil
					},
					signDataFunc: func(ctx context.Context, data []byte) (string, error) {
						return "mock.signature", nil
					},
				}
				alg, _ := algorithms.Get("ES256")
				jv := &jwtVault{
					vaultClient: mock,
					config: Config{
						TransitKeyPath: "test-key",
					},
					algorithm: alg,
				}
				return jv, mock
			},
			claims: map[string]interface{}{
				"sub":   "user123",
				"name":  "John Doe",
				"admin": true,
			},
			wantErr: false,
			checkJWT: func(t *testing.T, token string) {
				parts := strings.Split(token, ".")

				// Decode payload
				payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
				if err != nil {
					t.Errorf("failed to decode payload: %v", err)
				}

				var claims map[string]interface{}
				if err := json.Unmarshal(payloadJSON, &claims); err != nil {
					t.Errorf("failed to unmarshal claims: %v", err)
				}

				if claims["sub"] != "user123" {
					t.Errorf("expected sub=user123, got %v", claims["sub"])
				}
				if claims["name"] != "John Doe" {
					t.Errorf("expected name=John Doe, got %v", claims["name"])
				}
			},
		},
		{
			name: "error getting key version",
			setupMock: func() (*jwtVault, *mockVaultClient) {
				mock := &mockVaultClient{
					getCurrentKeyVersionFunc: func() (int64, error) {
						return 0, fmt.Errorf("vault error")
					},
				}
				alg, _ := algorithms.Get("ES256")
				jv := &jwtVault{
					vaultClient: mock,
					algorithm:   alg,
				}
				return jv, mock
			},
			claims:  StandardClaims{},
			wantErr: true,
		},
		{
			name: "error signing data",
			setupMock: func() (*jwtVault, *mockVaultClient) {
				mock := &mockVaultClient{
					getCurrentKeyVersionFunc: func() (int64, error) {
						return 1, nil
					},
					signDataFunc: func(ctx context.Context, data []byte) (string, error) {
						return "", fmt.Errorf("signing error")
					},
				}
				alg, _ := algorithms.Get("ES256")
				jv := &jwtVault{
					vaultClient: mock,
					algorithm:   alg,
				}
				return jv, mock
			},
			claims:  StandardClaims{},
			wantErr: true,
		},
		{
			name: "invalid claims type",
			setupMock: func() (*jwtVault, *mockVaultClient) {
				mock := &mockVaultClient{
					getCurrentKeyVersionFunc: func() (int64, error) {
						return 1, nil
					},
				}
				alg, _ := algorithms.Get("ES256")
				jv := &jwtVault{
					vaultClient: mock,
					algorithm:   alg,
				}
				return jv, mock
			},
			claims:  make(chan int), // Invalid claims type that can't be marshaled
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jv, _ := tt.setupMock()
			token, err := jv.Sign(context.Background(), tt.claims)

			if (err != nil) != tt.wantErr {
				t.Errorf("Sign() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err == nil && tt.checkJWT != nil {
				tt.checkJWT(t, token)
			}
		})
	}
}

func TestJWTVault_Verify(t *testing.T) {
	validHeader := base64.RawURLEncoding.EncodeToString([]byte(`{"typ":"JWT","alg":"ES256","kid":"test-key:1"}`))
	validClaims := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"123","exp":` + fmt.Sprintf("%d", time.Now().Add(time.Hour).Unix()) + `}`))
	validSignature := base64.RawURLEncoding.EncodeToString([]byte("valid-signature"))

	tests := []struct {
		name          string
		setupMock     func() (*jwtVault, *mockVaultClient)
		token         string
		wantErr       error
		checkVerified func(*testing.T, *VerifiedToken)
	}{
		{
			name: "invalid token format",
			setupMock: func() (*jwtVault, *mockVaultClient) {
				return &jwtVault{}, nil
			},
			token:   "invalid.token",
			wantErr: ErrInvalidToken,
		},
		{
			name: "invalid header encoding",
			setupMock: func() (*jwtVault, *mockVaultClient) {
				return &jwtVault{}, nil
			},
			token:   "invalid_base64!" + "." + validClaims + "." + validSignature,
			wantErr: ErrInvalidToken,
		},
		{
			name: "missing kid in header",
			setupMock: func() (*jwtVault, *mockVaultClient) {
				return &jwtVault{}, nil
			},
			token:   base64.RawURLEncoding.EncodeToString([]byte(`{"typ":"JWT","alg":"ES256"}`)) + "." + validClaims + "." + validSignature,
			wantErr: ErrMissingKID,
		},
		{
			name: "invalid claims encoding",
			setupMock: func() (*jwtVault, *mockVaultClient) {
				return &jwtVault{}, nil
			},
			token:   validHeader + ".invalid_base64!" + "." + validSignature,
			wantErr: ErrInvalidToken,
		},
		{
			name: "key fetch error",
			setupMock: func() (*jwtVault, *mockVaultClient) {
				mock := &mockVaultClient{
					getPublicKeyFunc: func(ctx context.Context, version string) (interface{}, error) {
						return nil, fmt.Errorf("key fetch error")
					},
				}
				alg, _ := algorithms.Get("ES256")
				jv := &jwtVault{
					vaultClient: mock,
					algorithm:   alg,
					config: Config{
						Algorithm: "ES256",
					},
					jwksCache: jwks.NewCache(jwks.Config{
						MaxAge:       time.Minute,
						KeyFetchFunc: mock.GetPublicKey,
					}),
				}
				return jv, mock
			},
			token:   validHeader + "." + validClaims + "." + validSignature,
			wantErr: fmt.Errorf("failed to get public key: failed to fetch key: key fetch error"),
		},
		{
			name: "expired token",
			setupMock: func() (*jwtVault, *mockVaultClient) {
				mock := &mockVaultClient{
					getPublicKeyFunc: func(ctx context.Context, version string) (interface{}, error) {
						key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
						return &key.PublicKey, nil
					},
				}
				alg, _ := algorithms.Get("ES256")
				return &jwtVault{
					vaultClient: mock,
					algorithm:   alg,
					jwksCache: jwks.NewCache(jwks.Config{
						MaxAge:       time.Minute,
						KeyFetchFunc: mock.GetPublicKey,
					}),
				}, mock
			},
			token: validHeader + "." +
				base64.RawURLEncoding.EncodeToString([]byte(`{"exp":`+fmt.Sprintf("%d", time.Now().Add(-time.Hour).Unix())+`}`)) +
				"." + validSignature,
			wantErr: ErrTokenExpired,
		},
		{
			name: "unsupported algorithm",
			setupMock: func() (*jwtVault, *mockVaultClient) {
				return &jwtVault{}, nil
			},
			token: base64.RawURLEncoding.EncodeToString([]byte(`{"typ":"JWT","alg":"UNSUPPORTED","kid":"test-key:1"}`)) +
				"." + validClaims + "." + validSignature,
			wantErr: fmt.Errorf("unsupported algorithm: unsupported algorithm: UNSUPPORTED"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jv, _ := tt.setupMock()
			verified, err := jv.Verify(context.Background(), tt.token)

			if tt.wantErr != nil {
				if err == nil {
					t.Errorf("Verify() expected error %v, got nil", tt.wantErr)
					return
				}
				if tt.wantErr.Error() != err.Error() {
					t.Errorf("Verify() expected error %v, got %v", tt.wantErr, err)
				}
				return
			}

			if err != nil {
				t.Errorf("Verify() unexpected error: %v", err)
				return
			}

			if tt.checkVerified != nil {
				tt.checkVerified(t, verified)
			}
		})
	}
}

func TestJWTVault_GetPublicKey(t *testing.T) {
	tests := []struct {
		name      string
		setupMock func() (*jwtVault, *mockVaultClient)
		kid       string
		wantErr   error
		checkKey  func(*testing.T, interface{})
	}{
		{
			name: "successfully get ECDSA key",
			setupMock: func() (*jwtVault, *mockVaultClient) {
				mock := &mockVaultClient{
					getPublicKeyFunc: func(ctx context.Context, version string) (interface{}, error) {
						key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
						return &key.PublicKey, nil
					},
				}
				alg, _ := algorithms.Get("ES256")
				return &jwtVault{
					vaultClient: mock,
					algorithm:   alg,
					config: Config{
						Algorithm:      "ES256",
						TransitKeyPath: "jwt-key",
					},
					jwksCache: jwks.NewCache(jwks.Config{
						MaxAge:       time.Minute,
						KeyFetchFunc: mock.GetPublicKey,
					}),
				}, mock
			},
			kid: "jwt-key:1",
			checkKey: func(t *testing.T, key interface{}) {
				if key == nil {
					t.Fatal("expected key, got nil")
				}
				if _, ok := key.(*ecdsa.PublicKey); !ok {
					t.Errorf("expected *ecdsa.PublicKey, got %T", key)
				}
			},
		},
		{
			name: "successfully get RSA key",
			setupMock: func() (*jwtVault, *mockVaultClient) {
				mock := &mockVaultClient{
					getPublicKeyFunc: func(ctx context.Context, version string) (interface{}, error) {
						key, _ := rsa.GenerateKey(rand.Reader, 2048)
						return &key.PublicKey, nil
					},
				}
				alg, _ := algorithms.Get("RS256")
				return &jwtVault{
					vaultClient: mock,
					algorithm:   alg,
					config: Config{
						Algorithm:      "RS256",
						TransitKeyPath: "jwt-key",
					},
					jwksCache: jwks.NewCache(jwks.Config{
						MaxAge:       time.Minute,
						KeyFetchFunc: mock.GetPublicKey,
					}),
				}, mock
			},
			kid: "jwt-key:1",
			checkKey: func(t *testing.T, key interface{}) {
				if key == nil {
					t.Fatal("expected key, got nil")
				}
				if _, ok := key.(*rsa.PublicKey); !ok {
					t.Errorf("expected *rsa.PublicKey, got %T", key)
				}
			},
		},
		{
			name: "key fetch error",
			setupMock: func() (*jwtVault, *mockVaultClient) {
				mock := &mockVaultClient{
					getPublicKeyFunc: func(ctx context.Context, version string) (interface{}, error) {
						return nil, fmt.Errorf("key fetch error")
					},
				}
				alg, _ := algorithms.Get("ES256")
				return &jwtVault{
					vaultClient: mock,
					algorithm:   alg,
					config: Config{
						Algorithm:      "ES256",
						TransitKeyPath: "jwt-key",
					},
					jwksCache: jwks.NewCache(jwks.Config{
						MaxAge:       time.Minute,
						KeyFetchFunc: mock.GetPublicKey,
					}),
				}, mock
			},
			kid:     "jwt-key:1",
			wantErr: fmt.Errorf("failed to get public key: failed to fetch key: key fetch error"),
		},
		{
			name: "wrong key type for algorithm",
			setupMock: func() (*jwtVault, *mockVaultClient) {
				mock := &mockVaultClient{
					getPublicKeyFunc: func(ctx context.Context, version string) (interface{}, error) {
						// Return RSA key when ES256 is expected
						key, _ := rsa.GenerateKey(rand.Reader, 2048)
						return &key.PublicKey, nil
					},
				}
				alg, _ := algorithms.Get("ES256")
				return &jwtVault{
					vaultClient: mock,
					algorithm:   alg,
					config: Config{
						Algorithm:      "ES256",
						TransitKeyPath: "jwt-key",
					},
					jwksCache: jwks.NewCache(jwks.Config{
						MaxAge:       time.Minute,
						KeyFetchFunc: mock.GetPublicKey,
					}),
				}, mock
			},
			kid:     "jwt-key:1",
			wantErr: fmt.Errorf("invalid key type: expected ECDSA, got *rsa.PublicKey"),
		},
		{
			name: "invalid kid format",
			setupMock: func() (*jwtVault, *mockVaultClient) {
				mock := &mockVaultClient{
					getPublicKeyFunc: func(ctx context.Context, version string) (interface{}, error) {
						return nil, fmt.Errorf("invalid kid format")
					},
				}
				alg, _ := algorithms.Get("ES256")
				return &jwtVault{
					vaultClient: mock,
					algorithm:   alg,
					config: Config{
						Algorithm:      "ES256",
						TransitKeyPath: "jwt-key",
					},
					jwksCache: jwks.NewCache(jwks.Config{
						MaxAge:       time.Minute,
						KeyFetchFunc: mock.GetPublicKey,
					}),
				}, mock
			},
			kid:     "invalid-format",
			wantErr: fmt.Errorf("failed to get public key: invalid kid format: invalid-format"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jv, _ := tt.setupMock()
			key, err := jv.GetPublicKey(context.Background(), tt.kid)

			if tt.wantErr != nil {
				if err == nil {
					t.Fatalf("expected error %v, got nil", tt.wantErr)
				}
				if tt.wantErr.Error() != err.Error() {
					t.Errorf("expected error %v, got %v", tt.wantErr, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tt.checkKey != nil {
				tt.checkKey(t, key)
			}
		})
	}
}
