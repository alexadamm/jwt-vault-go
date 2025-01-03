package jwks

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"
	"time"
)

func TestCache(t *testing.T) {
	// Generate test keys
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	fetchCount := 0
	mockFetch := func(ctx context.Context, version string) (interface{}, error) {
		fetchCount++
		switch version {
		case "1":
			return &ecKey.PublicKey, nil
		case "2":
			return &rsaKey.PublicKey, nil
		default:
			return nil, errors.New("key not found")
		}
	}

	cache := NewCache(Config{
		MaxAge:          100 * time.Millisecond,
		CleanupInterval: 50 * time.Millisecond,
		KeyFetchFunc:    mockFetch,
	})

	t.Run("Get ECDSA Key", func(t *testing.T) {
		key, err := cache.GetKey(context.Background(), "valid-key:1")
		if err != nil {
			t.Errorf("GetKey failed: %v", err)
		}
		if key == nil {
			t.Error("Expected key, got nil")
		}
		if _, ok := key.(*ecdsa.PublicKey); !ok {
			t.Error("Expected ECDSA key")
		}
		if fetchCount != 1 {
			t.Errorf("Expected 1 fetch, got %d", fetchCount)
		}

		// Second fetch should use cache
		_, err = cache.GetKey(context.Background(), "valid-key:1")
		if err != nil {
			t.Errorf("Second GetKey failed: %v", err)
		}
		if fetchCount != 1 {
			t.Error("Expected cache hit")
		}
	})

	t.Run("Get RSA Key", func(t *testing.T) {
		key, err := cache.GetKey(context.Background(), "valid-key:2")
		if err != nil {
			t.Errorf("GetKey failed: %v", err)
		}
		if key == nil {
			t.Error("Expected key, got nil")
		}
		if _, ok := key.(*rsa.PublicKey); !ok {
			t.Error("Expected RSA key")
		}
	})

	t.Run("Get Key With Type", func(t *testing.T) {
		key, keyType, err := cache.GetKeyWithType(context.Background(), "valid-key:1")
		if err != nil {
			t.Errorf("GetKeyWithType failed: %v", err)
		}
		if keyType != KeyTypeECDSA {
			t.Error("Expected ECDSA key type")
		}
		if _, ok := key.(*ecdsa.PublicKey); !ok {
			t.Error("Expected ECDSA key")
		}

		key, keyType, err = cache.GetKeyWithType(context.Background(), "valid-key:2")
		if err != nil {
			t.Errorf("GetKeyWithType failed: %v", err)
		}
		if keyType != KeyTypeRSA {
			t.Error("Expected RSA key type")
		}
		if _, ok := key.(*rsa.PublicKey); !ok {
			t.Error("Expected RSA key")
		}
	})

	t.Run("Get Invalid Key", func(t *testing.T) {
		_, err := cache.GetKey(context.Background(), "invalid-key:3")
		if err == nil {
			t.Error("Expected error for invalid key")
		}
	})

	t.Run("Key Expiration", func(t *testing.T) {
		initialCount := fetchCount
		time.Sleep(150 * time.Millisecond)

		_, err := cache.GetKey(context.Background(), "valid-key:1")
		if err != nil {
			t.Errorf("GetKey after expiry failed: %v", err)
		}
		if fetchCount != initialCount+1 {
			t.Error("Expected new fetch after expiry")
		}
	})

	t.Run("Invalid KID Format", func(t *testing.T) {
		_, err := cache.GetKey(context.Background(), "invalid-format")
		if err == nil {
			t.Error("Expected error for invalid KID format")
		}
	})
}

func TestKeyTypeDetection(t *testing.T) {
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	tests := []struct {
		name     string
		key      interface{}
		wantType KeyType
		wantErr  bool
	}{
		{
			name:     "ECDSA Key",
			key:      &ecKey.PublicKey,
			wantType: KeyTypeECDSA,
			wantErr:  false,
		},
		{
			name:     "RSA Key",
			key:      &rsaKey.PublicKey,
			wantType: KeyTypeRSA,
			wantErr:  false,
		},
		{
			name:     "Unsupported Key",
			key:      "not a key",
			wantType: 0,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotType, err := determineKeyType(tt.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("determineKeyType() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotType != tt.wantType {
				t.Errorf("determineKeyType() = %v, want %v", gotType, tt.wantType)
			}
		})
	}
}
