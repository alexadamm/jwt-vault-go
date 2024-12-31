package jwks

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"
	"time"
)

func TestCache(t *testing.T) {
	testKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	fetchCount := 0
	mockFetch := func(ctx context.Context, kid string) (*ecdsa.PublicKey, error) {
		fetchCount++
		if kid == "valid-key" {
			return &testKey.PublicKey, nil
		}
		return nil, errors.New("key not found")
	}

	cache := NewCache(Config{
		MaxAge:          100 * time.Millisecond,
		CleanupInterval: 50 * time.Millisecond,
		KeyFetchFunc:    mockFetch,
	})

	t.Run("Get Valid Key", func(t *testing.T) {
		key, err := cache.GetKey(context.Background(), "valid-key")
		if err != nil {
			t.Errorf("GetKey failed: %v", err)
		}
		if key == nil {
			t.Error("Expected key, got nil")
		}
		if fetchCount != 1 {
			t.Errorf("Expected 1 fetch, got %d", fetchCount)
		}

		// Second fetch should use cache
		_, err = cache.GetKey(context.Background(), "valid-key")
		if err != nil {
			t.Errorf("Second GetKey failed: %v", err)
		}
		if fetchCount != 1 {
			t.Error("Expected cache hit")
		}
	})

	t.Run("Get Invalid Key", func(t *testing.T) {
		_, err := cache.GetKey(context.Background(), "invalid-key")
		if err == nil {
			t.Error("Expected error for invalid key")
		}
	})

	t.Run("Key Expiration", func(t *testing.T) {
		initialCount := fetchCount
		time.Sleep(150 * time.Millisecond)

		_, err := cache.GetKey(context.Background(), "valid-key")
		if err != nil {
			t.Errorf("GetKey after expiry failed: %v", err)
		}
		if fetchCount != initialCount+1 {
			t.Error("Expected new fetch after expiry")
		}
	})
}
