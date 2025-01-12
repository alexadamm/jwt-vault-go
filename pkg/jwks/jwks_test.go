package jwks

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestCache verifies JWKS caching functionality:
// - Key retrieval and caching
// - Type identification (ECDSA vs RSA)
// - Cache expiration and cleanup
// - Error handling for invalid keys
// No Vault instance required - uses mock keys
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

// TestKeyTypeDetection verifies key type detection:
// - ECDSA key detection with different curves
// - RSA key detection with different sizes
// - Error handling for unsupported key types
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

func TestCacheConcurrency(t *testing.T) {
	// Generate test keys
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	fetchCount := 0
	var fetchMutex sync.Mutex
	mockFetch := func(ctx context.Context, version string) (interface{}, error) {
		fetchMutex.Lock()
		fetchCount++
		fetchMutex.Unlock()
		return &ecKey.PublicKey, nil
	}

	cache := NewCache(Config{
		MaxAge:          100 * time.Millisecond,
		CleanupInterval: 50 * time.Millisecond,
		KeyFetchFunc:    mockFetch,
	})

	// Test concurrent access
	const numGoroutines = 10
	const numRequests = 100
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < numRequests; j++ {
				key, err := cache.GetKey(context.Background(), "test-key:1")
				if err != nil {
					t.Errorf("GetKey failed: %v", err)
				}
				if key == nil {
					t.Error("Expected key, got nil")
				}
				time.Sleep(time.Millisecond) // Simulate some work
			}
		}()
	}

	wg.Wait()

	// Should have far fewer fetches than requests due to caching
	if fetchCount >= numGoroutines*numRequests {
		t.Errorf("Expected caching to reduce fetch count, got %d fetches for %d requests",
			fetchCount, numGoroutines*numRequests)
	}
}

func TestCacheEviction(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	fetchCount := make(map[string]int)
	var fetchMutex sync.Mutex
	mockFetch := func(ctx context.Context, version string) (interface{}, error) {
		fetchMutex.Lock()
		defer fetchMutex.Unlock()
		fetchCount[version]++
		return &ecKey.PublicKey, nil
	}

	// Use longer durations to avoid flaky tests
	maxAge := 200 * time.Millisecond
	cache := NewCache(Config{
		MaxAge:          maxAge,
		CleanupInterval: maxAge / 2,
		KeyFetchFunc:    mockFetch,
	})

	getFetchCount := func(version string) int {
		fetchMutex.Lock()
		defer fetchMutex.Unlock()
		return fetchCount[version]
	}

	validateKey := func(t *testing.T, key interface{}, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("GetKey failed: %v", err)
		}
		if key == nil {
			t.Fatal("Expected key, got nil")
		}
		if _, ok := key.(*ecdsa.PublicKey); !ok {
			t.Fatal("Expected ECDSA public key")
		}
	}

	t.Run("cache hit", func(t *testing.T) {
		// First fetch
		key, err := cache.GetKey(context.Background(), "key1:1")
		validateKey(t, key, err)
		initialCount := getFetchCount("1")

		// Immediate second fetch - should hit cache
		key, err = cache.GetKey(context.Background(), "key1:1")
		validateKey(t, key, err)
		if getFetchCount("1") != initialCount {
			t.Error("Expected cache hit, got cache miss")
		}
	})

	t.Run("cache expiry", func(t *testing.T) {
		// First fetch
		key, err := cache.GetKey(context.Background(), "key2:1")
		validateKey(t, key, err)
		initialCount := getFetchCount("1")

		// Wait for cache to expire
		time.Sleep(maxAge * 2)

		// Second fetch - should miss cache
		key, err = cache.GetKey(context.Background(), "key2:1")
		validateKey(t, key, err)
		if getFetchCount("1") <= initialCount {
			t.Error("Expected cache miss after expiry")
		}
	})

	t.Run("different keys", func(t *testing.T) {
		initialCount := getFetchCount("1")

		// Fetch different keys
		for _, kid := range []string{"key3:1", "key4:1"} {
			key, err := cache.GetKey(context.Background(), kid)
			validateKey(t, key, err)
		}

		if getFetchCount("1") != initialCount+2 {
			t.Error("Expected separate cache entries for different keys")
		}
	})
}

func TestCacheErrorHandling(t *testing.T) {
	mockFetch := func(ctx context.Context, version string) (interface{}, error) {
		switch version {
		case "error":
			return nil, errors.New("fetch error")
		case "nil":
			return nil, nil
		case "invalid":
			return "not a key", nil
		default:
			key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			return &key.PublicKey, nil
		}
	}

	cache := NewCache(Config{
		MaxAge:          100 * time.Millisecond,
		CleanupInterval: 50 * time.Millisecond,
		KeyFetchFunc:    mockFetch,
	})

	testCases := []struct {
		name        string
		keyID       string
		wantErr     bool
		errContains string
	}{
		{
			name:        "fetch error",
			keyID:       "test:error",
			wantErr:     true,
			errContains: "fetch error",
		},
		{
			name:        "nil key",
			keyID:       "test:nil",
			wantErr:     true,
			errContains: "unsupported key type: <nil>", // Updated error message
		},
		{
			name:        "invalid key type",
			keyID:       "test:invalid",
			wantErr:     true,
			errContains: "unsupported key type",
		},
		{
			name:        "invalid key format",
			keyID:       "invalid-format",
			wantErr:     true,
			errContains: "invalid kid format",
		},
		{
			name:        "valid key",
			keyID:       "test:valid",
			wantErr:     false,
			errContains: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			key, err := cache.GetKey(context.Background(), tc.keyID)
			if tc.wantErr {
				if err == nil {
					t.Error("Expected error, got nil")
				} else if !strings.Contains(err.Error(), tc.errContains) {
					t.Errorf("Expected error containing %q, got %v", tc.errContains, err)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if key == nil {
					t.Error("Expected key, got nil")
				}
			}
		})
	}
}

func TestCacheInvalidation(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	fetchCount := 0
	mockFetch := func(ctx context.Context, version string) (interface{}, error) {
		fetchCount++
		return &ecKey.PublicKey, nil
	}

	cache := NewCache(Config{
		MaxAge:          time.Hour, // Long enough to not expire during test
		CleanupInterval: time.Hour,
		KeyFetchFunc:    mockFetch,
	})

	// Get key to populate cache
	keyID := "test:1"
	_, err = cache.GetKey(context.Background(), keyID)
	if err != nil {
		t.Fatalf("Initial GetKey failed: %v", err)
	}
	initialFetchCount := fetchCount

	// Get key again - should use cache
	_, err = cache.GetKey(context.Background(), keyID)
	if err != nil {
		t.Fatalf("Second GetKey failed: %v", err)
	}
	if fetchCount != initialFetchCount {
		t.Error("Expected cache hit, got cache miss")
	}

	// Invalidate key
	cache.InvalidateKey(keyID)

	// Get key again - should fetch
	_, err = cache.GetKey(context.Background(), keyID)
	if err != nil {
		t.Fatalf("GetKey after invalidation failed: %v", err)
	}
	if fetchCount != initialFetchCount+1 {
		t.Error("Expected cache miss after invalidation")
	}

	// Clear all keys
	cache.Clear()

	// Get key again - should fetch
	_, err = cache.GetKey(context.Background(), keyID)
	if err != nil {
		t.Fatalf("GetKey after clear failed: %v", err)
	}
	if fetchCount != initialFetchCount+2 {
		t.Error("Expected cache miss after clear")
	}
}
