package jwks

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"strings"
	"sync"
	"time"
)

// KeyType represents the type of cryptographic key
type KeyType int

const (
	KeyTypeECDSA KeyType = iota
	KeyTypeRSA
)

// Cache represents a thread-safe cache for JWKS
type Cache struct {
	sync.RWMutex
	keys     map[string]*cachedKey
	maxAge   time.Duration
	keyFetch KeyFetchFunc
}

// cachedKey represents a cached public key with metadata
type cachedKey struct {
	key       interface{} // Can be *ecdsa.PublicKey or *rsa.PublicKey
	keyType   KeyType
	lastUsed  time.Time
	fetchedAt time.Time
}

// KeyFetchFunc defines how to retrieve a public key from the source
type KeyFetchFunc func(ctx context.Context, kid string) (interface{}, error)

// Config holds configuration for the JWKS cache
type Config struct {
	MaxAge          time.Duration
	CleanupInterval time.Duration
	KeyFetchFunc    KeyFetchFunc
}

// NewCache creates a new JWKS cache
func NewCache(config Config) *Cache {
	cache := &Cache{
		keys:     make(map[string]*cachedKey),
		maxAge:   config.MaxAge,
		keyFetch: config.KeyFetchFunc,
	}

	if config.CleanupInterval > 0 {
		go cache.startCleanup(config.CleanupInterval)
	}

	return cache
}

// GetKey retrieves a key from the cache or fetches it if not found/expired
func (c *Cache) GetKey(ctx context.Context, kid string) (interface{}, error) {
	if key := c.getFromCache(kid); key != nil {
		return key, nil
	}
	return c.fetchAndCache(ctx, kid)
}

// GetKeyWithType retrieves a key and its type from the cache
func (c *Cache) GetKeyWithType(ctx context.Context, kid string) (interface{}, KeyType, error) {
	c.RLock()
	if cached, exists := c.keys[kid]; exists && time.Since(cached.fetchedAt) < c.maxAge {
		cached.lastUsed = time.Now()
		c.RUnlock()
		return cached.key, cached.keyType, nil
	}
	c.RUnlock()

	key, err := c.fetchAndCache(ctx, kid)
	if err != nil {
		return nil, 0, err
	}

	c.RLock()
	defer c.RUnlock()
	cached := c.keys[kid]
	return key, cached.keyType, nil
}

func (c *Cache) getFromCache(kid string) interface{} {
	c.RLock()
	defer c.RUnlock()

	if cached, exists := c.keys[kid]; exists {
		if time.Since(cached.fetchedAt) < c.maxAge {
			cached.lastUsed = time.Now()
			return cached.key
		}
	}
	return nil
}

func (c *Cache) fetchAndCache(ctx context.Context, kid string) (interface{}, error) {
	c.Lock()
	defer c.Unlock()

	// Double check if another goroutine already fetched
	if cached, exists := c.keys[kid]; exists {
		if time.Since(cached.fetchedAt) < c.maxAge {
			cached.lastUsed = time.Now()
			return cached.key, nil
		}
	}

	// Parse key ID format (format: keypath:version)
	kidParts := strings.Split(kid, ":")
	if len(kidParts) != 2 {
		return nil, fmt.Errorf("invalid kid format: %s", kid)
	}

	key, err := c.keyFetch(ctx, kidParts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to fetch key: %w", err)
	}

	// Determine key type
	keyType, err := determineKeyType(key)
	if err != nil {
		return nil, fmt.Errorf("failed to determine key type: %w", err)
	}

	c.keys[kid] = &cachedKey{
		key:       key,
		keyType:   keyType,
		lastUsed:  time.Now(),
		fetchedAt: time.Now(),
	}

	return key, nil
}

// InvalidateKey removes a key from the cache
func (c *Cache) InvalidateKey(kid string) {
	c.Lock()
	defer c.Unlock()
	delete(c.keys, kid)
}

// Clear removes all keys from the cache
func (c *Cache) Clear() {
	c.Lock()
	defer c.Unlock()
	c.keys = make(map[string]*cachedKey)
}

func (c *Cache) startCleanup(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		c.cleanup()
	}
}

func (c *Cache) cleanup() {
	c.Lock()
	defer c.Unlock()

	now := time.Now()
	for kid, cached := range c.keys {
		if now.Sub(cached.fetchedAt) > c.maxAge ||
			now.Sub(cached.lastUsed) > 2*c.maxAge {
			delete(c.keys, kid)
		}
	}
}

// determineKeyType identifies the type of a public key
func determineKeyType(key interface{}) (KeyType, error) {
	switch key.(type) {
	case *ecdsa.PublicKey:
		return KeyTypeECDSA, nil
	case *rsa.PublicKey:
		return KeyTypeRSA, nil
	default:
		return 0, fmt.Errorf("unsupported key type: %T", key)
	}
}
