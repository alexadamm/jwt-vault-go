package algorithms

import (
	"crypto"
	"errors"
	"testing"
)

func TestRegistry(t *testing.T) {
	// Test registering a mock algorithm
	mockAlg := &mockAlgorithm{name: "MOCK256"}
	Register(mockAlg)

	// Test retrieving algorithm
	t.Run("Get existing algorithm", func(t *testing.T) {
		alg, err := Get("MOCK256")
		if err != nil {
			t.Errorf("Expected no error, got %v", err)
		}
		if alg.Name() != "MOCK256" {
			t.Errorf("Expected MOCK256, got %s", alg.Name())
		}
	})

	t.Run("Get non-existent algorithm", func(t *testing.T) {
		_, err := Get("NONEXISTENT")
		if err == nil {
			t.Error("Expected error for non-existent algorithm")
		}
		if !errorContains(err, ErrUnsupportedAlgorithm) {
			t.Errorf("Expected error containing %v, got %v", ErrUnsupportedAlgorithm, err)
		}
	})

	t.Run("List registered algorithms", func(t *testing.T) {
		algList := List()
		found := false
		for _, name := range algList {
			if name == "MOCK256" {
				found = true
				break
			}
		}
		if !found {
			t.Error("Expected MOCK256 in algorithm list")
		}
	})
}

// Mock algorithm for testing
type mockAlgorithm struct {
	name string
	BaseAlgorithm
}

func (m *mockAlgorithm) Name() string {
	return m.name
}

func (m *mockAlgorithm) Hash() crypto.Hash {
	return crypto.SHA256
}

func (m *mockAlgorithm) VaultKeyType() string {
	return "mock"
}

func (m *mockAlgorithm) SigningParams() map[string]interface{} {
	return map[string]interface{}{
		"key": "value",
	}
}

func (m *mockAlgorithm) Verify(message, signature []byte, key interface{}) error {
	return nil
}

func (m *mockAlgorithm) KeyCheck(key interface{}) error {
	return nil
}

// Helper function to check if an error contains a specific error
func errorContains(err, target error) bool {
	return errors.Is(err, target)
}
