package vault

import (
	"context"
	"os"
	"testing"
)

func TestVaultClient(t *testing.T) {
	// Skip if not in integration test environment
	if os.Getenv("VAULT_ADDR") == "" {
		t.Skip("Skipping vault integration test (VAULT_ADDR not set)")
	}

	config := Config{
		Address:     os.Getenv("VAULT_ADDR"),
		Token:       os.Getenv("VAULT_TOKEN"),
		TransitPath: "jwt-test",
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("Failed to create vault client: %v", err)
	}

	t.Run("Get Key Version", func(t *testing.T) {
		version, err := client.GetCurrentKeyVersion()
		if err != nil {
			t.Errorf("Failed to get key version: %v", err)
		}
		if version < 1 {
			t.Error("Invalid key version")
		}
	})

	t.Run("Sign Data", func(t *testing.T) {
		data := []byte("test data")
		signature, err := client.SignData(context.Background(), data)
		if err != nil {
			t.Errorf("Failed to sign data: %v", err)
		}
		if len(signature) == 0 {
			t.Error("Empty signature returned")
		}
	})

	t.Run("Rotate Key", func(t *testing.T) {
		initialVersion := client.keyVersion
		err := client.RotateKey(context.Background())
		if err != nil {
			t.Errorf("Failed to rotate key: %v", err)
		}
		if client.keyVersion <= initialVersion {
			t.Error("Key version did not increase after rotation")
		}
	})
}
