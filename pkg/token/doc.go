/*
Package token provides JWT (JSON Web Token) functionality using HashiCorp Vault's Transit engine
for signing and verification operations.

Basic usage:
```

	jv, err := token.New(token.Config{
	    VaultAddr:      "http://localhost:8200",
	    VaultToken:     "your-token",
	    TransitKeyPath: "jwt-key",
	    Algorithm:      "ES256", // Supports ES256, ES384, ES512, RS256, RS384, RS512, PS256, PS384, PS512
	})

	if err != nil {
	    log.Fatal(err)
	}

	// Create and sign a token
	claims := map[string]interface{}{
	    "sub": "1234567890",
	    "name": "John Doe",
	}

	token, err := jv.Sign(context.Background(), claims)

	// Verify a token
	verified, err := jv.Verify(context.Background(), token)

```

Algorithm Support:
- ECDSA: ES256 (P-256), ES384 (P-384), ES512 (P-521)
- RSA: RS256, RS384, RS512 (PKCS1v15 padding)
- RSA-PSS: PS256, PS384, PS512

Vault Configuration:
The library uses Vault's Transit engine with JWS marshaling for signatures.
Required Vault key types:
- For ES256: ecdsa-p256
- For ES384: ecdsa-p384
- For ES512: ecdsa-p521
- For RS256/PS256: rsa-2048
- For RS384/PS384: rsa-3072
- For RS512/PS512: rsa-4096

Custom Claims Example:
```

	type CustomClaims struct {
	    token.StandardClaims
	    UserID   string   `json:"user_id"`
	    Username string   `json:"username"`
	    Roles    []string `json:"roles"`
	}

	claims := CustomClaims{
	    StandardClaims: token.StandardClaims{
	        Issuer:    "my-app",
	        Subject:   "user-123",
	        IssuedAt:  time.Now().Unix(),
	        ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
	    },
	    UserID:   "user-123",
	    Username: "johndoe",
	    Roles:    []string{"user", "admin"},
	}

```

Key Rotation:
```

	// Rotate the signing key
	err := jv.RotateKey(context.Background())

	// Old tokens will still be valid after rotation
	// New tokens will use the new key version

```

Health Checking:
```

	health, err := jv.Health(context.Background())

```
*/
package token
