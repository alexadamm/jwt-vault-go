/*
Package token provides JWT (JSON Web Token) functionality using HashiCorp Vault's Transit engine
for signing and verification operations.

Basic usage:
```

	jv, err := token.New(token.Config{
	    VaultAddr:      "http://localhost:8200",
	    VaultToken:     "your-token",
	    TransitKeyPath: "jwt-key",
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
The package supports custom claims through struct embedding:
```

	type CustomClaims struct {
	    token.StandardClaims
	    UserID   string   `json:"user_id"`
	    Username string   `json:"username"`
	    Roles    []string `json:"roles"`
	}

```
Key rotation is supported through the RotateKey method:
```
err := jv.RotateKey(context.Background())
```
Health checking is also supported:
```
health, err := jv.Health(context.Background())
```
*/
package token
