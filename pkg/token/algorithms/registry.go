package algorithms

import "fmt"

var algorithms = make(map[string]Algorithm)

// Register adds an algorithm to the registry
// Called by algorithm implementations in their init() functions
// Each algorithm must have a unique name
func Register(alg Algorithm) {
	algorithms[alg.Name()] = alg
}

// Get retrieves an algorithm from the registry by name
// Returns ErrUnsupportedAlgorithm if algorithm not found
// Supported algorithms:
// - ES256, ES384, ES512 (ECDSA)
// - RS256, RS384, RS512 (RSA PKCS1v15)
// - PS256, PS384, PS512 (RSA-PSS)
func Get(name string) (Algorithm, error) {
	alg, exists := algorithms[name]
	if !exists {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedAlgorithm, name)
	}
	return alg, nil
}

// List returns all registered algorithm names
// Used for validating algorithm selection and documentation
func List() []string {
	var names []string
	for name := range algorithms {
		names = append(names, name)
	}
	return names
}
