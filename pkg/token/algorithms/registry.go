package algorithms

import "fmt"

var algorithms = make(map[string]Algorithm)

// Register adds an algorithm to the registry
func Register(alg Algorithm) {
	algorithms[alg.Name()] = alg
}

// Get retrieves an algorithm from the registry
func Get(name string) (Algorithm, error) {
	alg, exists := algorithms[name]
	if !exists {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedAlgorithm, name)
	}
	return alg, nil
}

// List returns all registered algorithm names
func List() []string {
	var names []string
	for name := range algorithms {
		names = append(names, name)
	}
	return names
}
