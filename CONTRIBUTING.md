# Contributing to JWT-Vault-Go

We want to make contributing to JWT-Vault-Go as easy and transparent as possible, whether it's:

- Reporting a bug
- Discussing the current state of the code
- Submitting a fix
- Proposing new features
- Becoming a maintainer

## Development Process

1. Fork the repo and create your branch from `main`.
2. If you've added code that should be tested, add tests.
3. If you've changed APIs, update the documentation.
4. Ensure the test suite passes.
5. Make sure your code lints.
6. Submit your pull request.

## Testing

Before submitting a pull request, make sure all tests pass. You'll need a running Vault instance:

```bash
# Start Vault in dev mode
vault server -dev

# In another terminal
export VAULT_ADDR='http://127.0.0.1:8200'
export VAULT_TOKEN='dev-token'

# Enable transit and create test keys
vault secrets enable transit

# Create test keys for each algorithm
vault write -f transit/keys/jwt-test-es256 type=ecdsa-p256
vault write -f transit/keys/jwt-test-rs256 type=rsa-2048
vault write -f transit/keys/jwt-test-ps256 type=rsa-2048

# Run tests with race detection
go test -v -race ./...
```

## Performance Testing

When making changes that affect performance or concurrency:

1. Test with race detection enabled
2. Verify cache behavior under load
3. Test concurrent access patterns
4. Check version cache effectiveness
5. Validate thread safety

## Algorithm Support

When adding support for new algorithms:

1. Implement the Algorithm interface
2. Add appropriate Vault key type mapping
3. Add tests covering the new algorithm
4. Update documentation with key requirements
5. Add examples demonstrating usage
6. Ensure thread safety in implementation

## Pull Request Process

1. Update the README.md with details of changes if applicable
2. Update examples if functionality changes
3. Add any new dependencies to go.mod
4. Update documentation for any API changes
5. Add comprehensive tests for new functionality
6. Ensure all tests pass with race detection
7. Fix any linting issues (`make lint`)
8. Follow existing code style and patterns
9. The PR will be merged once you have sign-off from a maintainer

## Code Style

- Follow standard Go formatting (`go fmt`)
- Use meaningful variable names
- Document exported functions and types
- Add comments explaining complex logic
- Maintain consistent error handling patterns
- Use context.Context appropriately
- Follow concurrent programming best practices
- Maintain backward compatibility when possible

## Testing Requirements

- Unit tests for new functionality
- Integration tests with Vault
- Concurrent access tests where applicable
- Error case coverage
- Edge case handling
- Performance impact verification
- Race condition checking

## Documentation

- Update README.md for feature additions
- Add/update examples
- Document concurrent usage patterns
- Include configuration details
- Explain performance implications
- Document any breaking changes

## Any contributions you make will be under the MIT Software License
In short, when you submit code changes, your submissions are understood to be under the same [MIT License](LICENSE) that covers the project. Feel free to contact the maintainers if that's a concern.

## Report bugs using Github's [issue tracker](issues)
We use GitHub issues to track public bugs.
