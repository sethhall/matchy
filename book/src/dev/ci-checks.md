# CI/CD Checks

Continuous integration checks for Matchy.

## Local Checks

Run before committing:

```bash
# Run all checks
cargo test
cargo clippy -- -D warnings
cargo fmt -- --check
```

## CI Pipeline

Automated checks on pull requests:

### Tests
```bash
cargo test --all-features
cargo test --no-default-features
```

### Lints
```bash
cargo clippy -- -D warnings
```

### Format
```bash
cargo fmt -- --check
```

### Documentation
```bash
cargo doc --no-deps
```

## Pre-commit Hook

```bash
#!/bin/bash
# .git/hooks/pre-commit

set -e

echo "Running tests..."
cargo test --quiet

echo "Running clippy..."
cargo clippy -- -D warnings

echo "Checking format..."
cargo fmt -- --check

echo "All checks passed!"
```

## See Also

- [Development Guide](../development.md)
- [Testing](testing.md)
