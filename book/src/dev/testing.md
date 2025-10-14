# Testing

Comprehensive testing guide for Matchy.

## Running Tests

```bash
# Run all tests
cargo test

# Run with output
cargo test -- --nocapture

# Run specific test
cargo test test_glob_matching

# Run integration tests
cargo test --test integration_tests

# Run with backtrace
RUST_BACKTRACE=1 cargo test
```

## Test Categories

### Unit Tests

In module files alongside code:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_ip_lookup() {
        let db = build_test_db();
        let result = db.lookup("1.2.3.4").unwrap();
        assert!(result.is_some());
    }
}
```

### Integration Tests

In `tests/` directory:

```rust
// tests/integration_tests.rs
use matchy::*;

#[test]
fn test_end_to_end_workflow() {
    // Build database
    let mut builder = MmdbBuilder::new(MatchMode::CaseSensitive);
    builder.add_ip("1.2.3.4", HashMap::new()).unwrap();
    let bytes = builder.build().unwrap();
    
    // Save and load
    std::fs::write("test.mxy", &bytes).unwrap();
    let db = Database::open("test.mxy").unwrap();
    
    // Query
    let result = db.lookup("1.2.3.4").unwrap();
    assert!(result.is_some());
}
```

### Benchmark Tests

```bash
cargo bench
```

## Test Patterns

### Setup and Teardown

```rust
fn setup() -> Database {
    let mut builder = MmdbBuilder::new(MatchMode::CaseSensitive);
    builder.add_ip("1.2.3.4", HashMap::new()).unwrap();
    let bytes = builder.build().unwrap();
    std::fs::write("test.mxy", &bytes).unwrap();
    Database::open("test.mxy").unwrap()
}

#[test]
fn test_query() {
    let db = setup();
    // test...
}
```

### Testing Errors

```rust
#[test]
fn test_invalid_ip() {
    let db = setup();
    let result = db.lookup("invalid");
    assert!(result.is_err());
}
```

## Coverage

```bash
# Install tarpaulin
cargo install cargo-tarpaulin

# Generate coverage
cargo tarpaulin --out Html
```

## See Also

- [Development Guide](../development.md)
- [Fuzzing](fuzzing.md)
- [CI/CD](ci-checks.md)
