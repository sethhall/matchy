# Development Guide

Guide for contributing to and developing Matchy.

## Quick Start

```bash
# Clone
git clone https://github.com/sethhall/matchy.git
cd matchy

# Build
cargo build

# Test
cargo test

# Run benchmarks
cargo bench
```

## Project Structure

```
matchy/
├── src/
│   ├── lib.rs              # Public API
│   ├── database.rs         # Database querying
│   ├── mmdb_builder.rs     # Database building
│   ├── glob.rs             # Glob matching
│   ├── data_section.rs     # MMDB data encoding
│   ├── binary/             # Binary format
│   └── c_api/              # C FFI
├── tests/                  # Integration tests
├── benches/                # Benchmarks
├── examples/               # Example programs
└── book/                   # Documentation
```

## Development Workflow

### Building

```bash
# Debug build
cargo build

# Release build (optimized)
cargo build --release

# Check without building
cargo check
```

### Testing

```bash
# Run all tests
cargo test

# Run with output
cargo test -- --nocapture

# Run specific test
cargo test test_name

# Run integration tests
cargo test --test integration_tests
```

**See:** [Testing](dev/testing.md)

### Code Quality

```bash
# Format code
cargo fmt

# Run clippy
cargo clippy

# Clippy with warnings as errors
cargo clippy -- -D warnings
```

**See:** [CI/CD](dev/ci-checks.md)

### Benchmarking

```bash
# Run all benchmarks
cargo bench

# Run specific benchmark
cargo bench pattern_matching
```

**See:** [Benchmarking](dev/benchmarking.md)

### Documentation

```bash
# Generate Rust docs
cargo doc --no-deps --open

# Build mdBook documentation
cd book
mdbook build
mdbook serve  # Live preview
```

## Architecture

- **Unified database** - Single file for IPs, strings, and patterns
- **Zero-copy** - Memory-mapped offset-based structures
- **Memory safety** - Safe Rust core, unsafe only at FFI
- **Binary stability** - `#[repr(C)]` for cross-platform compat

**See:** [System Architecture](architecture/overview.md)

## Contributing

1. **Fork** the repository
2. **Create** a feature branch
3. **Write** tests for new features
4. **Run** `cargo test` and `cargo clippy`
5. **Format** with `cargo fmt`
6. **Submit** a pull request

**See:** [Contributing](contributing.md)

## Resources

- [Testing Guide](dev/testing.md)
- [Benchmarking](dev/benchmarking.md)
- [CI/CD](dev/ci-checks.md)
- [Building from Source](dev/building.md)
