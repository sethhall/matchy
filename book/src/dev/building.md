# Building from Source

Build Matchy from source code.

## Prerequisites

- Rust 1.70 or later
- C compiler (for examples)

## Quick Build

```bash
# Clone
git clone https://github.com/sethhall/matchy.git
cd matchy

# Build
cargo build --release

# Test
cargo test

# Install CLI
cargo install --path .
```

## Build Profiles

### Debug Build

```bash
cargo build
# Output: target/debug/
```

- Fast compilation
- Includes debug symbols
- No optimizations

### Release Build

```bash
cargo build --release
# Output: target/release/
```

- Slow compilation
- Full optimizations
- LTO enabled
- Single codegen unit

## Build Options

```bash
# Check without building
cargo check

# Build with all features
cargo build --all-features

# Build examples
cargo build --examples

# Build documentation
cargo doc --no-deps
```

## C Header Generation

The C header is auto-generated on release builds:

```bash
cargo build --release
# Generates: include/matchy.h
```

## Cross-Compilation

```bash
# Install target
rustup target add x86_64-unknown-linux-gnu

# Build for target
cargo build --release --target x86_64-unknown-linux-gnu
```

## See Also

- [Development Guide](../development.md)
- [Testing](testing.md)
