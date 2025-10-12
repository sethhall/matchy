# WARP.md

Guidance for working with the matchy codebase.

## Project Overview

**matchy** is a production-ready Rust implementation of multi-pattern glob matching using the Aho-Corasick algorithm. It provides zero-copy memory-mapped file support and maintains binary compatibility with the original C++ paraglob library.

**Status**: ✅ Production Ready
- 79/79 tests passing
- Performance exceeds C++ baseline (2.4×-14× faster depending on workload)
- Binary format compatible with C++ implementation
- Stable C FFI for cross-language use

### Design Principles

1. **Zero-copy architecture**: Offset-based data structures enable direct memory mapping
2. **Memory safety**: Core algorithms in safe Rust; unsafe code only at FFI boundaries
3. **Performance**: O(n) matching complexity regardless of pattern count
4. **FFI stability**: C API uses opaque handles and integer error codes
5. **Binary compatibility**: `#[repr(C)]` structures match C++ layout exactly

## Documentation

Key documents:
- **README.md** - Project overview, performance metrics, usage examples
- **DEVELOPMENT.md** - Architecture details, benchmarks, implementation notes
- **examples/README.md** - How to run example programs
- **Cargo docs** - `cargo doc --no-deps --open` for API documentation

## Development Workflow

### Building

```bash
# Development build
cargo build

# Optimized build (with LTO, single codegen unit)
cargo build --release

# Check without building
cargo check
```

The release build automatically generates `include/matchy.h` via cbindgen.

### Testing

```bash
# Run all tests (79 tests)
cargo test

# Run with output visible
cargo test -- --nocapture

# Run specific test
cargo test test_ac_basic

# Run integration tests
cargo test --test integration_tests

# Run with backtrace on failure
RUST_BACKTRACE=1 cargo test
```

### Code Quality

```bash
# Format code
cargo fmt

# Check formatting without modifying
cargo fmt -- --check

# Run clippy lints
cargo clippy

# Clippy with warnings as errors
cargo clippy -- -D warnings

# Check for common issues
cargo clippy -- -W clippy::all -W clippy::pedantic
```

### Performance

```bash
# Run benchmarks
cargo bench

# Run specific benchmark
cargo bench pattern_matching

# Run examples (includes perf test)
cargo run --release --example production_test
cargo run --release --example glob_demo
```

### Documentation

```bash
# Generate and open docs
cargo doc --no-deps --open

# Generate docs for all dependencies
cargo doc --open
```

### C/C++ Integration Testing

```bash
# Compile and link C program against library
gcc -o myapp app.c \
    -I./include \
    -L./target/release \
    -lmatchy \
    -lpthread -ldl -lm

# Run with memory checking
valgrind --leak-check=full --show-leak-kinds=all ./myapp
```

## Repository Structure

### Project Layout

```
matchy/
├── src/                    # Rust source code
│   ├── lib.rs              # Public API, version constants, module declarations
│   ├── ac_offset.rs        # Offset-based Aho-Corasick automaton implementation
│   ├── paraglob_offset.rs  # High-level Paraglob API with glob matching
│   ├── glob.rs             # Glob pattern matching logic (wildcards, character classes)
│   ├── offset_format.rs    # Binary format structures (#[repr(C)])
│   ├── serialization.rs    # Save/load/mmap functions
│   ├── mmap.rs             # Memory-mapped file wrapper
│   ├── error.rs            # ParaglobError type and conversions
│   ├── binary/             # Binary format implementation
│   │   ├── mod.rs          # Module exports
│   │   ├── format.rs       # #[repr(C)] structures for binary format
│   │   └── validation.rs   # Format validation and offset checking
│   └── c_api/              # C FFI layer
│       └── mod.rs          # extern "C" functions, opaque handles, error codes
├── tests/
│   └── integration_tests.rs  # End-to-end integration tests
├── benches/
│   └── paraglob_bench.rs     # Criterion benchmarks
├── examples/
│   ├── glob_demo.rs          # Basic glob pattern demonstrations
│   ├── production_test.rs    # Production workload simulation
│   └── cpp_comparison_test.rs # C++ compatibility validation
├── include/
│   └── matchy.h         # Auto-generated C header (cbindgen)
├── Cargo.toml              # Package metadata, dependencies, build profiles
├── build.rs                # Build script (runs cbindgen)
├── cbindgen.toml           # cbindgen configuration
├── README.md               # Project overview, usage examples
├── DEVELOPMENT.md          # Architecture, benchmarks, design decisions
└── WARP.md                 # This file
```

### Module Responsibilities

| Module | Purpose |
|--------|----------|
| **lib.rs** | Public API surface, version info, module organization |
| **ac_offset.rs** | Aho-Corasick automaton with offset-based pointers for mmap |
| **paraglob_offset.rs** | Main Paraglob struct, pattern matching orchestration |
| **glob.rs** | Glob syntax parsing and matching (*, ?, [], [!]) |
| **offset_format.rs** | Binary format definitions, must match C++ layout exactly |
| **serialization.rs** | High-level save/load/mmap API |
| **binary/** | Low-level binary format reading/writing/validation |
| **mmap.rs** | Safe wrapper around memory-mapped files |
| **c_api/** | C FFI with opaque handles, error codes |
| **error.rs** | Error types (Rust-style) and C conversion |


## Best Practices

### Code Style

- Use `cargo fmt` before committing - formatting is enforced
- Run `cargo clippy` and address warnings - keep the codebase clean
- Add doc comments (`///`) for all public items
- Write tests for new functionality - maintain 79/79 passing
- Use descriptive variable names - clarity over brevity in this codebase

### Safety Guidelines

**Unsafe code is only permitted at FFI boundaries.** Core algorithms must be safe Rust.

When working with unsafe:
1. Document why unsafe is necessary
2. Keep unsafe blocks as small as possible
3. Validate all assumptions with comments
4. Add safety documentation (`# Safety` section)

### Binary Format Changes

All binary format structures use `#[repr(C)]` and **must maintain exact C++ layout**:

```rust
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct OffsetAcHeader {
    pub magic: [u8; 8],     // Magic bytes: "PARAGLOB"
    pub version: u32,       // Format version
    pub num_nodes: u32,     // Node count
    pub nodes_offset: u32,  // Offset to node table
    // ...
}
```

**Critical**: Any changes to these structures break binary compatibility. If you must change:
1. Update the version number
2. Test with C++ implementation
3. Verify byte-by-byte .pgb file compatibility
4. Update DEVELOPMENT.md with format changes

### Testing Strategy

When adding new features:

```bash
# 1. Write unit tests in the same file
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_your_feature() {
        // test code
    }
}

# 2. Run tests frequently
cargo test

# 3. Add integration tests for complex workflows
# tests/integration_tests.rs

# 4. Benchmark if performance-sensitive
# benches/paraglob_bench.rs
```

## Implementation Patterns

### FFI Safety

All `extern "C"` functions must:

1. **Validate all pointers** before dereferencing:
```rust
if db.is_null() || text.is_null() {
    return PARAGLOB_ERROR_INVALID_PARAM;
}
```

2. **Use panic catching** at FFI boundaries:
```rust
let result = std::panic::catch_unwind(|| {
    // ... actual logic ...
});
result.unwrap_or(PARAGLOB_ERROR_UNKNOWN)
```

3. **Convert Rust types safely**:
```rust
let text = unsafe { CStr::from_ptr(text) }
    .to_str()
    .ok()?;
```

4. **Use opaque handles** for ownership transfer:
```rust
// Transfer to C
Box::into_raw(Box::new(db))

// Reclaim from C
unsafe { drop(Box::from_raw(db)); }
```

### Offset-Based Access Pattern

Unlike pointer-based structures, all references use file offsets:

```rust
pub struct AcNode {
    failure_offset: u32,  // Not a pointer!
    edges_offset: u32,
    num_edges: u16,
    // ...
}

impl AcNode {
    fn get_failure_node<'a>(&self, buffer: &'a [u8]) -> Result<&'a AcNode> {
        // Validate offset bounds and alignment first!
        validate_offset::<AcNode>(buffer, self.failure_offset as usize)?;
        
        // Safe after validation
        Ok(unsafe { 
            &*(buffer.as_ptr().add(self.failure_offset as usize) as *const AcNode)
        })
    }
}
```

**Always validate offsets** before dereferencing to prevent undefined behavior.

## Common Patterns

### Validating Offsets

Always validate before dereferencing:

```rust
fn validate_offset<T>(buffer: &[u8], offset: usize) -> Result<()> {
    let size = std::mem::size_of::<T>();
    
    // Bounds check
    if offset + size > buffer.len() {
        return Err(ParaglobError::CorruptData { 
            offset, 
            reason: "Offset out of bounds" 
        });
    }
    
    // Alignment check
    if offset % std::mem::align_of::<T>() != 0 {
        return Err(ParaglobError::CorruptData {
            offset,
            reason: "Misaligned offset"
        });
    }
    
    Ok(())
}
```

### Converting Rust Errors to C

```rust
fn to_c_error(err: ParaglobError) -> paraglob_error_t {
    match err {
        ParaglobError::IoError(e) if e.kind() == ErrorKind::NotFound 
            => PARAGLOB_ERROR_FILE_NOT_FOUND,
        ParaglobError::InvalidFormat { .. } 
            => PARAGLOB_ERROR_INVALID_FORMAT,
        ParaglobError::CorruptData { .. } 
            => PARAGLOB_ERROR_CORRUPT_DATA,
        _ => PARAGLOB_ERROR_UNKNOWN,
    }
}
```

## Debugging Tips

### Enable Debug Output

```bash
# With cargo test
RUST_LOG=debug cargo test -- --nocapture

# With release builds
RUST_LOG=matchy=trace cargo run --release
```

### Inspecting Binary Format

```bash
# Hex dump of matchy database (shows internal PARAGLOB section if present)
hexdump -C patterns.mxy | head -20

# Check magic bytes (MMDB metadata marker)
xxd patterns.mxy | head -1

# Compare two database files
diff <(xxd db1.mxy) <(xxd db2.mxy)
```

### Memory Debugging

```bash
# Address sanitizer (Linux/macOS)
RUSTFLAGS="-Z sanitizer=address" cargo +nightly test

# Leak detection
valgrind --leak-check=full ./test_c_api

# Undefined behavior (Miri)
cargo +nightly miri test
```

## Integration with Parent Project

This Rust port is part of the larger `mmdb_with_strings` project:

- **Parent directory**: `/Users/seth/factual/mmdb_with_strings/`
- **C++ paraglob**: `../paraglob/` - Original implementation
- **libmaxminddb**: `../libmaxminddb/` - MaxMind DB integration
- **Parent WARP.md**: `../WARP.md` - Broader project context

The Rust port aims to replace the C++ implementation while maintaining binary compatibility, enabling the larger project to eliminate C++ runtime dependencies.

## Cargo Profile Settings

The project uses these profiles:

```toml
[profile.release]
opt-level = 3
lto = true              # Link-time optimization
codegen-units = 1       # Better optimization
panic = "abort"         # Don't unwind through FFI
strip = false           # Keep symbols initially

[profile.dev]
opt-level = 0
debug = true

[profile.bench]
inherits = "release"
```

**Note**: `panic = "abort"` is critical - panics must never cross FFI boundaries!
