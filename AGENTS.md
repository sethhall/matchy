# AGENTS.md

Guidance for AI agents and developers working with the matchy codebase.

## Quick Context

**What is matchy?** A Rust library and CLI for fast IoC (Indicator of Compromise) matching. Builds memory-mapped databases from threat intel feeds, enabling sub-millisecond lookups of IPs, domains, hashes, and glob patterns.

**Key entry points:**
- `crates/matchy/src/lib.rs` - Public API, re-exports
- `crates/matchy/src/database.rs` - Unified Database API
- `crates/matchy/src/bin/matchy.rs` - CLI entry point

**Most common operations:**
```bash
cargo build                    # Build
cargo test                     # Run all tests
cargo clippy                   # Lint
cargo fmt                      # Format
cargo run --release -- --help  # Run CLI
```

**File extension:** `.mxy` for matchy databases, `.mmdb` for MaxMind-compatible databases

---

## Project Overview

**matchy** is a production-ready unified database for IP addresses, string literals, and glob pattern matching. Built in Rust, it provides:
- Fast IP address lookups using binary trie
- Exact string matching with hash tables
- Multi-pattern glob matching using Aho-Corasick algorithm
- Zero-copy memory-mapped file support
- Extended MMDB format with backwards compatibility

### Design Principles

1. **Unified database**: Single file format for IP addresses, strings, and patterns
2. **Zero-copy architecture**: Offset-based data structures enable direct memory mapping
3. **Memory safety**: Core algorithms in safe Rust; unsafe code only at FFI boundaries
4. **Performance**: Optimized data structures for each query type
5. **FFI stability**: C API uses opaque handles and integer error codes
6. **Binary stability**: `#[repr(C)]` structures for cross-platform compatibility

---

## Development Workflow

### Essential Commands

```bash
# Build
cargo build                  # Development build
cargo build --release        # Optimized (generates include/matchy.h via cbindgen)

# Test
cargo test                   # Run all tests
cargo test -- --nocapture    # With output visible
cargo test <test_name>       # Run specific test
RUST_BACKTRACE=1 cargo test  # With backtrace on failure

# Code Quality
cargo fmt                    # Format code (required before commit)
cargo fmt -- --check         # Check formatting only
cargo clippy                 # Run lints
cargo clippy -- -D warnings  # Lints as errors

# Performance
cargo bench                  # Run benchmarks
cargo bench -p matchy        # Just main crate benchmarks

# Documentation
cargo doc --no-deps --open   # Generate and open API docs
```

### Before Committing

Run this to ensure CI will pass:

```bash
cargo fmt && make ci-local
```

### mdbook Documentation

**Important**: All mdbook commands must run from the `book/` directory.

```bash
cd book && mdbook build      # Build the book
cd book && mdbook serve      # Serve with live reload at http://localhost:3000
```

---

## Repository Structure

Matchy is a Cargo workspace with multiple crates:

```
matchy/
├── crates/
│   ├── matchy/              # Main crate: CLI + library + C API
│   │   ├── src/
│   │   │   ├── lib.rs       # Public API surface
│   │   │   ├── database.rs  # Unified Database API
│   │   │   ├── processing.rs # Batch processing (Worker, LineFileReader)
│   │   │   ├── c_api/       # C FFI layer
│   │   │   └── bin/         # CLI implementation
│   │   ├── tests/           # Integration tests
│   │   ├── benches/         # Benchmarks
│   │   ├── examples/        # Example programs
│   │   └── include/         # Generated C headers (matchy.h)
│   │
│   ├── matchy-format/       # Binary format, MMDB builder, mmap
│   ├── matchy-ip-trie/      # IP address lookups via binary trie
│   ├── matchy-literal-hash/ # O(1) exact string matching
│   ├── matchy-paraglob/     # Glob pattern matching with Aho-Corasick
│   ├── matchy-ac/           # Offset-based Aho-Corasick automaton
│   ├── matchy-extractor/    # Extract IPs, domains, emails from text
│   ├── matchy-data-format/  # DataValue type for database entries
│   └── matchy-match-mode/   # CaseSensitive/CaseInsensitive enum
│
├── book/                    # mdbook documentation
├── fuzz/                    # Fuzzing tests
└── scripts/                 # Build and benchmark scripts
```

### Crate Responsibilities

| Crate | Purpose |
|-------|---------|
| **matchy** | Main integration crate: CLI, public API, unified Database, processing |
| **matchy-format** | Binary format structures, MMDB builder, mmap handling |
| **matchy-ip-trie** | IP address lookups via binary trie |
| **matchy-literal-hash** | O(1) exact string matching |
| **matchy-paraglob** | Glob pattern matching with Aho-Corasick |
| **matchy-ac** | Offset-based Aho-Corasick automaton |
| **matchy-extractor** | Fast extraction of IPs, domains, emails from text |
| **matchy-data-format** | DataValue type for database entries |
| **matchy-match-mode** | CaseSensitive/CaseInsensitive configuration |

### Main Crate Modules

| Module | Purpose |
|--------|---------|
| **lib.rs** | Public API surface, re-exports from subcrates |
| **database.rs** | Unified Database API for IP and pattern queries |
| **processing.rs** | Batch processing (Worker, LineFileReader, LineBatch) |
| **validation.rs** | Database validation for untrusted files |
| **serialization.rs** | High-level save/load/mmap API |
| **c_api/** | C FFI with opaque handles, error codes |
| **bin/** | CLI implementation |

---

## Code Conventions

### Style

- **Format**: Run `cargo fmt` before committing - CI enforces this
- **Lints**: Run `cargo clippy` and fix warnings
- **Docs**: Add `///` doc comments for all public items
- **Naming**: Clarity over brevity - use descriptive variable names

### Safety Rules

**Unsafe code is only permitted at FFI boundaries.** Core algorithms must be safe Rust.

When writing unsafe code:
1. Document WHY unsafe is necessary
2. Keep unsafe blocks minimal
3. Add `# Safety` section in doc comments
4. Validate all assumptions with comments

### FFI Safety Patterns

All `extern "C"` functions must:

1. **Validate pointers** before dereferencing
2. **Catch panics** at FFI boundaries (panics must never cross FFI)
3. **Use opaque handles** for ownership transfer
4. **Return integer error codes**, not Result types

```rust
#[no_mangle]
pub extern "C" fn matchy_query(db: *const Database, key: *const c_char) -> i32 {
    // 1. Validate pointers
    if db.is_null() || key.is_null() {
        return ERROR_INVALID_PARAM;
    }
    
    // 2. Catch panics
    std::panic::catch_unwind(|| {
        // ... actual logic ...
    }).unwrap_or(ERROR_UNKNOWN)
}
```

---

## Binary Format Rules

**CRITICAL**: Binary format changes break compatibility with existing `.mxy` files.

All binary format structures use `#[repr(C)]` for cross-platform stability.

Format structures are defined in:
- `matchy-format/src/offset_format.rs` - MMDB format structures
- `matchy-format/src/mmdb/format.rs` - MMDB-specific structures
- `matchy-ac/src/lib.rs` - Aho-Corasick node structures
- `matchy-paraglob/src/offset_format.rs` - Pattern matching structures

**If you must change binary format:**
1. Increment the version number in the relevant format module
2. Test with existing databases to verify they either load (backwards compat) or fail gracefully
3. Verify byte-by-byte `.mxy` file compatibility
4. Update DEVELOPMENT.md with format changes
5. Consider migration code if needed

### Offset-Based Access Pattern

All references use file offsets, not pointers (enables zero-copy mmap):

```rust
pub struct AcNode {
    failure_offset: u32,  // Offset, not pointer!
    edges_offset: u32,
    // ...
}
```

**Always validate offsets** (bounds + alignment) before dereferencing.

---

## Common Pitfalls

### Don't Do

| Anti-Pattern | Why |
|--------------|-----|
| Suppress type errors (`as any`, `@ts-ignore`) | Hides real bugs |
| Empty catch blocks | Silences errors |
| Delete failing tests to "pass" | Tests exist for a reason |
| Change `#[repr(C)]` struct fields | Breaks binary compatibility |
| Let panics cross FFI boundaries | Undefined behavior |
| Use pointers instead of offsets in serialized structures | Breaks mmap/zero-copy |
| Hardcode absolute paths | Breaks portability |

### Watch Out For

- **Test data files**: Located in `crates/matchy/src/data/` and `crates/*/tests/data/`
- **Generated files**: `include/matchy.h` is generated by cbindgen - don't edit manually
- **Book preprocessors**: mdbook commands must run from `book/` directory
- **Benchmark data**: Some benchmarks need setup; check bench file comments

---

## Testing Strategy

### Test Organization

- **Unit tests**: In the same file as the code (`#[cfg(test)] mod tests`)
- **Integration tests**: `crates/matchy/tests/`
- **CLI tests**: `crates/matchy/tests/cli_tests.rs`
- **Fuzz tests**: `fuzz/fuzz_targets/`

### Running Tests

```bash
cargo test                           # All tests
cargo test test_name                 # Specific test
cargo test --test integration_tests  # Just integration tests
cargo test -p matchy-paraglob        # Just one crate
```

### Adding Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_your_feature() {
        // Arrange
        let input = "test data";
        
        // Act
        let result = your_function(input);
        
        // Assert
        assert_eq!(result, expected);
    }
}
```

---

## Debugging

### Enable Debug Output

```bash
RUST_LOG=debug cargo test -- --nocapture
RUST_LOG=matchy=trace cargo run --release
```

### Inspecting Binary Format

```bash
hexdump -C file.mxy | head -20  # Hex dump
xxd file.mxy | head -1          # Check magic bytes
```

### Memory Debugging

```bash
# Address sanitizer (Linux/macOS)
RUSTFLAGS="-Z sanitizer=address" cargo +nightly test

# Undefined behavior (Miri)
cargo +nightly miri test

# Valgrind (for C integration)
valgrind --leak-check=full ./test_program
```

---

## Key Documents

| Document | Purpose |
|----------|---------|
| **README.md** | Project overview, quick start |
| **DEVELOPMENT.md** | Architecture details, performance analysis |
| **book/** | User documentation (mdbook) |
| **examples/** | Working code examples |

Generate API docs with: `cargo doc --no-deps --open`

---

## Cargo Profiles

```toml
[profile.release]
opt-level = 3
lto = true              # Link-time optimization
codegen-units = 1       # Better optimization
panic = "abort"         # Don't unwind through FFI (CRITICAL)

[profile.dev]
opt-level = 0
debug = true
```

**Note**: `panic = "abort"` is critical - panics must never cross FFI boundaries.

---

## Processing Module Overview

The `processing` module provides batch-oriented file analysis. Key types:

- **`Worker`** - Processes data batches with extraction + database matching
- **`LineFileReader`** - Reads files in chunks with automatic gzip decompression
- **`MatchResult`** - Core match info (matched text, type, result, database ID)
- **`LineMatch`** - Match with file/line context
- **`LineBatch`** - Pre-chunked batch of line-oriented data

See `cargo doc --no-deps --open` for full API documentation and examples.
