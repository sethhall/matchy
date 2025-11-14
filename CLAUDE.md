# CLAUDE.md - AI Assistant Guide for Matchy

## Project Overview

**Matchy** is a production-ready, high-performance unified database for IP addresses, string literals, and glob pattern matching written in Rust. It provides:

- **Fast lookups**: 3-7M queries/second for IPs, 3M+ for patterns, 1-3M for literals
- **Zero-copy architecture**: Memory-mapped files with <1ms load time
- **Unified database format**: Single file for IPs, strings, and patterns
- **Extended MMDB format**: Backward-compatible with MaxMind databases
- **Multi-language support**: Rust API, C FFI, and MaxMind-compatible C API
- **SIMD-accelerated extraction**: Fast pattern extraction from logs (domains, IPs, emails, hashes, crypto addresses)

**Status**: ✅ Production-ready (all tests passing, comprehensive benchmarks, stable binary format)

**Version**: 1.2.2
**License**: BSD-2-Clause
**Rust Version**: 1.70+ required

---

## Quick Reference for AI Assistants

### Before Making Changes

1. **Read relevant documentation first**:
   - `README.md` - Project overview and examples
   - `DEVELOPMENT.md` - Architecture and performance analysis
   - `CONTRIBUTING.md` - Code quality standards
   - This file - Development workflows and conventions

2. **Run CI checks before committing**:
   ```bash
   make ci-local    # All checks (recommended)
   make ci-quick    # Fast checks (fmt + clippy)
   ```

3. **Understand the architecture**:
   - Three-layer design: Application → C API → Rust Core
   - Offset-based data structures for zero-copy mmap
   - Binary format uses `#[repr(C)]` for stability
   - Unsafe code ONLY at FFI boundaries

4. **Key constraints**:
   - No breaking changes to binary format without version bump
   - All public APIs must have doc comments
   - Tests required for new functionality
   - Performance regressions not acceptable

---

## Codebase Structure

### Directory Layout

```
matchy/
├── src/                          # Rust source code
│   ├── lib.rs                    # Public API, version constants, module exports
│   ├── database.rs               # Unified database API (primary user interface)
│   ├── mmdb_builder.rs           # DatabaseBuilder for creating databases
│   │
│   ├── ac_offset.rs              # Offset-based Aho-Corasick automaton
│   ├── paraglob_offset.rs        # Pattern matching core (AC + glob verification)
│   ├── glob.rs                   # Glob matching logic (*, ?, [], [!])
│   ├── literal_hash.rs           # Hash table for exact string matching (O(1))
│   ├── ac_literal_hash.rs        # Hash-based fast path for literal-only patterns
│   │
│   ├── extractor.rs              # SIMD-accelerated pattern extraction
│   ├── processing.rs             # Batch processing infrastructure (Worker, LineFileReader)
│   ├── file_reader.rs            # Line-oriented file I/O with gzip support
│   │
│   ├── offset_format.rs          # Binary format structures (#[repr(C)])
│   ├── data_section.rs           # JSON-like structured data storage
│   ├── serialization.rs          # Save/load/mmap operations
│   ├── mmap.rs                   # Cross-platform memory mapping
│   ├── validation.rs             # Database validation for untrusted files
│   │
│   ├── ip_tree_builder.rs        # MMDB binary trie builder
│   ├── misp_importer.rs          # MISP threat intel integration
│   ├── simd_utils.rs             # SIMD optimizations (ASCII lowercase, byte searching)
│   ├── endian.rs                 # Cross-platform byte order handling
│   ├── error.rs                  # ParaglobError and MatchyError types
│   │
│   ├── bin/                      # CLI implementation
│   │   ├── matchy.rs             # CLI entry point (Clap argument parsing)
│   │   ├── cli_utils.rs          # Shared CLI utilities
│   │   ├── commands/             # CLI command implementations
│   │   │   ├── build_cmd.rs      # matchy build
│   │   │   ├── query_cmd.rs      # matchy query
│   │   │   ├── match_cmd.rs      # matchy match (log scanning)
│   │   │   ├── extract_cmd.rs    # matchy extract
│   │   │   ├── validate_cmd.rs   # matchy validate
│   │   │   ├── inspect_cmd.rs    # matchy inspect
│   │   │   └── bench/            # Benchmarking subcommands
│   │   └── match_processor/      # Parallel/sequential processing engines
│   │       ├── mod.rs
│   │       ├── parallel.rs       # Multi-threaded processing
│   │       └── sequential.rs     # Single-threaded processing
│   │
│   └── c_api/                    # C FFI layer
│       ├── mod.rs                # Module exports
│       ├── matchy.rs             # Matchy-specific C API
│       └── maxminddb_compat.rs   # MaxMind MMDB compatible API
│
├── include/matchy/               # C header files
│   ├── matchy.h                  # Auto-generated (cbindgen)
│   └── maxminddb.h               # MaxMind compatibility header
│
├── tests/                        # Integration tests
│   ├── integration_tests.rs      # Comprehensive Rust API tests
│   ├── cli_tests.rs              # CLI command tests
│   ├── test_c_api.c              # C API tests
│   ├── test_c_api_extensions.c   # Extended C API tests
│   └── test_mmdb_compat.c        # MaxMind compatibility tests
│
├── benches/                      # Performance benchmarks (Criterion)
│   ├── matchy_bench.rs           # Core query performance
│   ├── cache_bench.rs            # Cache performance analysis
│   ├── mmdb_build_bench.rs       # Database construction performance
│   ├── batch_bench.rs            # Batch processing benchmarks
│   └── query_profile.rs          # Memory profiling tool (dhat)
│
├── examples/                     # Example programs (20+ examples)
│   ├── README.md                 # Examples documentation
│   ├── production_test.rs        # Production simulation
│   ├── extractor_demo.rs         # Pattern extraction demo
│   ├── cache_demo.rs             # Query caching demo
│   ├── build_combined_database.rs
│   └── ...
│
├── book/                         # mdBook documentation
│   ├── book.toml                 # mdBook configuration
│   ├── src/                      # Documentation source
│   │   ├── SUMMARY.md            # Table of contents
│   │   ├── commands/             # Command reference
│   │   ├── dev/                  # Developer guides
│   │   ├── architecture/         # Architecture docs
│   │   └── getting-started/      # Getting started guides
│   └── mdbook-project-version/   # Custom mdBook plugin
│
├── fuzz/                         # Fuzzing targets (AFL-style)
│   ├── README.md
│   └── fuzz_quickstart.sh
│
├── scripts/                      # Development scripts
│   ├── benchmark_baseline.sh
│   ├── benchmark_compare.sh
│   ├── benchmark_report.sh
│   └── save_current_as_baseline.sh
│
├── tools/update-psl/             # Public Suffix List updater
│
├── .github/workflows/            # CI/CD pipelines
│   ├── ci.yml                    # Continuous integration
│   ├── release.yml               # Release automation
│   └── deploy-docs.yml           # Documentation deployment
│
├── Cargo.toml                    # Package manifest
├── build.rs                      # Build script (C header generation)
├── cbindgen.toml                 # C binding configuration
├── Makefile                      # C tests and CI checks
├── .cargo/config.toml            # Cargo aliases
│
├── README.md                     # Project overview
├── DEVELOPMENT.md                # Architecture and performance
├── CONTRIBUTING.md               # Contribution guidelines
├── WARP.md                       # Original AI assistant guide
├── CHANGELOG.md                  # Version history
└── CLAUDE.md                     # This file
```

### Module Responsibilities

| Module | Purpose | Key Types/Functions |
|--------|---------|---------------------|
| **database.rs** | Primary user interface | `Database`, `Database::open()`, `Database::lookup()` |
| **mmdb_builder.rs** | Database construction | `DatabaseBuilder`, `DatabaseBuilder::build()` |
| **ac_offset.rs** | Aho-Corasick automaton | `AcAutomaton`, offset-based state machine |
| **paraglob_offset.rs** | Pattern matching | AC + glob verification, pattern IDs |
| **glob.rs** | Glob syntax | Wildcard matching (*, ?, [], [!]) |
| **literal_hash.rs** | Exact string matching | Hash table, O(1) lookups |
| **extractor.rs** | Pattern extraction | SIMD-accelerated extraction of IPs, domains, emails, hashes |
| **processing.rs** | Batch processing | `Worker`, `LineFileReader`, `LineBatch` |
| **validation.rs** | Database validation | Security validation for untrusted databases |
| **data_section.rs** | Metadata storage | JSON-like structured data (DataValue) |
| **serialization.rs** | Persistence | Save/load/mmap operations |
| **ip_tree_builder.rs** | IP tree construction | MMDB binary trie builder |
| **c_api/** | FFI layer | Opaque handles, error codes, extern "C" |

---

## Development Workflows

### Initial Setup

```bash
# Clone repository
git clone https://github.com/sethhall/matchy.git
cd matchy

# Build
cargo build

# Run tests
cargo test

# Build release (with optimizations + C headers)
cargo build --release
```

### Pre-Commit Workflow (REQUIRED)

**Always run before committing:**

```bash
make ci-local    # All CI checks (recommended)
```

Or for faster iteration:

```bash
make ci-quick    # Just fmt + clippy
```

Individual checks:

```bash
make fmt         # Check formatting
make clippy      # Lint check
make check-docs  # Documentation check
make test-rust   # Run Rust tests
make test-doc    # Run doc tests
```

### Using Cargo Aliases

Defined in `.cargo/config.toml`:

```bash
# Individual CI checks
cargo check-fmt        # Format check
cargo check-clippy     # Clippy with -D warnings
cargo check-docs       # Build docs with -D warnings

# Test commands
cargo test-all         # Verbose tests
cargo test-doc         # Doc tests only
cargo test-int         # Integration tests only

# Convenience
cargo fmt-fix          # Auto-format code
cargo clippy-fix       # Auto-fix clippy issues
```

### Testing Strategy

```bash
# Unit tests (embedded in source files)
cargo test

# Integration tests
cargo test --test integration_tests
cargo test --test cli_tests

# C API tests
make test              # All C tests
make test-c            # C API only
make test-c-ext        # C API extensions only
make test-mmdb         # MMDB compatibility only

# Benchmarks
cargo bench --no-run                    # Compile benchmarks
cargo bench -- --test                   # Smoke test
cargo bench                             # Full benchmark suite
cargo bench -- pattern_matching         # Specific benchmark

# Memory profiling
cargo bench --bench query_profile --features dhat-heap
```

### Documentation

```bash
# Rust API docs
cargo doc --no-deps --open

# mdBook user guide (MUST run from book/ directory!)
cd book
mdbook build
mdbook serve    # Live reload at http://localhost:3000

# Or from project root:
(cd book && mdbook build)
```

**Important**: mdBook commands must be run from `book/` directory due to preprocessors.

### Building Examples

```bash
# List all examples
cargo run --example

# Run specific example
cargo run --release --example production_test
cargo run --release --example extractor_demo
cargo run --release --example cache_demo

# Build all examples
cargo build --release --examples
```

### CLI Usage

```bash
# Install
cargo install matchy

# Or run from source
cargo run --release -- <command>

# Build database
matchy build threats.csv -o threats.mxy --format csv

# Query
matchy query threats.mxy 1.2.3.4
matchy query threats.mxy evil.com

# Scan logs
matchy match threats.mxy access.log --stats
matchy match threats.mxy access.log.gz --follow  # Live tail

# Validate database
matchy validate threats.mxy
matchy validate threats.mxy --level strict

# Inspect database
matchy inspect threats.mxy

# Extract patterns
matchy extract access.log --type domain
matchy extract access.log --type ipv4 --type email
```

---

## Key Conventions and Patterns

### 1. Binary Format Stability

**CRITICAL**: Binary format changes break compatibility!

All binary structures use `#[repr(C)]`:

```rust
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct OffsetAcHeader {
    pub magic: [u8; 8],     // "PARAGLOB"
    pub version: u32,       // Format version
    pub num_nodes: u32,
    // ...
}
```

**Rules**:
- Never modify existing fields
- Only append new fields at the end
- Bump version number on any change
- Test with existing .mxy files
- Document changes in DEVELOPMENT.md

### 2. Offset-Based Access Pattern

Unlike pointer-based structures, all references use **file offsets**:

```rust
pub struct AcNode {
    failure_offset: u32,  // Not a pointer!
    edges_offset: u32,
    num_edges: u16,
}

impl AcNode {
    fn get_failure_node<'a>(&self, buffer: &'a [u8]) -> Result<&'a AcNode> {
        // ALWAYS validate offset bounds first!
        validate_offset::<AcNode>(buffer, self.failure_offset as usize)?;

        // Safe after validation
        Ok(unsafe {
            &*(buffer.as_ptr().add(self.failure_offset as usize) as *const AcNode)
        })
    }
}
```

**Always validate offsets before dereferencing!**

### 3. Memory Safety Rules

**Core algorithms MUST be safe Rust. Unsafe code ONLY at FFI boundaries.**

When writing unsafe code:

```rust
// ✅ GOOD: Document safety, validate assumptions
/// # Safety
/// Caller must ensure `db` is a valid pointer returned from matchy_open()
#[no_mangle]
pub unsafe extern "C" fn matchy_query(db: *mut Database, text: *const c_char) -> matchy_result_t {
    // Validate pointers
    if db.is_null() || text.is_null() {
        return matchy_result_t { found: false, .. };
    }

    // Catch panics (never unwind through FFI!)
    let result = std::panic::catch_unwind(|| {
        // ... actual logic ...
    });

    result.unwrap_or_else(|_| matchy_result_t { found: false, .. })
}

// ❌ BAD: Unchecked pointer dereference
pub unsafe extern "C" fn bad_function(ptr: *mut Database) {
    (*ptr).query("1.2.3.4");  // What if ptr is null?
}
```

### 4. Error Handling Patterns

**Rust API** (idiomatic):
```rust
pub fn lookup(&self, query: &str) -> Result<Option<QueryResult>, MatchyError> {
    // ... implementation ...
}
```

**C API** (error codes):
```rust
#[no_mangle]
pub unsafe extern "C" fn matchy_open(path: *const c_char) -> *mut Database {
    if path.is_null() {
        return std::ptr::null_mut();
    }
    // ... implementation ...
}

// Separate error retrieval
#[no_mangle]
pub extern "C" fn matchy_get_last_error() -> matchy_error_t { /* ... */ }
```

### 5. Testing Patterns

**Unit tests** (same file as implementation):
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_lookup() {
        let mut builder = DatabaseBuilder::new();
        builder.add_ip("192.168.1.1", data).unwrap();
        let db = builder.build().unwrap();

        let result = db.lookup("192.168.1.1").unwrap();
        assert!(result.is_some());
    }
}
```

**Integration tests** (`tests/integration_tests.rs`):
```rust
#[test]
fn test_build_query_roundtrip() {
    // Multi-module, end-to-end testing
}
```

**Property-based tests**:
```rust
use proptest::prelude::*;

proptest! {
    #[test]
    fn test_all_ips_match(ip in any::<Ipv4Addr>()) {
        // Test property holds for all IPs
    }
}
```

### 6. Documentation Standards

**All public APIs must have doc comments:**

```rust
/// Queries the database for a match against the given string.
///
/// This function automatically detects the query type:
/// - IP addresses (IPv4/IPv6)
/// - CIDR ranges
/// - Exact strings
/// - Glob patterns
///
/// # Arguments
///
/// * `query` - The string to search for
///
/// # Returns
///
/// * `Ok(Some(QueryResult))` - Match found
/// * `Ok(None)` - No match
/// * `Err(MatchyError)` - Query error
///
/// # Examples
///
/// ```
/// use matchy::Database;
///
/// let db = Database::open("threats.mxy")?;
/// if let Some(result) = db.lookup("8.8.8.8")? {
///     println!("Found: {:?}", result);
/// }
/// # Ok::<(), matchy::MatchyError>(())
/// ```
pub fn lookup(&self, query: &str) -> Result<Option<QueryResult>, MatchyError> {
    // ... implementation ...
}
```

### 7. Performance Guidelines

**Measure before optimizing:**

```bash
cargo bench                              # Baseline
# Make changes
cargo bench                              # Compare
scripts/benchmark_compare.sh             # Automated comparison
```

**Cache-aware design:**

```rust
// ✅ GOOD: Support optional caching
let db = Database::from("threats.mxy")
    .cache_capacity(10_000)  // LRU cache
    .open()?;

// Query automatically uses cache
db.lookup("8.8.8.8")?;
```

**Avoid unnecessary allocations:**

```rust
// ✅ GOOD: Zero-copy where possible
pub fn extract_from_line<'a>(&self, line: &'a [u8]) -> impl Iterator<Item = Match<'a>> {
    // Return references to input, not owned strings
}

// ❌ BAD: Unnecessary allocation
pub fn extract_from_line(&self, line: &[u8]) -> Vec<String> {
    // Allocates for every match
}
```

---

## Common Tasks for AI Assistants

### Task 1: Add a New CLI Command

1. **Create command module**: `src/bin/commands/mycommand_cmd.rs`
   ```rust
   use clap::Args;

   #[derive(Args)]
   pub struct MyCommandArgs {
       /// Input file
       #[arg(short, long)]
       input: PathBuf,
   }

   pub fn run(args: MyCommandArgs) -> Result<(), String> {
       // Implementation
       Ok(())
   }
   ```

2. **Register in CLI**: `src/bin/matchy.rs`
   ```rust
   mod commands;

   #[derive(Subcommand)]
   enum Commands {
       MyCommand(commands::mycommand_cmd::MyCommandArgs),
   }

   Commands::MyCommand(args) => commands::mycommand_cmd::run(args)?,
   ```

3. **Add tests**: `tests/cli_tests.rs`
   ```rust
   #[test]
   fn test_mycommand() {
       Command::cargo_bin("matchy")
           .unwrap()
           .args(&["mycommand", "--input", "test.txt"])
           .assert()
           .success();
   }
   ```

4. **Update documentation**: `book/src/commands/mycommand.md`

5. **Run checks**:
   ```bash
   cargo test --test cli_tests
   make ci-local
   ```

### Task 2: Add Support for a New Pattern Type

1. **Update extractor**: `src/extractor.rs`
   ```rust
   pub fn extract_my_pattern(&self, line: &[u8]) -> impl Iterator<Item = Match> {
       // SIMD-accelerated extraction
   }
   ```

2. **Add validation logic**:
   ```rust
   fn validate_my_pattern(candidate: &str) -> bool {
       // Validation rules
   }
   ```

3. **Add tests**:
   ```rust
   #[test]
   fn test_extract_my_pattern() {
       let extractor = Extractor::new().unwrap();
       let matches: Vec<_> = extractor.extract_my_pattern(b"test data").collect();
       assert_eq!(matches.len(), 1);
   }
   ```

4. **Add benchmarks**: `benches/matchy_bench.rs`
   ```rust
   fn bench_my_pattern(c: &mut Criterion) {
       // Benchmark extraction
   }
   ```

5. **Document in examples**: `examples/extractor_demo.rs`

### Task 3: Fix a Performance Regression

1. **Establish baseline**:
   ```bash
   git checkout main
   cargo bench
   scripts/save_current_as_baseline.sh
   ```

2. **Switch to your branch**:
   ```bash
   git checkout your-branch
   cargo bench
   ```

3. **Compare**:
   ```bash
   scripts/benchmark_compare.sh
   ```

4. **Investigate**:
   - Profile with `cargo bench --bench query_profile --features dhat-heap`
   - Check for unnecessary allocations
   - Look for algorithmic changes
   - Review hot paths with `cargo flamegraph`

5. **Fix and verify**:
   ```bash
   cargo bench
   scripts/benchmark_compare.sh
   ```

### Task 4: Add a New Database Validation Check

1. **Update validation module**: `src/validation.rs`
   ```rust
   fn validate_my_check(db: &DatabaseRef) -> ValidationResult {
       let mut report = ValidationReport::new();

       // Perform validation
       if problem_detected {
           report.add_error("My check failed");
       }

       report
   }
   ```

2. **Add to validation levels**:
   ```rust
   pub fn validate_database(path: &Path, level: ValidationLevel) -> Result<ValidationReport> {
       // Add to appropriate level (Basic/Standard/Strict)
       if level >= ValidationLevel::Standard {
           validate_my_check(&db)?;
       }
   }
   ```

3. **Add tests**:
   ```rust
   #[test]
   fn test_validation_my_check() {
       // Create invalid database
       // Assert validation catches it
   }
   ```

4. **Update CLI**: Already automatically included in `matchy validate`

### Task 5: Optimize Memory Usage

1. **Profile current usage**:
   ```bash
   cargo bench --bench query_profile --features dhat-heap
   # Check dhat-heap.json output
   ```

2. **Identify allocations**:
   - Look for `Vec` allocations in hot paths
   - Check string allocations
   - Review data structure sizes

3. **Apply optimizations**:
   ```rust
   // ✅ GOOD: Reuse buffers
   struct Worker {
       buffer: Vec<u8>,  // Reused across calls
   }

   // ❌ BAD: Allocate every time
   fn process(&self, data: &[u8]) {
       let buffer = Vec::new();  // Allocation!
   }
   ```

4. **Verify improvement**:
   ```bash
   cargo bench --bench query_profile --features dhat-heap
   # Compare dhat-heap.json
   ```

---

## Performance Characteristics

### Query Performance

| Query Type | Database Size | Throughput | Latency | Notes |
|------------|---------------|------------|---------|-------|
| **IP Addresses** | 10K | 4.00M q/s | 0.25µs | Binary trie, O(log n) |
| **IP Addresses** | 100K | 3.87M q/s | 0.26µs | Scales linearly |
| **Literals** | 10K | 1.14M q/s | 0.88µs | Hash table, O(1) |
| **Literals** | 100K | 165K q/s | 6.07µs | Degrades with collisions |
| **Suffix Patterns** | 10K | 3.08M q/s | - | `*.domain.com` |
| **Prefix Patterns** | 10K | 956K q/s | - | `prefix-*` |
| **Complex Patterns** | 10K | 59K q/s | - | Multi-wildcard + classes |

**Pattern Complexity Impact**:
- **Suffix patterns** (`*.evil.com`): 3M+ q/s (fast suffix check)
- **Prefix patterns** (`log-*`): ~950K q/s (AC + prefix verify)
- **Complex patterns** (`*[0-9].*evil-*`): 12.7K-430K q/s (depends on wildcards)

### Build Performance

| Database Type | Size | Build Time | Build Rate |
|---------------|------|------------|------------|
| IP addresses | 10K | 3.8ms | 2.65M/sec |
| IP addresses | 100K | 36ms | 2.78M/sec |
| Literals | 10K | 5.1ms | 1.96M/sec |
| Suffix patterns | 10K | 19ms | 516K/sec |
| Complex patterns | 50K | 246ms | 203K/sec |

**Build time is a one-time cost!** Even 50K complex patterns build in <250ms.

### Load Time

Memory-mapped databases load in **<1ms regardless of size**:

| Database | Size | Load Time |
|----------|------|-----------|
| 10K IPs | 59 KB | 0.34ms |
| 100K IPs | 586 KB | 0.72ms |
| 50K patterns | 7.61 MB | 0.91ms |

### Memory Efficiency

**Traditional approach** (heap deserialization):
```
50 processes × 100 MB database = 5,000 MB RAM
```

**Matchy approach** (memory-mapped):
```
50 processes sharing 100 MB = 100 MB RAM
Savings: 4,900 MB (98% reduction)
```

OS automatically shares physical pages across processes.

---

## Architecture Deep Dive

### Three-Layer Design

```
┌─────────────────────────────────────┐
│     Application Layer               │
│  (C, Rust, Python, Go consumers)    │
└─────────────────────────────────────┘
              │
      ┌───────▼───────┐
      │    C API      │
      │  (extern C)   │
      │  - matchy.h   │
      │  - maxminddb.h│
      └───────┬───────┘
              │
      ┌───────▼───────────────┐
      │     Rust Core         │
      │                       │
      │  ┌─────────────────┐  │
      │  │ IP Binary Trie  │  │  O(log n)
      │  └─────────────────┘  │
      │                       │
      │  ┌─────────────────┐  │
      │  │ String Hash Tbl │  │  O(1)
      │  └─────────────────┘  │
      │                       │
      │  ┌─────────────────┐  │
      │  │ AC Pattern Eng  │  │  O(n)
      │  └─────────────────┘  │
      │                       │
      │  ┌─────────────────┐  │
      │  │ Glob Matching   │  │  Verification
      │  └─────────────────┘  │
      │                       │
      │  ┌─────────────────┐  │
      │  │ MMDB Format I/O │  │  Extended MMDB
      │  └─────────────────┘  │
      │                       │
      │  ┌─────────────────┐  │
      │  │ Memory Mapping  │  │  Zero-copy
      │  └─────────────────┘  │
      └───────────────────────┘
```

### Query Flow

```
User Query "sub.evil.com"
      │
      ▼
┌─────────────────┐
│ Database.lookup │  Entry point
└────────┬────────┘
         │
         ├─→ Parse query type
         │   (IP? CIDR? String?)
         │
         ├─→ Check LRU cache
         │   (if enabled)
         │
         ├─→ Route to engine:
         │   │
         │   ├─→ IP Binary Trie
         │   │   (for IP addresses)
         │   │
         │   ├─→ Literal Hash Table
         │   │   (for exact strings)
         │   │
         │   └─→ AC + Glob Engine
         │       (for patterns)
         │       │
         │       ├─→ AC automaton scan
         │       │   (find candidate literals)
         │       │
         │       ├─→ Glob verification
         │       │   (check full pattern match)
         │       │
         │       └─→ Return pattern ID
         │
         ├─→ Fetch metadata
         │   (from data section)
         │
         └─→ Return QueryResult
```

### Binary Format

```
┌─────────────────────────────────────┐
│         MMDB Header                 │  Standard MaxMind format
│  - Metadata tree                    │
│  - Database description             │
│  - IP version, record size, etc.    │
└─────────────────────────────────────┘
│
├─────────────────────────────────────┤
│         IP Binary Trie              │  IP lookups (IPv4/IPv6)
│  - Node table                       │
│  - Pointer table                    │
│  - Data section                     │
└─────────────────────────────────────┘
│
├─────────────────────────────────────┤
│      PARAGLOB Section (optional)    │  String/pattern matching
│                                     │
│  Magic: "PARAGLOB"                  │
│  Version: u32                       │
│                                     │
│  ┌───────────────────────────────┐  │
│  │   AC Automaton                │  │  Aho-Corasick state machine
│  │  - Node table (offset-based)  │  │
│  │  - Edge table                 │  │
│  │  - Failure links              │  │
│  └───────────────────────────────┘  │
│                                     │
│  ┌───────────────────────────────┐  │
│  │   Pattern Metadata            │  │  Pattern types and IDs
│  │  - Pattern array              │  │
│  │  - Literal mappings           │  │
│  └───────────────────────────────┘  │
│                                     │
│  ┌───────────────────────────────┐  │
│  │   String/Offset Tables        │  │  Literal storage
│  │  - Pattern strings            │  │
│  │  - Literal strings            │  │
│  └───────────────────────────────┘  │
└─────────────────────────────────────┘
│
├─────────────────────────────────────┤
│         Data Section                │  JSON-like metadata
│  - Key-value pairs                  │  (shared by IP and patterns)
│  - Structured data (DataValue)      │
└─────────────────────────────────────┘
```

All structures use **file offsets** (u32) instead of pointers for zero-copy mmap support.

---

## Security and Validation

### Database Validation

**Always validate untrusted databases!**

```bash
# Validate before use
matchy validate untrusted.mxy
matchy validate untrusted.mxy --level strict
```

**Validation levels**:
- **Basic** (~1ms): Magic bytes, version, critical offsets
- **Standard** (~5ms, default): All offset bounds, UTF-8 validation, structure integrity
- **Strict** (~10ms): Deep graph analysis, cycle detection, efficiency warnings

**API usage**:
```rust
use matchy::validation::{validate_database, ValidationLevel};

let report = validate_database(
    Path::new("database.mxy"),
    ValidationLevel::Standard
)?;

if !report.is_valid() {
    for error in &report.errors {
        eprintln!("ERROR: {}", error);
    }
    return Err("Unsafe database");
}
```

### Safe vs. Trusted Mode

**Safe mode** (default):
```rust
let db = Database::open("untrusted.mxy")?;
// Validates UTF-8 on every string read
// Safe for untrusted databases
// ~15-20% slower
```

**Trusted mode**:
```rust
let db = Database::open_trusted("validated.mxy")?;
// Skips UTF-8 validation
// ONLY for validated or self-built databases!
// Undefined behavior if database has invalid UTF-8
```

**Recommendation**: Always validate external databases, then use trusted mode for better performance.

### FFI Safety Checklist

When writing `extern "C"` functions:

- [ ] Validate all pointers before dereferencing
- [ ] Use `std::panic::catch_unwind()` at FFI boundary
- [ ] Never unwind through FFI (set `panic = "abort"`)
- [ ] Convert Rust types safely (check `CStr::from_ptr().to_str()`)
- [ ] Use opaque handles for ownership transfer
- [ ] Document safety invariants
- [ ] Add null pointer checks
- [ ] Return error codes, not panics

---

## Troubleshooting Guide

### Build Issues

**Problem**: Build fails with "cbindgen not found"
```bash
# Solution: Install cbindgen
cargo install cbindgen
```

**Problem**: C tests fail to compile
```bash
# Solution: Build Rust library first
cargo build --release
make test
```

**Problem**: Link errors on Linux
```bash
# Solution: Add required libraries
gcc ... -lmatchy -lpthread -ldl -lm
```

### Test Failures

**Problem**: Test fails with "Corrupt data"
```bash
# Solution: Validate offset alignment
fn validate_offset<T>(buffer: &[u8], offset: usize) -> Result<()> {
    if offset % std::mem::align_of::<T>() != 0 {
        return Err(ParaglobError::CorruptData { /* ... */ });
    }
    Ok(())
}
```

**Problem**: FFI tests crash
```bash
# Solution: Check for null pointers
if db.is_null() {
    return error_code;
}
```

**Problem**: Intermittent test failures
```bash
# Solution: Run with backtrace
RUST_BACKTRACE=1 cargo test

# Or with address sanitizer
RUSTFLAGS="-Z sanitizer=address" cargo +nightly test
```

### Performance Issues

**Problem**: Queries are slower than benchmarks
```bash
# Solution: Enable caching
let db = Database::from("threats.mxy")
    .cache_capacity(10_000)
    .open()?;
```

**Problem**: Complex patterns are slow
```bash
# Solution: Simplify patterns or split into multiple simple patterns
# Bad:  "*[0-9].*.evil-*"
# Good: "*.evil-*" + separate validation
```

**Problem**: Build is slow
```bash
# Solution: Reduce pattern complexity or use rayon parallelism
# Build already uses rayon for large datasets
```

### Memory Issues

**Problem**: High memory usage
```bash
# Solution: Use memory mapping instead of reading into RAM
let db = Database::open("large.mxy")?;  // Uses mmap, not read()
```

**Problem**: Memory leaks in C code
```bash
# Solution: Check cleanup
matchy_t *db = matchy_open("db.mxy");
// ... use db ...
matchy_close(db);  // MUST call this!
```

### Debugging Tips

**Enable debug output**:
```bash
RUST_LOG=debug cargo test -- --nocapture
RUST_LOG=matchy=trace cargo run --release
```

**Inspect binary format**:
```bash
# Hex dump
hexdump -C patterns.mxy | head -20

# Check magic bytes
xxd patterns.mxy | head -1
# Should show MMDB metadata marker or PARAGLOB

# Compare databases
diff <(xxd db1.mxy) <(xxd db2.mxy)
```

**Memory debugging**:
```bash
# Address sanitizer (detect memory errors)
RUSTFLAGS="-Z sanitizer=address" cargo +nightly test

# Leak detection
valgrind --leak-check=full ./test_c_api

# Undefined behavior (Miri)
cargo +nightly miri test
```

**Profiling**:
```bash
# Heap allocations
cargo bench --bench query_profile --features dhat-heap

# CPU profiling
cargo flamegraph --bench matchy_bench

# Criterion benchmarks
cargo bench -- --save-baseline main
# Make changes
cargo bench -- --baseline main
```

---

## CI/CD Pipeline

### GitHub Actions Workflows

**ci.yml** - Runs on every push/PR:
```yaml
- Format check (cargo fmt)
- Clippy lints (all targets, all features, -D warnings)
- Documentation build (RUSTDOCFLAGS="-D warnings")
- Tests (Rust + C API + integration)
- Doc tests
- Benchmarks (compile only, no run)
- Security audit (cargo-audit)
- Code coverage (tarpaulin)
```

**Platforms tested**:
- Ubuntu (latest)
- macOS (latest)
- Windows (latest)
- FreeBSD (cross-platform validation)

**Rust versions**:
- stable
- beta

**release.yml** - Triggered on tags:
```yaml
- Build release binaries
- Create GitHub release
- Publish to crates.io
- Upload artifacts
```

**deploy-docs.yml** - Deploys mdBook:
```yaml
- Build book
- Deploy to GitHub Pages
- URL: https://sethhall.github.io/matchy/
```

### Local CI Simulation

Run the same checks as CI:

```bash
make ci-local     # Matches CI exactly
```

Breakdown:
```bash
make fmt          # cargo fmt --check
make clippy       # cargo clippy -D warnings
make check-docs   # RUSTDOCFLAGS="-D warnings" cargo doc
make test-rust    # cargo test --verbose
make test-doc     # cargo test --doc
```

---

## Dependencies Overview

### Core Dependencies

| Crate | Version | Purpose | Critical? |
|-------|---------|---------|-----------|
| **memmap2** | 0.9.9 | Memory mapping | Yes |
| **zerocopy** | 0.8.27 | Safe zero-copy access | Yes |
| **serde** | 1.0 | JSON serialization | Yes |
| **rustc-hash** | 2.0 | FxHash for literals | Yes |
| **xxhash-rust** | 0.8 | Stable on-disk hashing | Yes |
| **lru** | 0.16 | Query result caching | No |
| **memchr** | 2.7 | SIMD byte searching | Yes |
| **rayon** | 1.10 | Parallel sorting | No |
| **flate2** | 1.1 | Gzip support | No |

### Cryptography Dependencies (for address validation)

| Crate | Purpose |
|-------|---------|
| **bs58** | Base58 encoding (Bitcoin/Monero) |
| **sha2** | SHA256 (Bitcoin checksums) |
| **tiny-keccak** | Keccak256 (Ethereum checksums) |
| **bech32** | Bech32 encoding (Bitcoin SegWit) |

### CLI Dependencies (optional, behind `cli` feature)

| Crate | Purpose |
|-------|---------|
| **clap** | Command-line parsing |
| **csv** | CSV file reading |
| **notify** | File watching (--follow mode) |
| **ctrlc** | Graceful shutdown |

### Dev Dependencies

| Crate | Purpose |
|-------|---------|
| **criterion** | Benchmarking framework |
| **proptest** | Property-based testing |
| **tempfile** | Temporary file management |
| **dhat** | Heap profiling |
| **assert_cmd** | CLI testing |
| **predicates** | Output assertions |

---

## Feature Flags

```toml
[features]
default = ["cli"]

# CLI includes all binary dependencies
cli = ["clap", "notify", "ctrlc", "csv"]

# cargo-c compatibility marker
capi = []

# Enable dhat heap profiling
dhat-heap = []
```

**Usage**:
```bash
# Library only (no CLI dependencies - saves ~40 crates)
cargo add matchy --no-default-features

# Full installation with CLI
cargo install matchy

# Build with all features
cargo build --all-features
```

---

## API Examples

### Rust API

**Basic usage**:
```rust
use matchy::{Database, DatabaseBuilder};

// Build database
let mut builder = DatabaseBuilder::new();
builder.add_ip("8.8.8.8", json!({"service": "dns"}))?;
builder.add_pattern("*.evil.com", json!({"threat": "phishing"}))?;
builder.save("threats.mxy")?;

// Query
let db = Database::open("threats.mxy")?;
if let Some(result) = db.lookup("sub.evil.com")? {
    println!("Match: {:?}", result);
}
```

**With caching**:
```rust
let db = Database::from("threats.mxy")
    .cache_capacity(10_000)  // LRU cache for 10k queries
    .open()?;

// Repeated queries hit cache
for _ in 0..1000 {
    db.lookup("8.8.8.8")?;  // Fast after first query
}
```

**Pattern extraction**:
```rust
use matchy::extractor::Extractor;

let extractor = Extractor::builder()
    .extract_domains(true)
    .extract_ipv4(true)
    .extract_emails(true)
    .build()?;

for match_item in extractor.extract_from_line(b"Visit evil.com or email bad@evil.com") {
    println!("Found: {} ({})", match_item.text, match_item.match_type);
}
```

**Batch processing**:
```rust
use matchy::{Database, processing};
use matchy::extractor::Extractor;

let db = Database::open("threats.mxy")?;
let extractor = Extractor::new()?;

let mut worker = processing::Worker::builder()
    .extractor(extractor)
    .add_database("threats", db)
    .build();

let reader = processing::LineFileReader::new("access.log.gz", 128 * 1024)?;
for batch in reader.batches() {
    let matches = worker.process_lines(&batch?)?;
    for m in matches {
        println!("{}:{} - {}", m.source.display(), m.line_number, m.match_result.matched_text);
    }
}

println!("Stats: {:?}", worker.stats());
```

### C API

```c
#include <matchy/matchy.h>

int main() {
    // Open database
    matchy_t *db = matchy_open("threats.mxy");
    if (!db) {
        fprintf(stderr, "Failed to open database\n");
        return 1;
    }

    // Query
    matchy_result_t result = matchy_query(db, "evil.com");
    if (result.found) {
        printf("Match found!\n");
        printf("Data: %s\n", result.data_json);

        // Must free result
        matchy_free_result(result);
    }

    // Close database
    matchy_close(db);
    return 0;
}
```

### MaxMind-Compatible C API

```c
#include <matchy/maxminddb.h>

int main() {
    MMDB_s mmdb;
    int status = MMDB_open("GeoIP2-City.mmdb", MMDB_MODE_MMAP, &mmdb);
    if (status != MMDB_SUCCESS) {
        fprintf(stderr, "Error: %s\n", MMDB_strerror(status));
        return 1;
    }

    int gai_error, mmdb_error;
    MMDB_lookup_result_s result = MMDB_lookup_string(&mmdb, "8.8.8.8", &gai_error, &mmdb_error);

    if (result.found_entry) {
        MMDB_entry_data_s entry_data;
        status = MMDB_get_value(&result.entry, &entry_data, "city", "names", "en", NULL);
        if (status == MMDB_SUCCESS && entry_data.has_data) {
            printf("City: %.*s\n", (int)entry_data.data_size, entry_data.utf8_string);
        }
    }

    MMDB_close(&mmdb);
    return 0;
}
```

---

## Code Review Checklist

When reviewing PRs or writing code, verify:

### Correctness
- [ ] All tests pass (`make ci-local`)
- [ ] New functionality has tests
- [ ] Edge cases are handled
- [ ] Error messages are helpful
- [ ] No panics in library code (only in binaries)

### Performance
- [ ] No performance regressions (`cargo bench`)
- [ ] Unnecessary allocations avoided
- [ ] Hot paths are optimized
- [ ] Caching used appropriately

### Safety
- [ ] No unsafe code in core algorithms
- [ ] FFI boundaries have panic guards
- [ ] Offsets validated before dereferencing
- [ ] Binary format changes documented

### Documentation
- [ ] Public APIs have doc comments
- [ ] Examples included in docs
- [ ] CHANGELOG.md updated
- [ ] Breaking changes documented

### Code Quality
- [ ] Code is formatted (`cargo fmt`)
- [ ] Clippy warnings addressed (`cargo clippy`)
- [ ] Variable names are clear
- [ ] Complex logic has comments
- [ ] No dead code

### Binary Compatibility
- [ ] No changes to `#[repr(C)]` structures
- [ ] Version number bumped if format changed
- [ ] Backward compatibility tested
- [ ] Migration path documented

---

## Resources and Links

### Documentation
- **Official Docs**: https://sethhall.github.io/matchy/
- **API Reference**: https://docs.rs/matchy
- **Crates.io**: https://crates.io/crates/matchy
- **GitHub**: https://github.com/sethhall/matchy

### Key Files
- `README.md` - Project overview, quick start
- `DEVELOPMENT.md` - Architecture, performance analysis
- `CONTRIBUTING.md` - Contribution guidelines
- `CHANGELOG.md` - Version history
- `WARP.md` - Original AI guide (predecessor to this file)

### External References
- **MaxMind MMDB**: https://maxmind.github.io/MaxMind-DB/
- **Paraglob**: https://github.com/zeek/paraglob (inspiration)
- **Aho-Corasick**: String matching algorithm
- **Public Suffix List**: https://publicsuffix.org/

### Community
- **Issues**: https://github.com/sethhall/matchy/issues
- **Discussions**: GitHub Discussions
- **CI Status**: https://github.com/sethhall/matchy/actions

---

## Version History

**Current**: v1.2.2

Recent changes:
- Improved I/O bottleneck detection
- Fixed clippy errors and improved thread auto-tuning
- Optimized LineFileReader to reduce allocations
- Replaced channels with crossbeam for better performance
- Enhanced buffer management

See `CHANGELOG.md` for complete history.

---

## Contact and Support

**Maintainer**: Seth Hall <seth@remor.com>
**Repository**: https://github.com/sethhall/matchy
**License**: BSD-2-Clause

For bugs, feature requests, or questions, open an issue on GitHub.

---

## Acknowledgments

Matchy extends MaxMind's MMDB format with Paraglob's pattern matching, creating a unified database for IPs, strings, and patterns with memory efficiency that scales to hundreds of worker processes.

Special thanks to:
- MaxMind for the MMDB format specification
- Zeek team for the Paraglob concept
- Rust community for excellent tooling and libraries

---

**Last Updated**: 2025-11-14
**Generated for**: AI assistants working with the Matchy codebase
**Status**: Production-ready, actively maintained
