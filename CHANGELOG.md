# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.1] - 2025-10-14

### Fixed
- **Critical: IP Longest Prefix Match Bug** ([#10](https://github.com/sethhall/matchy/issues/10))
  - Fixed insertion order dependency where more specific IP prefixes inserted before less specific ones could be incorrectly overridden
  - Added prefix length tracking to `NodePointer::Data` for proper route specificity comparison
  - Affects both IPv4 and IPv6 address lookups
  - Example: Inserting 192.0.2.1/32 before 192.0.2.0/24 now correctly returns the /32 match
  - This fix is internal only and does not affect the on-disk MMDB format

### Added
- Comprehensive test suite for IP longest prefix matching scenarios
- IPv6 longest prefix match validation tests

## [1.0.0] - 2025-10-13

### 🎉 Major Release - Production Ready

This is the first stable release of matchy, representing a production-ready unified database for IP addresses, string literals, and glob pattern matching. The 1.0.0 release includes database format changes and comprehensive validation infrastructure.

### 🚨 Breaking Changes
- **Database Format**: Updated binary format with new validation metadata (databases must be rebuilt)
- **Match Mode Storage**: Case sensitivity now stored in database metadata (format incompatibility)

### Added
- **Comprehensive Validation System** (`validation.rs` - 3,200+ lines)
  - Three validation levels: Standard (basic checks), Strict (deep analysis), Audit (security review)
  - MMDB format validation: header integrity, metadata consistency, IP tree structure
  - PARAGLOB section validation: AC automaton integrity, pattern consistency checks
  - Safety-critical checks: UTF-8 validation, pointer cycle detection, depth limits, bounds checking
  - IP tree traversal: full recursive validation detecting cycles and orphaned nodes
  - Data section pointer validation: prevents infinite loops from malicious databases
  - CLI commands: `matchy validate` (with `--level` and `--json` flags), `matchy audit` for security analysis
  - C API: `matchy_validate()` function with validation level constants
  - Example: `examples/audit_database.rs` demonstrating validation API usage

- **Case-Insensitive Matching Support**
  - Build-time flag: `-i/--case-insensitive` for `matchy build` command
  - Match mode (case-sensitive/insensitive) persisted in database metadata
  - Case-insensitive literal hash table with automatic query normalization
  - Automatic deduplication of case variants (smaller databases)
  - Zero query-time overhead (simple lowercase conversion)
  - Backward compatible (defaults to case-sensitive)

### Changed
- **CLI Security**: Generated database files now set to read-only (0444 permissions) to protect memory-mapped integrity
- **Database Loader**: Automatically reads and applies match_mode from metadata (no query-time flags needed)
- **Format Version**: Database format updated to support validation metadata and match mode

### Performance
- Validation overhead: ~18-20ms on 193MB database (minimal impact, <0.01% of query time)
- Case-insensitive matching: Zero query-time overhead (normalization at build and lookup)
- All existing performance characteristics maintained from 0.5.x releases

### Testing
- 21 new unit tests for validation system
- All 163 tests passing (increased from 142 in v0.5.x)
- Case-insensitive matching verified for both globs and literals
- Comprehensive validation test coverage

### Documentation
- Updated README.md with validation and case-insensitive matching sections
- Enhanced DEVELOPMENT.md with validation architecture details
- API documentation improvements throughout

## [0.5.2] - 2025-10-12

### 🚀 Major Performance Improvements
- **State-Specific AC Encoding**: 30-57% faster pattern matching
  - ONE encoding (75-80% of states): Single transition stored inline
  - SPARSE encoding (10-15% of states): 2-8 transitions via edge array
  - DENSE encoding (2-5% of states): 9+ transitions via 256-entry lookup table
  - O(1) lookup for high-degree nodes (1KB per dense state)
  - 13% memory reduction overall due to ONE state optimization

- **O(1) Database Loading**
  - AC literal hash table eliminates HashMap construction on load
  - Lazy offset-based pattern data lookups instead of eager deserialization
  - Load time reduced from O(n) to O(1) where n = pattern count
  - <100μs load time maintained at any scale

- **Zero-Copy Optimizations**
  - Added zerocopy derives (FromBytes, IntoBytes, Immutable, KnownLayout)
  - Safe zero-copy header parsing with zerocopy::Ref
  - Upgraded to zerocopy 0.8 with modern trait derivations

- **Trusted Mode** for maximum performance
  - `Database::open_trusted()` API skips UTF-8 validation
  - 15-20% query speedup for databases from trusted sources
  - `--trusted` flag for matchy CLI bench command
  - Safe by default: `Database::open()` still validates

### Added
- **Comprehensive Benchmark Command** (`matchy bench`)
  - 900+ lines of benchmarking infrastructure
  - Benchmarks build time, load time, query performance
  - Supports ip, literal, pattern, and combined database types
  - Configurable entry counts, load iterations, query counts
  - Hit rate control for realistic query distributions
  - Optional temp file mode or persistent output

- **Fuzzing Infrastructure**
  - Comprehensive `docs/FUZZING_GUIDE.md` (663 lines)
  - 5 fuzz targets: pattern_matching, ip_lookup, glob_patterns, data_values, literal_exact_match
  - `fuzz/README.md` (229 lines) and `FUZZ_TARGETS_SUMMARY.md` (71 lines)
  - `fuzz_quickstart.sh` automation script
  - cargo-fuzz configuration in fuzz/ directory

- **New Example Programs**
  - `examples/prefix_convention.rs`: Demonstrates custom matching semantics (131 lines)

- **C FFI Additions**
  - `matchy_open_trusted()` for trusted database loading
  - Updated matchy.h header with new API function

### Fixed
- **Critical: UTF-8 Boundary Panic** (discovered by fuzzing)
  - Star wildcard (*) matching could panic on multi-byte UTF-8 characters
  - Fixed by using character boundary iteration instead of byte positions
  - Added `test_utf8_boundary_in_star_matching` regression test
  - Example: Pattern `*4**4\4**4\*` with text containing 'Ż' would crash

- **Critical: Exponential Backtracking / OOM** (discovered by fuzzing)
  - Patterns with multiple wildcards could cause exponential backtracking
  - Fixed by adding step counter (100,000 steps) to limit backtracking
  - Added `test_backtracking_limit` regression test
  - Example: Pattern `*a*b*c*d*e*f*g*h*i*j*k*l*m*n*o*p*` against mismatched text

- MMDB data section pointer resolution
- Windows compilation issues
- Rustdoc warnings
- docs.rs build configuration

### Changed
- **Breaking**: Removed C++ wrapper API (C API remains)
- **Internal**: Paraglob now stores BufferStorage + metadata instead of cached data
- **Internal**: Replace pattern_data_cache with pattern_data_map offset metadata
- **Build**: Minor regression (+5-10% slower build time) for 30-57% faster queries

### Removed
- Obsolete example programs replaced by CLI bench:
  - `examples/large_scale_ip_benchmark.rs`
  - `examples/test_v3_performance.rs`

### Performance
- **Pattern Matching**: 30-57% faster across all benchmarks
  - p10_t10000/high: +103% throughput
  - p100_t10000/high: +106% throughput  
  - p1000_t10000/high: +133% throughput
  - realistic_workload: +49% throughput
- **Database Loading**: O(1) vs O(n), <100μs at any scale
- **Trusted Mode**: 15-20% additional query speedup
- **Memory**: 13% reduction due to ONE state encoding

### Dependencies
- Added `zerocopy = "0.8"` for safe zero-copy parsing

### Testing
- All 79 tests passing
- 5 comprehensive fuzz targets active
- Both critical bugs discovered and fixed within minutes of fuzzing

### Documentation
- Added 64-byte cache-line alignment documentation
- Added cross-platform endianness support documentation
- Updated WARP.md with performance characteristics
- Added trusted vs safe mode trade-off notes
- Comprehensive fuzzing guide and best practices
- Updated README.md with performance claims (7M+ IP, 1M+ pattern queries/sec)
- Better examples with clearer comments

## [0.5.1] - 2025-10-11

### Added
- **cargo-c Configuration** for C/C++ library installation
  - Complete cargo-c metadata in Cargo.toml
  - Headers install to `/usr/local/include/matchy/`
  - Proper pkg-config support with correct include paths
  - `strip_include_path_components` for correct `#include <matchy/matchy.h>`
  - Documentation: `docs/C_INSTALLATION.md` (273 lines)
  - Documentation: `docs/CARGO_C_SETUP.md` with implementation details

### Changed
- Added `capi` feature required by cargo-c
- Updated installation instructions for system-wide library installation

### Documentation
- Updated README.md with installation instructions
- Complete C installation guide with usage examples

### Installation
Users can now install matchy as a system library:
```bash
cargo install cargo-c
sudo cargo cinstall --release --prefix=/usr/local
```

## [0.5.0] - 2025-01-15

### 🚀 Major Performance Improvements
- **Hybrid Lookup Architecture**: Three-tier lookup system for optimal performance
  - Hash table for literal strings: O(1) exact match
  - Aho-Corasick automaton for glob patterns only
  - IP binary trie for IP addresses
- **18x Faster Build Times**: 424K patterns now build in ~1 second (was ~18 seconds)
- **15x Smaller Databases**: ~72 MB for mixed datasets (was 1.1 GB)
- **10-100x Faster Literal Queries**: O(1) hash lookup vs O(n) AC scan

### Added
- **Literal Hash Table** (`literal_hash.rs`)
  - FxHash-based hash table with linear probing
  - Memory-mapped format for zero-copy loading
  - Automatic deduplication of identical data
  - Pattern ID to data offset mapping

- **CSV Input Format**
  - Build databases from CSV files with metadata
  - First column must be "entry" or "key"
  - Automatic type inference (numbers, booleans, strings)
  - Support for multiple CSV files

- **MISP Streaming Import**
  - Low-memory streaming processing of MISP files
  - `MispImporter::build_from_files()` for large datasets
  - Automatic file type detection (skips manifest.json, etc.)
  - IP subnet support (ip-src/netmask, ip-dst/netmask)

- **Enhanced CLI Output**
  - Query results always return JSON arrays
  - Exit codes: 0 = found, 1 = not found
  - Quiet mode (`--quiet`) for scripting
  - Verbose statistics during build
  - Better progress indicators

- **New Database API Methods**
  - `add_literal()` - Explicit literal string (no wildcards)
  - `add_glob()` - Explicit glob pattern
  - `add_ip()` - Explicit IP/CIDR entry
  - `has_literal_data()` - Check for literal support
  - `has_glob_data()` - Check for glob support
  - `has_string_data()` - Check for any string support
  - `literal_count()` - Get literal count
  - `glob_count()` - Get glob count
  - `ip_count()` - Get IP count

- **C API Additions**
  - `matchy_has_literal_data()`
  - `matchy_has_glob_data()`
  - `matchy_has_string_data()`

### Changed
- **Breaking**: Query CLI now always returns JSON arrays (was mixed format)
- **Breaking**: `has_pattern_data()` deprecated in favor of `has_literal_data()` / `has_glob_data()`
- **MISP Import**: All indicators now use explicit `add_literal()` / `add_ip()` methods
- **Auto-detection**: IP parsing is more strict, validates CIDR notation
- **Database Format**: Added MMDB_LITERAL section marker
- **Statistics**: Split `pattern_entries` into `literal_entries` + `glob_entries`
- **Build Process**: Builder now takes ownership on build (fixes double-build bug)

### Fixed
- Builder can now be built multiple times without panic
- CSV parsing errors provide better context
- MISP importer properly handles non-event files
- Glob validation prevents invalid patterns from being accepted
- Memory deduplication during streaming import

### Performance
- **Build Time** (424K patterns):
  - Before: ~18 seconds
  - After: ~1 second (18x faster)
- **Database Size** (424K patterns):
  - Before: 1.1 GB
  - After: ~72 MB (15x smaller)
- **Query Time** (literal matches):
  - 10-100x faster via O(1) hash lookup

### Documentation
- Added comprehensive README section on building databases
- All input formats documented (text, CSV, JSON, MISP)
- Query examples with expected output
- Database inspection guide
- Architecture proposal document (docs/ARCHITECTURE_PROPOSAL.md)
- Better inline code documentation

### Dependencies
- Added `rustc-hash` 2.1.1 for fast FxHash implementation
- Added `csv` 1.3.1 for CSV file parsing

## [0.4.0] - 2025-01-10

### 🎉 Major Changes
- **Project Rename**: `paraglob-rs` → `matchy` - now a unified database for IP addresses and patterns
- **MMDB Integration**: Full MaxMind DB (MMDB) format support for IP address lookups
- **Unified Database**: Single database format supporting both IP addresses and glob patterns
- **v3 Format**: Zero-copy AC literal mapping for O(1) database loading

### Added
- **IP Address Support**
  - IP address and CIDR range matching using binary trie
  - IPv4 and IPv6 support
  - Compatible with MaxMind GeoIP databases
  - Automatic IP vs pattern detection in queries

- **MISP Integration**
  - Direct import from MISP JSON threat feeds
  - Preserves all MISP metadata (tags, threat levels, categories)
  - Automatic indicator type detection (IPs, domains, hashes, URLs)
  - Built-in MISP attribute parsers

- **Unified Database API**
  - `Database::open()` - works with any database format
  - `Database::lookup()` - auto-detects query type (IP or pattern)
  - `QueryResult` enum for type-safe result handling
  - `MmdbBuilder` for building combined IP + pattern databases

- **CLI Tool**
  - `matchy query` - Query databases
  - `matchy inspect` - Inspect database metadata
  - `matchy build` - Build databases from JSON
  - Support for MISP JSON import

- **Data Section (v2 Format)**
  - Rich structured data storage with patterns
  - MMDB-compatible encoding (maps, arrays, strings, numbers)
  - Automatic data deduplication
  - Pattern data retrieval API

- **v3 Format Improvements**
  - Pre-serialized AC literal mapping
  - O(1) database loading (was O(n))
  - Maintains <100μs load time at any scale
  - Backward compatible with v2 format

### Fixed
- Alignment bug in v3 AC literal mapping deserialization
- Memory safety in pointer casting for unaligned data
- All clippy warnings resolved
- Documentation examples updated to use `matchy` crate name

### Changed
- **Breaking**: Crate renamed from `paraglob-rs` to `matchy`
- **Breaking**: All imports now use `matchy::` instead of `paraglob_rs::`
- C API version function now uses `CARGO_PKG_VERSION` automatically
- Project description updated to reflect database capabilities
- GitHub repository renamed to `matchy`

### Performance
- 1.4M queries/sec with 10K patterns (Apple M4)
- 1M queries/sec with 50K patterns (Apple M4)
- 1.5M IP lookups/sec (binary tree)
- <150μs database load time via mmap (all formats)
- ~4ms build time for 1K entries

### Testing
- 93 unit tests (all passing)
- 23 integration tests (all passing)
- 18 doc tests (all passing)
- Total: 134 tests, 100% passing

### Migration from paraglob-rs

```rust
// Old (paraglob-rs)
use paraglob_rs::Paraglob;

// New (matchy)
use matchy::Paraglob;
// or use the unified database API:
use matchy::Database;
```

## [0.3.1] - Previous Release

See paraglob-rs crate for version history before the rename.
