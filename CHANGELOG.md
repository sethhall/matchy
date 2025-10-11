# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
