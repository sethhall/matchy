# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
