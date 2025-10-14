# Changelog

All notable changes to matchy are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

For detailed version history, see the [full CHANGELOG.md](https://github.com/sethhall/matchy/blob/main/CHANGELOG.md) in the repository.

## [1.0.0] - 2025-10-13

### 🎉 First Stable Release

Matchy 1.0.0 is production-ready! This major release includes database format updates and comprehensive validation infrastructure.

### 🚨 Breaking Changes
- **Database Format**: Updated binary format (databases from v0.5.x must be rebuilt)
- **Match Mode Storage**: Case sensitivity now stored in database metadata

### Highlights

**Validation System**
- Three validation levels: Standard, Strict, and Audit
- Complete database integrity checking before loading
- CLI commands: `matchy validate` and `matchy audit`
- C API: `matchy_validate()` function
- Prevents crashes from corrupted or malicious databases

**Case-Insensitive Matching**
- Build-time `-i/--case-insensitive` flag
- Match mode persisted in database metadata
- Zero query-time overhead
- Automatic deduplication of case variants

**Performance**
- Validation: ~18-20ms on 193MB database (minimal impact)
- All 0.5.x performance characteristics maintained:
  - 7M+ IP queries/second
  - 1M+ pattern queries/second
  - <100μs database loading
  - 30-57% faster than 0.4.x pattern matching

**Testing**
- 163 tests passing (all unit, integration, and doc tests)
- 5 active fuzz targets
- Comprehensive validation coverage

## [0.5.2] - 2025-10-12

### Major Performance Improvements
- **30-57% faster pattern matching** via state-specific AC encoding
- **O(1) database loading** with lazy offset-based lookups
- **Trusted mode** for 15-20% additional speedup (skips validation)

### Critical Bug Fixes
- Fixed UTF-8 boundary panic in glob matching (found by fuzzing)
- Fixed exponential backtracking / OOM vulnerability (found by fuzzing)

### Added
- Comprehensive `matchy bench` command (900+ lines)
- Fuzzing infrastructure with 5 fuzz targets
- Zero-copy optimizations with zerocopy 0.8
- `Database::open_trusted()` API

## [0.5.1] - 2025-10-11

### Added
- cargo-c configuration for C/C++ library installation
- System-wide installation support: `cargo cinstall`
- Headers install to `/usr/local/include/matchy/`

## [0.5.0] - 2025-01-15

### Major Performance Improvements
- **18x faster build times** (424K patterns in ~1 second)
- **15x smaller databases** (~72 MB vs 1.1 GB)
- **10-100x faster literal queries** via O(1) hash lookup

### Added
- Hybrid lookup architecture (hash table + Aho-Corasick + IP trie)
- Literal hash table for exact string matching
- CSV input format support
- MISP streaming import
- Enhanced CLI with JSON output and exit codes

## [0.4.0] - 2025-01-10

### Major Changes
- **Project renamed** from `paraglob-rs` to `matchy`
- Full MMDB integration for IP address lookups
- Unified database format (IP addresses + patterns)
- v3 format with zero-copy AC literal mapping

### Added
- IP address and CIDR range matching (IPv4 and IPv6)
- MISP threat feed integration
- CLI tool: `matchy query`, `matchy inspect`, `matchy build`
- Rich structured data storage (MMDB-compatible encoding)

### Performance
- 1.4M queries/sec with 10K patterns
- 1.5M IP lookups/sec
- <150μs database load time

---

## Release Process

Releases follow [Semantic Versioning](https://semver.org/):

- **MAJOR** (1.x): Incompatible API or format changes
- **MINOR** (x.1): New backward-compatible functionality
- **PATCH** (x.x.1): Backward-compatible bug fixes

## See Also

- [Full CHANGELOG.md](https://github.com/sethhall/matchy/blob/main/CHANGELOG.md)
- [Contributing](contributing.md)
- [Development Guide](development.md)
