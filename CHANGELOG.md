# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial release of paraglob-rs
- Rust implementation of multi-pattern glob matching
- Aho-Corasick automaton with offset-based data structures
- Zero-copy memory-mapped file support
- C FFI for cross-language integration
- Binary format compatible with C++ implementation
- Comprehensive test suite (79 tests)
- Criterion benchmarks
- Example programs (glob_demo, production_test, cpp_comparison_test)
- Documentation (README, DEVELOPMENT, CONTRIBUTING)
- CI/CD with GitHub Actions
  - Multi-platform testing (Linux, macOS, Windows)
  - Code formatting checks
  - Clippy linting
  - Documentation builds
  - Security audits
  - Code coverage

### Performance
- 1.4M queries/sec with 10K patterns (Apple M4)
- 1M queries/sec with 50K patterns (Apple M4)
- <100μs database load time via mmap
- ~0.3ms build time for typical pattern sets

## [0.1.0] - TBD

Initial release.
