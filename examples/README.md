# Examples

This directory contains example programs demonstrating paraglob-rs usage and capabilities.

## Examples

### `glob_demo.rs`
Educational demo showing glob pattern matching features:
- Basic wildcards (`*`, `?`)
- Character classes (`[...]`, `[!...]`)
- Case sensitivity
- Escape sequences
- UTF-8 support
- Performance characteristics

**Run:** `cargo run --example glob_demo`

### `production_test.rs`
Real-world production usage example demonstrating:
- Building pattern matchers
- Matching performance
- Serialization to disk
- Zero-copy memory-mapped loading
- Multi-process memory sharing benefits
- Batch processing

**Run:** `cargo run --release --example production_test`

### `cpp_comparison_test.rs`
Performance benchmark matching the C++ reference implementation:
- 10K patterns, 20K queries (must exceed 100K qps)
- 50K patterns, 10K queries (must exceed 100K qps)
- CI/CD regression testing

**Run:** `cargo run --release --example cpp_comparison_test`

## Quick Start

```bash
# Try the interactive demo
cargo run --example glob_demo

# Check production readiness
cargo run --release --example production_test

# Verify performance meets requirements
cargo run --release --example cpp_comparison_test

# Run integration tests
cargo test --test integration_tests
```
