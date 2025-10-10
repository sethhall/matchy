# Examples

This directory contains example programs demonstrating matchy usage and capabilities.

## Building Databases

### `build_ip_database.rs`
Demonstrates building an IP address database with CIDR ranges:
- Adding IPv4 and IPv6 addresses
- CIDR range support (e.g., `192.168.0.0/16`)
- Attaching rich metadata to each entry
- Building and serializing to MMDB format
- Database statistics

**Run:** `cargo run --example build_ip_database`

### `build_combined_database.rs`
The power of the unified MMDB format - IP addresses AND patterns in one database:
- Combining IP lookups with pattern matching
- Single database for both types of queries
- Shared data section with automatic deduplication
- Real-world threat intelligence use case
- Demonstrates both search trees and Aho-Corasick automaton

**Run:** `cargo run --example build_combined_database`

### `build_misp_database.rs`
Builds a threat intelligence database from MISP JSON files:
- Loads MISP JSON threat intelligence feeds
- Extracts indicators (IPs, domains, hashes, etc.)
- Preserves all metadata (tags, threat levels, events)
- Demonstrates real-world threat intelligence workflow
- Supports multiple input files

**Run:** `cargo run --example build_misp_database -- misp-example.json`

### `custom_metadata.rs`
Shows how to set custom database metadata:
- Custom database type identifiers
- Multi-language descriptions
- Database versioning and branding
- Corporate deployment use case

**Run:** `cargo run --example custom_metadata`

### `incremental_builder.rs`
Demonstrates incremental pattern building with associated data:
- Adding patterns one at a time
- Attaching rich threat intelligence metadata
- Duplicate pattern detection
- Useful for streaming threat feeds
- Pattern data retrieval after building

**Run:** `cargo run --example incremental_builder`

## Querying Databases

### `geoip_query.rs`
Query GeoIP databases (MaxMind format):
- Loading MMDB GeoIP databases
- IP address lookups
- IPv6 support
- Displaying geographic data
- Demo mode with multiple IPs

**Run:** `cargo run --example geoip_query -- GeoLite2-Country.mmdb 8.8.8.8`

### `combined_query.rs`
Querying unified databases with both IP and pattern data:
- Automatic query type detection (IP vs pattern)
- Handling mixed-mode databases
- Displaying results for both query types
- Useful for threat intelligence lookups

**Run:** `cargo run --example combined_query -- combined_database.mmdb`

## Pattern Matching

### `glob_demo.rs`
Educational demo showing glob pattern matching features:
- Basic wildcards (`*`, `?`)
- Character classes (`[...]`, `[!...]`)
- Case sensitivity modes
- Escape sequences
- UTF-8 support
- Performance characteristics

**Run:** `cargo run --example glob_demo`

## Performance & Testing

### `production_test.rs`
Real-world production usage example demonstrating:
- Building pattern matchers
- Matching performance with realistic workloads
- Serialization to disk
- Zero-copy memory-mapped loading
- Multi-process memory sharing benefits
- Batch processing patterns

**Run:** `cargo run --release --example production_test`

### `cpp_comparison_test.rs`
Performance benchmark matching the C++ reference implementation:
- 10K patterns, 20K queries (must exceed 100K qps)
- 50K patterns, 10K queries (must exceed 100K qps)
- Fixed seed for reproducibility
- CI/CD regression testing
- Verifies performance targets are met

**Run:** `cargo run --release --example cpp_comparison_test`

### `test_v3_performance.rs`
Tests zero-copy loading performance of the v3 format:
- Scales from 1K to 50K patterns
- Measures build time vs load time
- Demonstrates O(1) loading time
- Shows massive improvement over v2 format
- Critical for multi-process deployments

**Run:** `cargo run --release --example test_v3_performance`

## Quick Start

```bash
# Building databases
cargo run --example build_ip_database
cargo run --example build_combined_database
cargo run --example build_misp_database -- misp-example.json

# Querying
cargo run --example geoip_query -- GeoLite2-Country.mmdb 8.8.8.8
cargo run --example combined_query -- combined_database.mmdb

# Pattern matching demo
cargo run --example glob_demo

# Performance validation
cargo run --release --example production_test
cargo run --release --example cpp_comparison_test
cargo run --release --example test_v3_performance

# Run integration tests
cargo test --test integration_tests
```

## Example Workflow

1. **Build a combined threat database:**
   ```bash
   cargo run --example build_combined_database
   ```

2. **Query it for threats:**
   ```bash
   cargo run --example combined_query -- combined_database.mmdb evil.com
   cargo run --example combined_query -- combined_database.mmdb 192.168.1.100
   ```

3. **Import MISP threat intelligence:**
   ```bash
   cargo run --example build_misp_database -- threat-feed.json
   ```

4. **Verify performance:**
   ```bash
   cargo run --release --example cpp_comparison_test
   ```
