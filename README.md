<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="book/src/images/logo-dark.svg">
    <source media="(prefers-color-scheme: light)" srcset="book/src/images/logo-light.svg">
    <img alt="Matchy Logo" src="book/src/images/logo-light.svg" width="200">
  </picture>
</p>

# Matchy

[![CI](https://github.com/sethhall/matchy/actions/workflows/ci.yml/badge.svg)](https://github.com/sethhall/matchy/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/matchy.svg)](https://crates.io/crates/matchy)
[![Documentation](https://docs.rs/matchy/badge.svg)](https://docs.rs/matchy)
[![License](https://img.shields.io/badge/license-BSD--2--Clause-blue.svg)](LICENSE)

**Fast unified database for IP addresses, strings, and glob patterns.**

Match IP addresses, CIDR ranges, exact strings, and thousands of glob patterns in microseconds. One database format, one API, zero compromises on performance.

```rust
let db = Database::open("threats.mxy")?;

// All query types use the same API
db.lookup("8.8.8.8")?;              // IP address
db.lookup("evil.example.com")?;     // Exact string
db.lookup("sub.evil.example.com")?; // Matches *.example.com pattern
```

## Features

- **7M+ queries/second** for IP lookups, 3M+ for glob patterns
- **<1ms load time** via memory mapping, regardless of database size
- **99% memory savings** in multi-process deployments
- **Query result caching**: 2-10x speedup for high-traffic workloads
- **Log scanning**: SIMD-accelerated extraction of domains, IPs (IPv4/IPv6), emails
- **Unified database**: IPs, strings, and patterns in one file
- **MaxMind compatible**: Extended MMDB format
- **Rich metadata**: JSON-like structured data storage
- **Multiple APIs**: Rust, C, and MaxMind-compatible C APIs

## Quick Start

### CLI

```bash
# Install
cargo install matchy

# Create a threats database
cat > threats.csv << EOF
entry,threat_level,category
1.2.3.4,high,malware
10.0.0.0/8,low,internal
*.evil.com,critical,phishing
malware.example.com,high,c2
EOF

matchy build threats.csv -o threats.mxy --format csv

# Query - matches return JSON
matchy query threats.mxy 1.2.3.4
# [{"threat_level":"high","category":"malware"}]

matchy query threats.mxy sub.evil.com
# [{"threat_level":"critical","category":"phishing"}]

# Scan logs for threats (outputs JSON, one match per line)
matchy match threats.mxy access.log --stats
# Outputs JSON to stdout (one line per match):
# {"matched_text":"evil.example.com","match_type":"pattern","data":[{"threat_level":"critical"}]}
# {"matched_text":"1.2.3.4","match_type":"ip","cidr":"1.2.3.0/24",...}
#
# Statistics to stderr (with --stats flag):
# [INFO] Lines processed: 15,234
# [INFO] Lines with matches: 127 (0.8%)
# [INFO] Throughput: 450.23 MB/s
```

### Rust API

```bash
cargo add matchy
```

```rust
use matchy::{Database, DatabaseBuilder, Extractor};

// Build
let mut builder = DatabaseBuilder::new();
builder.add_ip("8.8.8.8", data)?;
builder.add_pattern("*.evil.com", data)?;
builder.save("db.mxy")?;

// Query with caching for high-traffic workloads
let db = Database::from("db.mxy")
    .cache_capacity(10_000)  // LRU cache for 10k queries
    .open()?;

if let Some(result) = db.lookup("sub.evil.com")? {
    println!("Match: {:?}", result);
}

// Extract patterns from logs
let extractor = Extractor::new()?;
for line in log_file.lines() {
    for match_item in extractor.extract_from_line(line.as_bytes()) {
        println!("Found: {:?}", match_item);
    }
}
```

### C API

```c
#include <matchy/matchy.h>

matchy_t *db = matchy_open("db.mxy");
matchy_result_t result = matchy_query(db, "1.2.3.4");
if (result.found) {
    printf("Data: %s\n", result.data_json);
}
matchy_close(db);
```

## Documentation

- **[The Matchy Book](https://sethhall.github.io/matchy/introduction.html)** - Complete guide for CLI and APIs
- **[API Reference](https://docs.rs/matchy)** - Rust API documentation
- **[DEVELOPMENT.md](DEVELOPMENT.md)** - Architecture and implementation details

## Building

```bash
cargo build --release
cargo test
```

**Requirements:** Rust 1.70+

## Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

BSD-2-Clause

## Acknowledgments

Matchy extends MaxMind's MMDB format with [Paraglob's](https://github.com/zeek/paraglob) pattern matching, creating a unified database for IPs, strings, and patterns with memory efficiency that scales to hundreds of worker processes.

