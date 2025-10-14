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

matchy query threats.mxy benign.com
# []
```

### Rust API

```bash
cargo add matchy
```

```rust
use matchy::{Database, DatabaseBuilder};

// Build
let mut builder = DatabaseBuilder::new();
builder.add_ip("8.8.8.8", data)?;
builder.add_pattern("*.evil.com", data)?;
builder.save("db.mxy")?;

// Query
let db = Database::open("db.mxy")?;
if let Some(result) = db.lookup("sub.evil.com")? {
    println!("Match: {:?}", result);
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

