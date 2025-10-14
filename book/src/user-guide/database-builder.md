# Database Builder

The `MmdbBuilder` provides a high-level API for building Matchy databases in Rust.

## Basic Usage

```rust
use matchy::MmdbBuilder;
use matchy::glob::MatchMode;
use std::collections::HashMap;

let mut builder = MmdbBuilder::new(MatchMode::CaseSensitive);

// Add entries
builder.add_ip("1.2.3.4", HashMap::new())?;
builder.add_glob("*.evil.com", HashMap::new())?;
builder.add_literal("exact.match.com", HashMap::new())?;

// Build and save
let database_bytes = builder.build()?;
std::fs::write("database.mxy", &database_bytes)?;
```

## Match Modes

### Case Sensitive (Default)

```rust
let builder = MmdbBuilder::new(MatchMode::CaseSensitive);
// *.Evil.com matches "test.Evil.com" but NOT "test.evil.com"
```

### Case Insensitive

```rust
let builder = MmdbBuilder::new(MatchMode::CaseInsensitive);
// *.Evil.com matches both "test.Evil.com" AND "test.evil.com"
```

## Adding Entries

### IP Addresses & CIDR Ranges

```rust
use matchy::DataValue;

let mut data = HashMap::new();
data.insert("country".to_string(), DataValue::String("US".to_string()));

builder.add_ip("1.2.3.4", data)?;
builder.add_ip("10.0.0.0/8", HashMap::new())?;
```

### Glob Patterns

```rust
let mut data = HashMap::new();
data.insert("category".to_string(), DataValue::String("malware".to_string()));

builder.add_glob("*.evil.com", data)?;
builder.add_glob("test[0-9].com", HashMap::new())?;
```

### Literal Strings

```rust
builder.add_literal("exact.match.com", HashMap::new())?;
```

### Auto-Detection

```rust
// Automatically detects IP, glob, or literal
builder.add_entry("1.2.3.4", HashMap::new())?;      // IP
builder.add_entry("*.evil.com", HashMap::new())?;   // Glob
builder.add_entry("exact.com", HashMap::new())?;    // Literal
```

## Metadata

```rust
let builder = MmdbBuilder::new(MatchMode::CaseSensitive)
    .with_database_type("ThreatIntel")
    .with_description("en", "Threat intelligence database");
```

## Statistics

```rust
let stats = builder.stats();
println!("Total: {}", stats.total_entries);
println!("IPs: {}", stats.ip_entries);
println!("Globs: {}", stats.glob_entries);
```

## See Also

- [Data Types](data-types.md) - Supported data types
- [Querying Databases](querying.md) - Query databases
- [Rust API](rust-api.md) - Complete API reference
