# Rust API

Complete reference for the Matchy Rust API.

## Overview

The Matchy API provides two main types:
- **`DatabaseBuilder`** - For building databases
- **`Database`** - For querying databases

## Creating a Database

### Basic Builder

```rust
use matchy::{DatabaseBuilder, MatchMode};

let mut builder = DatabaseBuilder::new(MatchMode::CaseSensitive);
```

### Match Modes

```rust
// Case-sensitive matching (exact)
let builder = DatabaseBuilder::new(MatchMode::CaseSensitive);
// "Example.com" ≠ "example.com"

// Case-insensitive matching (recommended for domains)
let builder = DatabaseBuilder::new(MatchMode::CaseInsensitive);
// "Example.com" = "example.com"
```

## Adding Entries

### Automatic Type Detection

The builder automatically detects entry types:

```rust
use std::collections::HashMap;
use matchy::DataValue;

let data = HashMap::new();

// Detected as IPv4 address
builder.add_entry("192.0.2.1", data.clone())?;

// Detected as IPv6 address
builder.add_entry("2001:db8::1", data.clone())?;

// Detected as CIDR range
builder.add_entry("10.0.0.0/8", data.clone())?;

// Detected as glob pattern (has wildcards)
builder.add_entry("*.example.com", data.clone())?;

// Detected as exact string (no wildcards)
builder.add_entry("example.com", data)?;
```

### With Metadata

Attach structured data to any entry:

```rust
let mut metadata = HashMap::new();
metadata.insert("threat_level".to_string(), DataValue::String("high".to_string()));
metadata.insert("score".to_string(), DataValue::Uint32(95));
metadata.insert("active".to_string(), DataValue::Bool(true));

builder.add_entry("192.0.2.1", metadata)?;
```

### Builder Metadata

Set database-level metadata:

```rust
let builder = DatabaseBuilder::new(MatchMode::CaseSensitive)
    .with_database_type("MyCompany-ThreatIntel")
    .with_description("en", "Production threat intelligence database")
    .with_description("es", "Base de datos de inteligencia de amenazas");
```

## Building the Database

```rust
// Build returns Vec<u8>
let database_bytes = builder.build()?;

// Save to file
std::fs::write("database.mxy", &database_bytes)?;

// Or keep in memory for immediate use
```

### Build Statistics

```rust
let stats = builder.stats();
println!("Total entries: {}", stats.total_entries);
println!("IP entries: {}", stats.ip_entries);
println!("Literal entries: {}", stats.literal_entries);
println!("Glob entries: {}", stats.glob_entries);
```

## Opening a Database

### Standard Open

```rust
use matchy::Database;

// Open file (memory-mapped, <1ms)
let db = Database::open("database.mxy")?;
```

### Trusted Mode

Skip UTF-8 validation for databases from trusted sources:

```rust
// Faster, but assumes valid UTF-8
let db = Database::open_trusted("database.mxy")?;
```

**Warning:** Only use `open_trusted` for databases you control. Invalid UTF-8 can cause undefined behavior.

## Querying

### Basic Queries

```rust
use matchy::QueryResult;

// Query automatically detects type (IP vs string)
match db.lookup("192.0.2.1")? {
    Some(result) => println!("Found: {:?}", result),
    None => println!("Not found"),
}
```

### Query Result Types

```rust
match db.lookup(query)? {
    Some(QueryResult::Ip { data, prefix_len }) => {
        println!("IP match:");
        println!("  Data: {:?}", data);
        println!("  CIDR prefix: /{}", prefix_len);
    }
    Some(QueryResult::Pattern { pattern_ids, data }) => {
        println!("Pattern match:");
        println!("  {} patterns matched", pattern_ids.len());
        for (i, pattern_data) in data.iter().enumerate() {
            println!("  Pattern {}: {:?}", pattern_ids[i], pattern_data);
        }
    }
    Some(QueryResult::NotFound) => {
        println!("No match");
    }
    None => {
        println!("Query error or not found");
    }
}
```

### Type-Specific Queries

For performance-critical code, query directly:

```rust
use std::net::IpAddr;

// IP-only query (fastest for known IPs)
let ip: IpAddr = "192.0.2.1".parse()?;
if let Some(QueryResult::Ip { data, prefix_len }) = db.lookup_ip(ip)? {
    println!("Matched CIDR: /{}", prefix_len);
}

// String-only query (patterns + literals)
if let Some(QueryResult::Pattern { pattern_ids, data }) = db.lookup_str("example.com")? {
    println!("Matched {} patterns", pattern_ids.len());
}
```

## Data Types

All supported data types from `DataValue`:

```rust
use matchy::DataValue;

let mut data = HashMap::new();

// Strings
data.insert("name".to_string(), DataValue::String("value".to_string()));

// Numbers
data.insert("uint16".to_string(), DataValue::Uint16(42));
data.insert("uint32".to_string(), DataValue::Uint32(12345));
data.insert("uint64".to_string(), DataValue::Uint64(999999));
data.insert("uint128".to_string(), DataValue::Uint128(u128::MAX));
data.insert("int32".to_string(), DataValue::Int32(-42));

// Floats
data.insert("float".to_string(), DataValue::Float(3.14));
data.insert("double".to_string(), DataValue::Double(2.71828));

// Boolean
data.insert("active".to_string(), DataValue::Bool(true));

// Bytes
data.insert("binary".to_string(), DataValue::Bytes(vec![0xDE, 0xAD, 0xBE, 0xEF]));

// Nested maps
let mut nested = HashMap::new();
nested.insert("inner_key".to_string(), DataValue::String("inner_value".to_string()));
data.insert("nested".to_string(), DataValue::Map(nested));

// Arrays
data.insert("array".to_string(), DataValue::Array(vec![
    DataValue::Uint32(1),
    DataValue::Uint32(2),
    DataValue::Uint32(3),
]));
```

## Database Inspection

```rust
// Check capabilities
println!("Has IP data: {}", db.has_ip_data());
println!("Has literal data: {}", db.has_literal_data());
println!("Has glob data: {}", db.has_glob_data());

// Get counts
println!("IP entries: {}", db.ip_count());
println!("Literal entries: {}", db.literal_count());
println!("Glob entries: {}", db.glob_count());

// Database metadata
if let Some(metadata) = db.metadata() {
    println!("Metadata: {:?}", metadata);
}

// Format info
println!("Format: {}", db.format());
```

## Error Handling

```rust
use matchy::MatchyError;

match db.lookup(query) {
    Ok(Some(result)) => {
        // Process result
    }
    Ok(None) => {
        // No match found
    }
    Err(MatchyError::InvalidIpAddress(addr)) => {
        eprintln!("Invalid IP: {}", addr);
    }
    Err(MatchyError::IoError(e)) => {
        eprintln!("I/O error: {}", e);
    }
    Err(e) => {
        eprintln!("Error: {}", e);
    }
}
```

## Performance Tips

### 1. Reuse Database Handle

```rust
// ✅ Good: Open once, query many times
let db = Database::open("database.mxy")?;
for query in queries {
    db.lookup(query)?;
}

// ❌ Bad: Opening repeatedly
for query in queries {
    let db = Database::open("database.mxy")?;  // Expensive!
    db.lookup(query)?;
}
```

### 2. Use Trusted Mode When Safe

```rust
// For databases you built yourself
let db = Database::open_trusted("my-database.mxy")?;
```

### 3. Type-Specific Queries

```rust
// If you know it's an IP, use lookup_ip directly
let ip: IpAddr = addr.parse()?;
db.lookup_ip(ip)?;  // Faster than db.lookup(addr)?
```

### 4. Batch Operations

```rust
// Process multiple queries efficiently
let db = Database::open("database.mxy")?;
for query in queries {
    if let Some(result) = db.lookup(query)? {
        process(result);
    }
}
```

## Thread Safety

`Database` is `Send + Sync` and can be shared across threads:

```rust
use std::sync::Arc;
use std::thread;

let db = Arc::new(Database::open("database.mxy")?);

let handles: Vec<_> = (0..4).map(|i| {
    let db = Arc::clone(&db);
    thread::spawn(move || {
        // Each thread can query independently
        db.lookup(&format!("query-{}", i))
    })
}).collect();

for handle in handles {
    handle.join().unwrap()?;
}
```

## Complete Example

```rust
use matchy::{DatabaseBuilder, Database, MatchMode, DataValue, QueryResult};
use std::collections::HashMap;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Build database
    let mut builder = DatabaseBuilder::new(MatchMode::CaseInsensitive)
        .with_database_type("Example-DB")
        .with_description("en", "Example database");

    // Add threat intelligence
    let mut threat_data = HashMap::new();
    threat_data.insert("threat_level".to_string(), 
        DataValue::String("critical".to_string()));
    threat_data.insert("score".to_string(), DataValue::Uint32(95));
    
    builder.add_entry("192.0.2.1", threat_data)?;
    builder.add_entry("*.evil.com", HashMap::from([
        ("category".to_string(), DataValue::String("phishing".to_string()))
    ]))?;

    // Build and save
    let db_bytes = builder.build()?;
    std::fs::write("threats.mxy", &db_bytes)?;

    // Query
    let db = Database::open("threats.mxy")?;
    
    // Check IP
    match db.lookup("192.0.2.1")? {
        Some(QueryResult::Ip { data, prefix_len }) => {
            println!("Threat found: {:?}", data);
        }
        _ => println!("No threat"),
    }

    // Check domain
    match db.lookup("phishing.evil.com")? {
        Some(QueryResult::Pattern { pattern_ids, data }) => {
            println!("Matched {} patterns", pattern_ids.len());
        }
        _ => println!("No match"),
    }

    Ok(())
}
```

## See Also

- [Building Your First Database](../first-database.md) - Step-by-step tutorial
- [Data Types Reference](./data-types.md) - Complete `DataValue` documentation
- [Query Guide](./querying.md) - Advanced querying techniques
- [Database Builder Guide](./database-builder.md) - Builder options and patterns
