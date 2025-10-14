# First Database with Rust

Let's build and query a [*database*][def-database] using the Rust API.

## Create a new project

```console
$ cargo new --bin matchy-example
$ cd matchy-example
```

Add Matchy to `Cargo.toml`:

```toml
[dependencies]
matchy = "{{version_minor}}"
```

## Write the code

Edit `src/main.rs`:

```rust
use matchy::{Database, DatabaseBuilder, MatchMode, DataValue, QueryResult};
use std::collections::HashMap;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a builder
    let mut builder = DatabaseBuilder::new(MatchMode::CaseInsensitive);
    
    // Add an IP address
    let mut ip_data = HashMap::new();
    ip_data.insert("threat_level".to_string(), DataValue::String("high".to_string()));
    ip_data.insert("category".to_string(), DataValue::String("malware".to_string()));
    builder.add_entry("192.0.2.1", ip_data)?;
    
    // Add a CIDR range
    let mut cidr_data = HashMap::new();
    cidr_data.insert("network".to_string(), DataValue::String("internal".to_string()));
    builder.add_entry("10.0.0.0/8", cidr_data)?;
    
    // Add a pattern
    let mut pattern_data = HashMap::new();
    pattern_data.insert("category".to_string(), DataValue::String("phishing".to_string()));
    builder.add_entry("*.evil.com", pattern_data)?;
    
    // Build and save
    let database_bytes = builder.build()?;
    std::fs::write("threats.mxy", &database_bytes)?;
    println!("✅ Built database: {} bytes", database_bytes.len());
    
    // Open the database (memory-mapped)
    let db = Database::open("threats.mxy")?;
    println!("✅ Loaded database");
    
    // Query an IP address
    match db.lookup("192.0.2.1")? {
        Some(QueryResult::Ip { data, prefix_len }) => {
            println!("🔍 IP match (/{}):", prefix_len);
            println!("  {:?}", data);
        }
        _ => println!("Not found"),
    }
    
    // Query a pattern
    match db.lookup("phishing.evil.com")? {
        Some(QueryResult::Pattern { pattern_ids, data }) => {
            println!("🔍 Pattern match:");
            println!("  Matched {} pattern(s)", pattern_ids.len());
            println!("  {:?}", data[0]);
        }
        _ => println!("Not found"),
    }
    
    Ok(())
}
```

## Run it

```console
$ cargo run
   Compiling matchy v{{version_minor}}
   Compiling matchy-example v0.1.0
    Finished dev [unoptimized] target(s)
     Running `target/debug/matchy-example`
✅ Built database: 2847 bytes
✅ Loaded database
🔍 IP match (/32):
  {"threat_level": String("high"), "category": String("malware")}
🔍 Pattern match:
  Matched 1 pattern(s)
  Some({"category": String("phishing")})
```

## Understanding the code

### 1. Create a DatabaseBuilder

```rust
let mut builder = DatabaseBuilder::new(MatchMode::CaseInsensitive);
```

The [*match mode*][def-match-mode] determines whether string comparisons are case-sensitive.
`CaseInsensitive` is recommended for domain matching.

### 2. Add entries

```rust
builder.add_entry("192.0.2.1", ip_data)?;
```

The `add_entry` method accepts any string key and a `HashMap<String, DataValue>` for the
associated data. Matchy automatically detects whether the key is an IP, CIDR, pattern, or
exact string.

**Advanced**: For explicit control over entry types, use type-specific methods:

```rust
builder.add_ip("192.0.2.1", data)?;         // Force IP
builder.add_literal("*.txt", data)?;         // Force exact match (no wildcard)
builder.add_glob("*.evil.com", data)?;       // Force pattern
```

Or use type prefixes with `add_entry`:

```rust
builder.add_entry("literal:file*.txt", data)?;  // Match literal asterisk
builder.add_entry("glob:simple.com", data)?;    // Force pattern matching
```

See [Entry Types - Prefix Technique](../guide/entry-types.md#explicit-type-control-prefix-technique) for details.

### 3. Build the database

```rust
let database_bytes = builder.build()?;
std::fs::write("threats.mxy", &database_bytes)?;
```

The `build()` method produces a `Vec<u8>` containing the optimized binary database. You
can write it to a file or transmit it over a network.

### 4. Open and query

```rust
let db = Database::open("threats.mxy")?;
let result = db.lookup("192.0.2.1")?;
```

`Database::open()` memory-maps the file, loading it in under 1ms. The `lookup()` method
returns an `Option<QueryResult>` that indicates whether a match was found and what type
of match it was.

## Data types

Matchy supports several [*data value*][def-data-value] types:

```rust
use matchy::DataValue;

let mut data = HashMap::new();
data.insert("string".to_string(), DataValue::String("text".to_string()));
data.insert("integer".to_string(), DataValue::Uint32(42));
data.insert("float".to_string(), DataValue::Double(3.14));
data.insert("boolean".to_string(), DataValue::Bool(true));
data.insert("array".to_string(), DataValue::Array(vec![
    DataValue::String("one".to_string()),
    DataValue::String("two".to_string()),
]));
```

See [Data Types and Values](../guide/data-types.md) for complete details.

## Error handling

All Matchy operations return `Result<T, MatchyError>`:

```rust
match db.lookup("192.0.2.1") {
    Ok(Some(result)) => println!("Found: {:?}", result),
    Ok(None) => println!("Not found"),
    Err(e) => eprintln!("Error: {}", e),
}
```

## Going further

* [Matchy Guide](../guide/index.md) - Deeper dive into concepts
* [Rust API Reference](../reference/rust-api.md) - Complete API documentation
* [Data Types](../guide/data-types.md) - All supported data types
* [Pattern Matching](../guide/patterns.md) - Glob pattern syntax

[def-database]: ../appendix/glossary.md#database '"database" (glossary entry)'
[def-match-mode]: ../appendix/glossary.md#match-mode '"match mode" (glossary entry)'
[def-data-value]: ../appendix/glossary.md#data-value '"data value" (glossary entry)'
