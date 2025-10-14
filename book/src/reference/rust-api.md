# The Rust API

This chapter provides an overview of the Rust API. For your first steps with the
Rust API, see [First Database with Rust](../getting-started/api-rust-first.md).

## Core Types

The Matchy Rust API provides these main types:

**Building databases:**
- `DatabaseBuilder` - Builds new databases
- `MatchMode` - Case sensitivity setting
- `DataValue` - Structured data values

**Querying databases:**
- `Database` - Opened database (read-only)
- `QueryResult` - Query match results

**Error handling:**
- `MatchyError` - Error type for all operations
- `Result<T>` - Standard Rust result type

## Quick Reference

### Building a Database

```rust
use matchy::{DatabaseBuilder, MatchMode, DataValue};
use std::collections::HashMap;

let mut builder = DatabaseBuilder::new(MatchMode::CaseInsensitive);

let mut data = HashMap::new();
data.insert("field".to_string(), DataValue::String("value".to_string()));
builder.add_entry("192.0.2.1", data)?;

let db_bytes = builder.build()?;
std::fs::write("database.mxy", &db_bytes)?;
```

### Querying a Database

```rust
use matchy::{Database, QueryResult};

let db = Database::open("database.mxy")?;

match db.lookup("192.0.2.1")? {
    Some(QueryResult::Ip { data, prefix_len }) => {
        println!("IP match: {:?}", data);
    }
    Some(QueryResult::Pattern { pattern_ids, data }) => {
        println!("Pattern match: {} patterns", pattern_ids.len());
    }
    Some(QueryResult::ExactString { data }) => {
        println!("Exact match: {:?}", data);
    }
    None => println!("No match"),
}
```

## Module Structure

```rust
matchy
├── DatabaseBuilder    // Building databases
├── Database          // Querying databases
├── MatchMode         // Case sensitivity enum
├── DataValue         // Data type enum
├── QueryResult       // Query result enum
└── MatchyError       // Error type
```

## Error Handling

All operations return `Result<T, MatchyError>`:

```rust
use matchy::MatchyError;

match builder.build() {
    Ok(db_bytes) => { /* success */ }
    Err(MatchyError::IoError(e)) => { /* I/O error */ }
    Err(MatchyError::InvalidFormat { .. }) => { /* format error */ }
    Err(e) => { /* other error */ }
}
```

Common error types:
- `IoError` - File I/O failures
- `InvalidFormat` - Corrupt or wrong database format
- `InvalidEntry` - Invalid key/data during building
- `PatternError` - Invalid pattern syntax

## Type Conversion

### From JSON

```rust
use matchy::DataValue;
use serde_json::Value;

let json: Value = serde_json::from_str(r#"{"key": "value"}"#)?;
let data = DataValue::from_json(&json)?;
```

### To JSON

```rust
let json = data.to_json()?;
println!("{}", serde_json::to_string_pretty(&json)?);
```

## Thread Safety

- `Database` is `Send + Sync` - safe to share across threads
- `DatabaseBuilder` is `!Send + !Sync` - use one per thread
- Query operations are thread-safe and lock-free

```rust
use std::sync::Arc;

let db = Arc::new(Database::open("database.mxy")?);

// Clone Arc and move to threads
let db_clone = Arc::clone(&db);
std::thread::spawn(move || {
    db_clone.lookup("192.0.2.1")
});
```

## Memory Mapping

Databases use memory mapping (`mmap`) for instant loading:

```rust
// Opens instantly regardless of database size
let db = Database::open("large-database.mxy")?;
// Database is memory-mapped, not loaded into heap
```

Benefits:
- Sub-millisecond loading
- Shared pages across processes
- Work with databases larger than RAM

## Detailed Documentation

See the following chapters for complete details:

- [DatabaseBuilder](database-builder.md) - Complete builder API
- [Database and Querying](database-query.md) - Complete query API
- [Data Types Reference](data-types-ref.md) - All data types

## API Documentation

For rustdoc-generated API documentation:

```console
$ cargo doc --open
```

Or view online at [docs.rs/matchy](https://docs.rs/matchy)

## Examples

See the [Examples](../appendix/examples.md) appendix for complete working examples.
