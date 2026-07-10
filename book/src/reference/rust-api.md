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

let db = Database::from("database.mxy").open()?;

match db.lookup("192.0.2.1")? {
    Some(QueryResult::Ip { data, prefix_len, .. }) => {
        println!("IP match: {:?}", data);
        println!("Prefix length: {}", prefix_len);
    }
    Some(QueryResult::Pattern { pattern_ids, data, .. }) => {
        println!("Pattern match: {} patterns", pattern_ids.len());
        println!("Data: {:?}", data);
    }
    Some(QueryResult::NotFound) | None => println!("No match"),
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
├── FormatError       // Builder/serialization errors
└── DatabaseError     // Opening/query errors
```

## Error Handling

The re-exported builder returns `Result<T, FormatError>`, while database opening and
querying return `Result<T, DatabaseError>`:

```rust
use matchy::{Database, DatabaseError, FormatError};

match builder.build() {
    Ok(db_bytes) => { /* success */ }
    Err(FormatError::IoError(msg)) => { /* I/O error */ }
    Err(FormatError::InvalidPattern(msg)) => { /* invalid pattern */ }
    Err(e) => { /* other error */ }
}

match Database::from("database.mxy").open() {
    Ok(db) => { /* success */ }
    Err(DatabaseError::Io(msg)) => { /* file or mmap error */ }
    Err(DatabaseError::Format(e)) => { /* invalid database format */ }
    Err(e) => { /* other database error */ }
}
```

Common error types:
- `FormatError::IoError` - File I/O failures from builder workflows
- `FormatError::InvalidPattern` / `PatternError` - Pattern build failures
- `FormatError::ValidationError` - Entry or schema validation failures
- `DatabaseError::Io` - File or mmap failures while opening
- `DatabaseError::Format` - Corrupt database data while opening or querying
- `DatabaseError::Unsupported` - Unsupported operation or format feature
- `DatabaseError::Config` - Configuration or runtime resource-policy limit

## Type Conversion

### From JSON Values

```rust
use matchy::DataValue;
use serde_json::Value;

let json: Value = serde_json::from_str(r#"{"key": "value"}"#)?;
let data: DataValue = serde_json::from_value(json)?;
```

### To JSON

```rust
let json = serde_json::to_value(&data)?;
println!("{}", serde_json::to_string_pretty(&json)?);
```

## Thread Safety

- `Database` is `Send + Sync` - safe to share across threads
- `DatabaseBuilder` is mutable; do not mutate one builder concurrently without
  external synchronization
- Query operations are thread-safe and lock-free

```rust
use std::sync::Arc;

let db = Arc::new(Database::from("database.mxy").open()?);

// Clone Arc and move to threads
let db_clone = Arc::clone(&db);
std::thread::spawn(move || {
    db_clone.lookup("192.0.2.1")
});
```

## Memory Mapping

File-backed databases use memory mapping (`mmap`) to avoid whole-file deserialization:

```rust
// Memory-mapped: avoids whole-file deserialization
let db = Database::from("large-database.mxy").open()?;
// Database is memory-mapped, not loaded into heap
```

Benefits:
- No up-front whole-file deserialization
- Shared pages across processes
- The operating system can page untouched regions on demand

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
