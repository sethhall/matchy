# Error Handling Reference

Matchy exposes a small set of public error types. Builder workflows use
`MatchyError` or component errors such as `FormatError`; database opening and
querying use `DatabaseError`.

## Public Error Types

```rust
pub enum MatchyError {
    Paraglob(matchy_paraglob::error::ParaglobError),
    Format(matchy_format::FormatError),
    Io(std::io::Error),
    Database(String),
    Validation(String),
}
```

```rust
pub enum DatabaseError {
    Io(String),
    Format(matchy_format::mmdb::MmdbError),
    Unsupported(String),
    Config(String),
}
```

`DatabaseBuilder` methods are re-exported from `matchy-format` and return
`FormatError` directly. The `?` operator can still convert those errors into
`Box<dyn std::error::Error>` in examples and applications.

## Opening A Database

```rust
use matchy::{Database, DatabaseError};

match Database::from("database.mxy").open() {
    Ok(db) => {
        println!("Loaded database");
    }
    Err(DatabaseError::Io(msg)) => {
        eprintln!("File or mmap error: {msg}");
    }
    Err(DatabaseError::Format(err)) => {
        eprintln!("Invalid database format: {err}");
    }
    Err(err) => {
        eprintln!("Database error: {err}");
    }
}
```

## Building A Database

```rust
use matchy::{DatabaseBuilder, DataValue, MatchMode};
use std::collections::HashMap;

let mut builder = DatabaseBuilder::new(MatchMode::CaseInsensitive);

let mut data = HashMap::new();
data.insert("category".to_string(), DataValue::String("malware".to_string()));

match builder.add_entry("*.evil.com", data) {
    Ok(()) => {}
    Err(err) => {
        eprintln!("Entry was rejected: {err}");
    }
}
```

Schema validation errors are also reported when entries are added:

```rust
use matchy::{DatabaseBuilder, DatabaseBuilderExt, DataValue, MatchMode};
use std::collections::HashMap;

let mut builder = DatabaseBuilder::new(MatchMode::CaseInsensitive)
    .with_schema("threatdb")?;

let mut data = HashMap::new();
data.insert("threat_level".to_string(), DataValue::String("high".to_string()));

if let Err(err) = builder.add_entry("192.0.2.1", data) {
    eprintln!("ThreatDB schema validation failed: {err}");
}
```

## Querying

```rust
use matchy::{Database, QueryResult};

let db = Database::from("database.mxy").open()?;

match db.lookup("example.com") {
    Ok(Some(QueryResult::NotFound)) | Ok(None) => {
        println!("No match");
    }
    Ok(Some(result)) => {
        println!("Found: {result:?}");
    }
    Err(err) => {
        eprintln!("Lookup error: {err}");
    }
}
```

`Ok(None)` means the database has no applicable lookup table for the query type.
For example, an IP query against a string-only database can return `None`.
Misses in an existing table are represented by `QueryResult::NotFound`.

## Adding Context

With standard error handling:

```rust
use matchy::Database;

fn load_db(path: &str) -> Result<Database, Box<dyn std::error::Error>> {
    Database::from(path)
        .open()
        .map_err(|err| format!("failed to load database from {path}: {err}").into())
}
```

With `anyhow`:

```rust
use anyhow::{Context, Result};
use matchy::Database;

fn load_db(path: &str) -> Result<Database> {
    Database::from(path)
        .open()
        .with_context(|| format!("failed to load database from {path}"))
}
```

## Retry Logic

```rust
use matchy::{Database, DatabaseError};
use std::thread;
use std::time::Duration;

fn open_with_retry(path: &str, max_attempts: u32) -> Result<Database, DatabaseError> {
    for attempt in 1..=max_attempts {
        match Database::from(path).open() {
            Ok(db) => return Ok(db),
            Err(DatabaseError::Io(_)) if attempt < max_attempts => {
                thread::sleep(Duration::from_millis(100 * u64::from(attempt)));
            }
            Err(err) => return Err(err),
        }
    }
    unreachable!()
}
```

## Complete Example

```rust
use matchy::{Database, DatabaseBuilder, DataValue, MatchMode, QueryResult};
use std::collections::HashMap;
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let db = match Database::from("cache.mxy").open() {
        Ok(db) => db,
        Err(_) => build_database()?,
    };

    for query in ["192.0.2.1", "example.com", "login.evil.com"] {
        match db.lookup(query) {
            Ok(Some(QueryResult::NotFound)) | Ok(None) => {
                println!("{query}: no match");
            }
            Ok(Some(result)) => {
                println!("{query}: {result:?}");
            }
            Err(err) => {
                eprintln!("{query}: {err}");
            }
        }
    }

    Ok(())
}

fn build_database() -> Result<Database, Box<dyn std::error::Error>> {
    let mut builder = DatabaseBuilder::new(MatchMode::CaseInsensitive);

    let mut ip_data = HashMap::new();
    ip_data.insert("description".to_string(), DataValue::String("test IP".to_string()));
    builder.add_entry("192.0.2.1", ip_data)?;

    let mut pattern_data = HashMap::new();
    pattern_data.insert("category".to_string(), DataValue::String("phishing".to_string()));
    builder.add_entry("*.evil.com", pattern_data)?;

    let db_bytes = builder.build()?;
    fs::write("cache.mxy", &db_bytes)?;

    Ok(Database::from("cache.mxy").open()?)
}
```

## See Also

- [DatabaseBuilder](database-builder.md) - Building with validation
- [Database Querying](database-query.md) - Query errors
- [Rust Error Handling](https://doc.rust-lang.org/book/ch09-00-error-handling.html)
