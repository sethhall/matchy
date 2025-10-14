# Database and Querying

`Database` opens and queries databases. See [First Database with Rust](../getting-started/api-rust-first.md)
for a tutorial.

## Opening a Database

```rust
use matchy::Database;

let db = Database::open("database.mxy")?;
```

The database is memory-mapped and loads in under 1 millisecond regardless of size.

### Method Signature

```rust
pub fn open<P: AsRef<Path>>(path: P) -> Result<Database, MatchyError>
```

### Error Handling

```rust
match Database::open("database.mxy") {
    Ok(db) => { /* success */ }
    Err(MatchyError::FileNotFound { path }) => {
        eprintln!("Database not found: {}", path);
    }
    Err(MatchyError::InvalidFormat { reason }) => {
        eprintln!("Invalid database format: {}", reason);
    }
    Err(e) => eprintln!("Error: {}", e),
}
```

## Querying

### Method Signature

```rust
pub fn lookup<S: AsRef<str>>(&self, query: S) -> Result<Option<QueryResult>, MatchyError>
```

### Basic Usage

```rust
match db.lookup("192.0.2.1")? {
    Some(result) => println!("Found: {:?}", result),
    None => println!("Not found"),
}
```

## QueryResult Types

`QueryResult` is an enum with three variants:

### IP Match

```rust
QueryResult::Ip {
    data: Option<HashMap<String, DataValue>>,
    prefix_len: u8,
}
```

Example:
```rust
match db.lookup("192.0.2.1")? {
    Some(QueryResult::Ip { data, prefix_len }) => {
        println!("Matched IP with prefix /{}", prefix_len);
        if let Some(d) = data {
            println!("Data: {:?}", d);
        }
    }
    _ => {}
}
```

### Pattern Match

```rust
QueryResult::Pattern {
    pattern_ids: Vec<u32>,
    data: Vec<Option<HashMap<String, DataValue>>>,
}
```

Example:
```rust
match db.lookup("mail.google.com")? {
    Some(QueryResult::Pattern { pattern_ids, data }) => {
        println!("Matched {} pattern(s)", pattern_ids.len());
        for (i, pattern_data) in data.iter().enumerate() {
            println!("Pattern {}: {:?}", pattern_ids[i], pattern_data);
        }
    }
    _ => {}
}
```

**Note**: A query can match multiple patterns. All matching patterns are returned.

### Exact String Match

```rust
QueryResult::ExactString {
    data: Option<HashMap<String, DataValue>>,
}
```

Example:
```rust
match db.lookup("example.com")? {
    Some(QueryResult::ExactString { data }) => {
        println!("Exact match: {:?}", data);
    }
    _ => {}
}
```

## Complete Example

```rust
use matchy::{Database, QueryResult};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let db = Database::open("database.mxy")?;
    
    // Query different types
    let queries = vec![
        "192.0.2.1",           // IP
        "10.5.5.5",            // CIDR
        "test.example.com",    // Pattern
        "example.com",         // Exact string
    ];
    
    for query in queries {
        match db.lookup(query)? {
            Some(QueryResult::Ip { prefix_len, .. }) => {
                println!("{}: IP match (/{prefix_len})", query);
            }
            Some(QueryResult::Pattern { pattern_ids, .. }) => {
                println!("{}: Pattern match ({} patterns)", query, pattern_ids.len());
            }
            Some(QueryResult::ExactString { .. }) => {
                println!("{}: Exact match", query);
            }
            None => {
                println!("{}: No match", query);
            }
        }
    }
    
    Ok(())
}
```

## Thread Safety

`Database` is `Send + Sync` and can be safely shared across threads:

```rust
use std::sync::Arc;
use std::thread;

let db = Arc::new(Database::open("database.mxy")?);

let handles: Vec<_> = (0..4).map(|i| {
    let db = Arc::clone(&db);
    thread::spawn(move || {
        db.lookup(&format!("192.0.2.{}", i))
    })
}).collect();

for handle in handles {
    handle.join().unwrap()?;
}
```

## Performance

Query performance by entry type:

- **IP addresses**: ~7 million queries/second (138ns avg)
- **Exact strings**: ~8 million queries/second (112ns avg)
- **Patterns**: ~1-2 million queries/second (500ns-1μs avg)

See [Performance Considerations](../guide/performance.md) for details.

## Helper Methods

### Checking Entry Types

```rust
if let Some(QueryResult::Ip { .. }) = result {
    // Handle IP match
}
```

Or using match guards:

```rust
match db.lookup(query)? {
    Some(QueryResult::Ip { prefix_len, .. }) if prefix_len == 32 => {
        println!("Exact IP match");
    }
    Some(QueryResult::Ip { prefix_len, .. }) => {
        println!("CIDR match /{}", prefix_len);
    }
    _ => {}
}
```

## Database Lifecycle

Databases are immutable once opened:

```rust
let db = Database::open("database.mxy")?;
// db.lookup(...) - OK
// db.add_entry(...) - No such method!
```

To update a database:
1. Build a new database with `DatabaseBuilder`
2. Write to a temporary file
3. Atomically replace the old database

```rust
// Build new database
let db_bytes = builder.build()?;
std::fs::write("database.mxy.tmp", &db_bytes)?;
std::fs::rename("database.mxy.tmp", "database.mxy")?;

// Reopen
let db = Database::open("database.mxy")?;
```

## See Also

- [DatabaseBuilder](database-builder.md) - Building databases
- [Data Types Reference](data-types-ref.md) - Data value types
- [Performance Considerations](../guide/performance.md) - Optimization
