# Database and Querying

`Database` opens and queries databases. See [First Database with Rust](../getting-started/api-rust-first.md)
for a tutorial.

## Opening a Database

### Basic Opening

```rust path=null start=null
use matchy::Database;

// Simple - uses defaults (cache enabled, runtime structural checks on open)
let db = Database::from("database.mxy").open()?;
```

File-backed databases are memory-mapped, avoiding whole-file deserialization.
Opening still performs bounded structural parsing; latency depends on storage,
page-cache state, platform, optional sections, and legacy fallback scanning.
Keep the mapped inode immutable until the database is dropped. Publish updates
by writing a complete new file and atomically replacing the path; never truncate
or rewrite an inode that an open database may still map.

### Builder API

The recommended way to open databases uses the fluent builder API:

```rust path=null start=null
use matchy::Database;

// With custom cache size
let db = Database::from("database.mxy")
    .cache_capacity(1000)
    .open()?;

// Large cache for high repetition workloads
let db = Database::from("threats.mxy")
    .cache_capacity(100_000)
    .open()?;

// No cache (for unique queries)
let db = Database::from("database.mxy")
    .no_cache()
    .open()?;
```

### Builder Methods

| Method | Description |
|--------|-------------|
| `.cache_capacity(size)` | Set the LRU entry ceiling (default: 10,000) |
| `.no_cache()` | Disable caching entirely |
| `.open()` | Load the database |

**Cache Size Guidelines**:
- `0` (via `.no_cache()`): No caching - best for diverse queries
- `100-1000`: Good for moderate repetition
- `10,000` (default): Starting point for measurement
- Larger values: Useful only when the measured hot set and hit rate justify them

Caching applies to IP, literal, glob, and miss results. It is most useful when
avoided traversal or decoding costs outweigh cache lookup and owned-result
clone costs. In addition to the entry ceiling, Matchy caps estimated retained
cache heap at 64 MiB per calling thread across at most 16 recent database
generations.

### Error Handling

```rust
use matchy::{Database, DatabaseError};

match Database::from("database.mxy").open() {
    Ok(db) => { /* success */ }
    Err(DatabaseError::Io(msg)) => {
        eprintln!("I/O error: {}", msg);
    }
    Err(DatabaseError::Format(err)) => {
        eprintln!("Invalid database format: {}", err);
    }
    Err(e) => eprintln!("Error: {}", e),
}
```

## Querying

### lookup() - Direct String Lookup

```rust
pub fn lookup(&self, query: &str) -> Result<Option<QueryResult>, DatabaseError>
```

Basic usage:

```rust
match db.lookup("192.0.2.1")? {
    Some(QueryResult::NotFound) | None => println!("Not found"),
    Some(result) => println!("Found: {:?}", result),
}
```

### lookup_extracted() - Lookup After Extraction

```rust
pub fn lookup_extracted(
    &self,
    item: &matchy::extractor::Match,
    input: &[u8],
) -> Result<Option<QueryResult>, DatabaseError>
```

Efficient lookup for extracted patterns. Automatically uses the optimal lookup path:
- IP addresses use typed `lookup_ip()` (avoids string parsing)
- Other types use string-based `lookup()`

**Usage:**

```rust
use matchy::{Database, QueryResult, extractor::Extractor};

let db = Database::from("threats.mxy").open()?;
let extractor = Extractor::new()?;

let log_line = b"Connection from 192.168.1.1 to evil.com";

for item in extractor.extract_from_line(log_line) {
    if let Some(QueryResult::Ip { .. } | QueryResult::Pattern { .. }) =
        db.lookup_extracted(&item, log_line)?
    {
        println!("Match: {} (type: {})",
            item.as_str(log_line),
            item.item.type_name()
        );
    }
}
```

**Why use this?**

1. **Cleaner code**: No manual matching on `ExtractedItem` variants
2. **Better performance**: IP addresses use direct typed lookups
3. **Future-proof**: New extracted types work automatically

**Parameters:**
- `item`: The extracted match from `Extractor`
- `input`: Original input buffer (needed to extract string slices)

**Returns:** `Ok(Some(QueryResult))` when a matching lookup table exists. Check
for `QueryResult::NotFound` to handle misses. `Ok(None)` means the database has
no applicable lookup table for that query type.

See the [Querying guide](../guide/querying.md#extract-and-lookup-pattern) for more examples.

## QueryResult Types

`QueryResult` is an enum with three variants:

### IP Match

```rust
QueryResult::Ip {
    data: DataValue,
    prefix_len: u8,
    data_offset: u32,
}
```

Example:
```rust
match db.lookup("192.0.2.1")? {
    Some(QueryResult::Ip { data, prefix_len, .. }) => {
        println!("Matched IP with prefix /{}", prefix_len);
        println!("Data: {:?}", data);
    }
    _ => {}
}
```

### Pattern Match

```rust
QueryResult::Pattern {
    pattern_ids: Vec<u32>,
    data: Vec<Option<DataValue>>,
    data_offsets: Vec<u32>,
}
```

Example:
```rust
match db.lookup("mail.google.com")? {
    Some(QueryResult::Pattern { pattern_ids, data, .. }) => {
        println!("Matched {} pattern(s)", pattern_ids.len());
        for (i, pattern_data) in data.iter().enumerate() {
            println!("Pattern {}: {:?}", pattern_ids[i], pattern_data);
        }
    }
    _ => {}
}
```

**Note**: A query can match multiple patterns. All matching patterns are
returned when the query remains within runtime resource limits. Database
lookups reject more than 65,536 matches or one million units in any bounded
matching-work dimension (query bytes, unique literal hits, or raw mapped
candidates plus wildcard checks). They also apply one shared 64-million-unit
CPU-work allowance across matching phases instead of permitting multiplicative
work amplification.
Data decoding for all literal and glob
matches in one query shares the decoder's work and 64 MiB estimated-allocation
budget.
Literal string matches are returned through `QueryResult::Pattern`; exact
strings and glob patterns share the same string lookup result type.

## Complete Example

```rust
use matchy::{Database, QueryResult};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let db = Database::from("database.mxy").open()?;
    
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
            Some(QueryResult::NotFound) | None => {
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

let db = Arc::new(Database::from("database.mxy").open()?);

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

Query cost differs by entry type: IP traversal is bounded by the address width,
exact strings use average-case O(1) hash probing, and glob matching depends on
the input and pattern shape. Throughput and latency are workload- and
hardware-specific rather than API guarantees.

See [Performance Considerations](../guide/performance.md) for measurement
guidance.

## Database Statistics

### Get Statistics

Retrieve comprehensive statistics about database usage:

```rust path=null start=null
use matchy::Database;

let db = Database::from("threats.mxy").open()?;

// Do some queries
db.lookup("1.2.3.4")?;
db.lookup("example.com")?;
db.lookup("test.com")?;

// Get stats
let stats = db.stats();
println!("Total queries: {}", stats.total_queries);
println!("Queries with match: {}", stats.queries_with_match);
println!("Cache hit rate: {:.1}%", stats.cache_hit_rate() * 100.0);
println!("Match rate: {:.1}%", stats.match_rate() * 100.0);
println!("IP queries: {}", stats.ip_queries);
println!("String queries: {}", stats.string_queries);
```

### DatabaseStatsSnapshot Structure

```rust path=null start=null
pub struct DatabaseStatsSnapshot {
    pub total_queries: u64,
    pub queries_with_match: u64,
    pub queries_without_match: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub ip_queries: u64,
    pub string_queries: u64,
}

impl DatabaseStatsSnapshot {
    pub fn cache_hit_rate(&self) -> f64
    pub fn match_rate(&self) -> f64
}
```

**Helper Methods:**
- `cache_hit_rate()` - Returns cache hit rate as a value from 0.0 to 1.0
- `match_rate()` - Returns query match rate as a value from 0.0 to 1.0

### Interpreting Statistics

**Cache Performance:** Compare hit rate together with end-to-end latency and
retained memory under the production workload. A low hit rate can still help if
misses are expensive; a high hit rate does not by itself prove that caching is
worth its memory footprint.

**Query Distribution:**
- High `ip_queries`: Database is being used for IP lookups
- High `string_queries`: Database is being used for domain/pattern matching

The counters include `lookup`, typed `lookup_ip` / `lookup_string`, extracted
lookups, and offset-only `lookup_ref` calls.

## Cache Management

### Clear Cache

Remove all cached query results:

```rust path=null start=null
use matchy::Database;

let db = Database::from("threats.mxy").open()?;

// Do some queries (fills cache)
db.lookup("example.com")?;

// Clear cache to force fresh lookups
db.clear_cache();
```

Useful for benchmarking or when you need to ensure fresh lookups without reopening the database.

## Helper Methods

### Checking Entry Types

```rust path=null start=null
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
let db = Database::from("database.mxy").open()?;
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
let db = Database::from("database.mxy").open()?;
```

## See Also

- [DatabaseBuilder](database-builder.md) - Building databases
- [Data Types Reference](data-types-ref.md) - Data value types
- [Performance Considerations](../guide/performance.md) - Optimization
