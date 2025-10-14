# First Steps with Matchy

This section provides a quick sense for working with Matchy [*databases*][def-database]. We
demonstrate building a database, saving it to disk, and querying it.

## Creating a new database

To start a new database, create a `DatabaseBuilder`:

```rust
use matchy::{DatabaseBuilder, MatchMode};

let mut builder = DatabaseBuilder::new(MatchMode::CaseInsensitive);
```

The `MatchMode` determines how string and pattern matching is performed. `CaseInsensitive`
is recommended for domain matching.

## Adding entries

Let's add some entries to our database:

```rust
use matchy::DataValue;
use std::collections::HashMap;

// Add an IP address
let mut ip_data = HashMap::new();
ip_data.insert("threat".to_string(), DataValue::String("high".to_string()));
builder.add_entry("192.0.2.1", ip_data)?;

// Add a CIDR range
let mut cidr_data = HashMap::new();
cidr_data.insert("network".to_string(), DataValue::String("internal".to_string()));
builder.add_entry("10.0.0.0/8", cidr_data)?;

// Add a pattern
let mut pattern_data = HashMap::new();
pattern_data.insert("category".to_string(), DataValue::String("malware".to_string()));
builder.add_entry("*.evil.com", pattern_data)?;
```

Matchy automatically detects whether an entry is an IP address, CIDR range, pattern, or
exact string match.

## Building and saving

Build the database and save it to a file:

```rust
let database_bytes = builder.build()?;
std::fs::write("example.mxy", &database_bytes)?;
```

The `.build()` method produces an optimized binary representation. The `.mxy` extension
is conventional but not required.

## Querying

Open the database and query it:

```rust
use matchy::{Database, QueryResult};

let db = Database::open("example.mxy")?;

// Query an IP address
match db.lookup("192.0.2.1")? {
    Some(QueryResult::Ip { data, prefix_len }) => {
        println!("Found IP: {:?}", data);
    }
    _ => println!("Not found"),
}
```

The database is memory-mapped, so it loads in under 1 millisecond regardless of size.

## Query a pattern

```rust
match db.lookup("phishing.evil.com")? {
    Some(QueryResult::Pattern { pattern_ids, data }) => {
        println!("Matched pattern: *.evil.com");
        println!("Data: {:?}", data[0]);
    }
    _ => println!("Not found"),
}
```

The string `"phishing.evil.com"` matches the pattern `"*.evil.com"` that we added earlier.

## Complete example

Here's a complete program:

```rust
use matchy::{Database, DatabaseBuilder, MatchMode, DataValue, QueryResult};
use std::collections::HashMap;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create builder
    let mut builder = DatabaseBuilder::new(MatchMode::CaseInsensitive);
    
    // Add entries
    let mut data = HashMap::new();
    data.insert("threat".to_string(), DataValue::String("high".to_string()));
    builder.add_entry("192.0.2.1", data)?;
    
    let mut pattern_data = HashMap::new();
    pattern_data.insert("category".to_string(), DataValue::String("malware".to_string()));
    builder.add_entry("*.evil.com", pattern_data)?;
    
    // Build and save
    let database_bytes = builder.build()?;
    std::fs::write("example.mxy", &database_bytes)?;
    
    // Open and query
    let db = Database::open("example.mxy")?;
    
    if let Some(result) = db.lookup("192.0.2.1")? {
        println!("Found: {:?}", result);
    }
    
    if let Some(result) = db.lookup("phishing.evil.com")? {
        println!("Matched pattern: {:?}", result);
    }
    
    Ok(())
}
```

You can run this with `cargo run`.

## Going further

For more details on using Matchy, check out the [Matchy Guide](../guide/index.md).

[def-database]: ../appendix/glossary.md#database '"database" (glossary entry)'
