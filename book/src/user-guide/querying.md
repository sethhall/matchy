# Querying Databases

Query Matchy databases for IP addresses, strings, and glob patterns.

## Opening a Database

```rust
use matchy::Database;

// Open database (validates UTF-8)
let db = Database::open("threats.mxy")?;

// Open trusted database (skip UTF-8 validation - faster)
let db = Database::open_trusted("my-database.mxy")?;
```

## Query Methods

### Unified Lookup

Auto-detects IP vs string queries:

```rust
use matchy::QueryResult;

// Query an IP
let result = db.lookup("1.2.3.4")?;

// Query a string/domain
let result = db.lookup("evil.example.com")?;
```

### IP Lookup

Direct IP address queries:

```rust
use std::net::{IpAddr, Ipv4Addr};

let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
let result = db.lookup_ip(ip)?;
```

## Query Results

### IP Match

```rust
match result {
    Some(QueryResult::Ip { data, prefix_len }) => {
        println!("Found IP data: {:?}", data);
        println!("CIDR prefix: /{}", prefix_len);
    }
    _ => println!("No match"),
}
```

### Pattern Match

```rust
match result {
    Some(QueryResult::Pattern { pattern_ids, data }) => {
        println!("Matched {} patterns", pattern_ids.len());
        for (i, pattern_data) in data.iter().enumerate() {
            if let Some(d) = pattern_data {
                println!("Pattern {}: {:?}", pattern_ids[i], d);
            }
        }
    }
    _ => println!("No match"),
}
```

### Not Found

```rust
match result {
    Some(QueryResult::NotFound) | None => {
        println!("No match found");
    }
    _ => {}
}
```

## Extracting Data

### Maps

```rust
use matchy::DataValue;

if let Some(QueryResult::Ip { data, .. }) = result {
    if let DataValue::Map(map) = data {
        if let Some(DataValue::String(country)) = map.get("country") {
            println!("Country: {}", country);
        }
    }
}
```

### Arrays

```rust
if let DataValue::Array(tags) = data {
    for tag in tags {
        if let DataValue::String(s) = tag {
            println!("Tag: {}", s);
        }
    }
}
```

## Database Info

```rust
// Check capabilities
println!("Has IPs: {}", db.has_ip_data());
println!("Has literals: {}", db.has_literal_data());
println!("Has globs: {}", db.has_glob_data());

// Get counts
println!("IP count: {}", db.ip_count());
println!("Literal count: {}", db.literal_count());
println!("Glob count: {}", db.glob_count());

// Get metadata
if let Some(metadata) = db.metadata() {
    println!("Metadata: {:?}", metadata);
}
```

## Complete Example

```rust
use matchy::{Database, QueryResult, DataValue};
use std::collections::HashMap;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Open database
    let db = Database::open("threats.mxy")?;
    
    // Query IP
    let query = "1.2.3.4";
    match db.lookup(query)? {
        Some(QueryResult::Ip { data, prefix_len }) => {
            println!("IP Match!");
            println!("CIDR: {}/{}", query, prefix_len);
            
            if let DataValue::Map(map) = data {
                if let Some(DataValue::String(level)) = map.get("threat_level") {
                    println!("Threat Level: {}", level);
                }
            }
        }
        Some(QueryResult::Pattern { pattern_ids, data }) => {
            println!("Pattern Match!");
            println!("Matched {} patterns", pattern_ids.len());
            
            for threat_data in data.iter().flatten() {
                println!("Data: {:?}", threat_data);
            }
        }
        Some(QueryResult::NotFound) | None => {
            println!("No threat found");
        }
    }
    
    Ok(())
}
```

## Performance Tips

1. **Reuse Database instances** - opening is fast but reusing is faster
2. **Use `lookup_ip` for IP queries** - slightly faster than unified lookup
3. **Use trusted mode** for databases you control (~15-20% faster)
4. **Batch queries** when checking many entries

## See Also

- [Data Types](data-types.md) - Understanding returned data
- [Database Builder](database-builder.md) - Building databases
- [Rust API](rust-api.md) - Complete API reference
