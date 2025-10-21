# Building Your First Database

This tutorial walks you through building a complete threat intelligence database from scratch.

## What We'll Build

A database containing:
- Malicious IP addresses with threat scores
- CIDR ranges for known botnets
- Domain patterns for phishing sites  
- Exact domains on a blocklist

## Step 1: Create the Builder

```rust
use matchy::{DatabaseBuilder, MatchMode, DataValue};
use std::collections::HashMap;

let mut builder = DatabaseBuilder::new(MatchMode::CaseInsensitive);
```

The `MatchMode` determines how patterns are matched:
- `CaseSensitive` - "Evil.com" ≠ "evil.com"
- `CaseInsensitive` - "Evil.com" = "evil.com" (recommended for domains)

## Step 2: Add IP Addresses

Add individual IPs with rich metadata:

```rust
let mut threat_data = HashMap::new();
threat_data.insert("threat_level".to_string(), DataValue::String("critical".to_string()));
threat_data.insert("score".to_string(), DataValue::Uint32(95));
threat_data.insert("first_seen".to_string(), DataValue::String("2024-01-15".to_string()));
threat_data.insert("category".to_string(), DataValue::String("c2_server".to_string()));

builder.add_entry("192.0.2.1", threat_data)?;
```

## Step 3: Add CIDR Ranges

CIDR ranges match all IPs within the range:

```rust
let mut botnet_data = HashMap::new();
botnet_data.insert("network".to_string(), DataValue::String("mirai_botnet".to_string()));
botnet_data.insert("threat_level".to_string(), DataValue::String("high".to_string()));

builder.add_entry("203.0.113.0/24", botnet_data)?;
```

## Step 4: Add Glob Patterns

Patterns use wildcards to match multiple domains:

```rust
// Match any subdomain of evil.com
let mut pattern_data = HashMap::new();
pattern_data.insert("category".to_string(), DataValue::String("phishing".to_string()));
pattern_data.insert("threat_level".to_string(), DataValue::String("high".to_string()));

builder.add_entry("*.evil.com", pattern_data)?;

// Match specific patterns
let mut malware_data = HashMap::new();
malware_data.insert("category".to_string(), DataValue::String("malware_download".to_string()));

builder.add_entry("http://*/admin/config.php", malware_data)?;
```

## Step 5: Add Exact Strings

For known exact matches (no wildcards):

```rust
let mut blocklist_data = HashMap::new();
blocklist_data.insert("reason".to_string(), DataValue::String("confirmed_malware".to_string()));
blocklist_data.insert("blocked_date".to_string(), DataValue::String("2024-10-01".to_string()));

builder.add_entry("malicious-site.example", blocklist_data)?;
```

## Step 6: Build and Save

```rust
// Build the database (returns bytes)
let database_bytes = builder.build()?;

// Save to file
std::fs::write("threats.mxy", &database_bytes)?;

println!("✅ Database built: {} bytes", database_bytes.len());
```

## Step 7: Query the Database

```rust
use matchy::{Database, QueryResult};

// Open the database (memory-mapped, loads in <1ms)
let db = Database::open("threats.mxy")?;

// Query IP address
match db.lookup("192.0.2.1")? {
    Some(QueryResult::Ip { data, prefix_len }) => {
        println!("Found IP: {:?}", data);
        println!("Matched CIDR: /{}", prefix_len);
    }
    _ => println!("Not found"),
}

// Query domain (matches pattern *.evil.com)
match db.lookup("phishing.evil.com")? {
    Some(QueryResult::Pattern { pattern_ids, data }) => {
        println!("Matched {} patterns", pattern_ids.len());
        for (i, threat_data) in data.iter().enumerate() {
            if let Some(d) = threat_data {
                println!("Pattern {}: {:?}", pattern_ids[i], d);
            }
        }
    }
    _ => println!("No match"),
}
```

## Pattern Types

Matchy automatically detects entry types:

| Entry | Type | Example |
|-------|------|---------|
| `192.0.2.1` | IP Address | Single host |
| `192.0.2.0/24` | CIDR Range | Network block |
| `*.evil.com` | Glob Pattern | Wildcard domain |
| `evil.com` | Exact String | Literal match |

## Performance Tips

1. **Build once, query many** - Building is one-time, queries are microseconds
2. **Use CIDR ranges** - More efficient than individual IPs
3. **Prefer suffix patterns** - `*.evil.com` is faster than `evil-*`
4. **Exact strings are fastest** - O(1) hash lookup

## Next Steps

- [Rust API Reference](reference/rust-api.md) - Complete API documentation
- [Data Types](guide/data-types.md) - All supported data types
- [Performance Guide](guide/performance.md) - Optimization techniques
