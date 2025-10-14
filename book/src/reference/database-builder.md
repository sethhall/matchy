# DatabaseBuilder

`DatabaseBuilder` constructs new databases. See [Creating a New Database](../getting-started/api-rust-first.md)
for a tutorial.

## Creating a Builder

```rust
use matchy::{DatabaseBuilder, MatchMode};

let builder = DatabaseBuilder::new(MatchMode::CaseInsensitive);
```

### Match Modes

`MatchMode` controls string matching behavior:

- `MatchMode::CaseInsensitive` - "ABC" equals "abc" (recommended for domains)
- `MatchMode::CaseSensitive` - "ABC" does not equal "abc"

```rust
// Case-insensitive (recommended)
let builder = DatabaseBuilder::new(MatchMode::CaseInsensitive);

// Case-sensitive
let builder = DatabaseBuilder::new(MatchMode::CaseSensitive);
```

## Adding Entries

### Method Signature

```rust
pub fn add_entry<S: AsRef<str>>(
    &mut self,
    key: S,
    data: HashMap<String, DataValue>
) -> Result<(), MatchyError>
```

### Examples

**IP Address:**
```rust
let mut data = HashMap::new();
data.insert("country".to_string(), DataValue::String("US".to_string()));
builder.add_entry("192.0.2.1", data)?;
```

**CIDR Range:**
```rust
let mut data = HashMap::new();
data.insert("org".to_string(), DataValue::String("Example Inc".to_string()));
builder.add_entry("10.0.0.0/8", data)?;
```

**Pattern:**
```rust
let mut data = HashMap::new();
data.insert("category".to_string(), DataValue::String("search".to_string()));
builder.add_entry("*.google.com", data)?;
```

**Exact String:**
```rust
let mut data = HashMap::new();
data.insert("safe".to_string(), DataValue::Bool(true));
builder.add_entry("example.com", data)?;
```

## Building the Database

### Method Signature

```rust
pub fn build(self) -> Result<Vec<u8>, MatchyError>
```

### Usage

```rust
let db_bytes = builder.build()?;
std::fs::write("database.mxy", &db_bytes)?;
```

The `build()` method:
- Consumes the builder (takes ownership)
- Returns `Vec<u8>` containing the binary database
- Can fail if entries are invalid or memory is exhausted

## Complete Example

```rust
use matchy::{DatabaseBuilder, MatchMode, DataValue};
use std::collections::HashMap;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut builder = DatabaseBuilder::new(MatchMode::CaseInsensitive);
    
    // Add various entry types
    let mut ip_data = HashMap::new();
    ip_data.insert("type".to_string(), DataValue::String("ip".to_string()));
    builder.add_entry("192.0.2.1", ip_data)?;
    
    let mut cidr_data = HashMap::new();
    cidr_data.insert("type".to_string(), DataValue::String("cidr".to_string()));
    builder.add_entry("10.0.0.0/8", cidr_data)?;
    
    let mut pattern_data = HashMap::new();
    pattern_data.insert("type".to_string(), DataValue::String("pattern".to_string()));
    builder.add_entry("*.example.com", pattern_data)?;
    
    // Build and save
    let db_bytes = builder.build()?;
    std::fs::write("mixed.mxy", &db_bytes)?;
    
    println!("Database size: {} bytes", db_bytes.len());
    Ok(())
}
```

## Entry Validation

The builder validates entries when added:

**Invalid IP addresses:**
```rust
builder.add_entry("256.256.256.256", data)?; // Error: InvalidEntry
```

**Invalid CIDR:**
```rust
builder.add_entry("10.0.0.0/33", data)?; // Error: InvalidEntry (IPv4 max is /32)
```

**Invalid pattern:**
```rust
builder.add_entry("[unclosed", data)?; // Error: PatternError
```

## Building Large Databases

For large databases, add entries in a loop:

```rust
let mut builder = DatabaseBuilder::new(MatchMode::CaseInsensitive);

for entry in large_dataset {
    let mut data = HashMap::new();
    data.insert("value".to_string(), DataValue::from_json(&entry.data)?);
    builder.add_entry(&entry.key, data)?;
}

let db_bytes = builder.build()?;
```

Performance: ~100,000 IP/string entries per second, ~10,000 patterns per second.

## Error Handling

```rust
match builder.add_entry(key, data) {
    Ok(()) => println!("Added entry"),
    Err(MatchyError::InvalidEntry { key, reason }) => {
        eprintln!("Invalid entry {}: {}", key, reason);
    }
    Err(MatchyError::PatternError { pattern, reason }) => {
        eprintln!("Invalid pattern {}: {}", pattern, reason);
    }
    Err(e) => eprintln!("Other error: {}", e),
}
```

## See Also

- [Database and Querying](database-query.md) - Querying databases
- [Data Types Reference](data-types-ref.md) - DataValue types
- [First Database with Rust](../getting-started/api-rust-first.md) - Tutorial
