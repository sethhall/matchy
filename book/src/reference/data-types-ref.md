# Data Types Reference

Matchy databases store arbitrary data with each entry using the `DataValue` type system.

## Overview

`DataValue` is a Rust enum supporting these types:

- **Bool**: Boolean values
- **U16**: 16-bit unsigned integers
- **U32**: 32-bit unsigned integers
- **U64**: 64-bit unsigned integers
- **I32**: 32-bit signed integers
- **F32**: 32-bit floating point
- **F64**: 64-bit floating point
- **String**: UTF-8 text
- **Bytes**: Arbitrary binary data
- **Array**: Ordered list of values
- **Map**: Key-value mappings

See [Data Types](../guide/data-types.md) for conceptual overview.

## DataValue Enum

```rust
pub enum DataValue {
    Bool(bool),
    U16(u16),
    U32(u32),
    U64(u64),
    I32(i32),
    F32(f32),
    F64(f64),
    String(String),
    Bytes(Vec<u8>),
    Array(Vec<DataValue>),
    Map(HashMap<String, DataValue>),
}
```

## Creating Values

### Direct Construction

```rust
use matchy::DataValue;

let bool_val = DataValue::Bool(true);
let int_val = DataValue::U32(42);
let str_val = DataValue::String("hello".to_string());
```

### Using From/Into

```rust
let val: DataValue = 42u32.into();
let val: DataValue = "text".to_string().into();
let val: DataValue = true.into();
```

## Working with Maps

Maps are the most common data structure:

```rust
use std::collections::HashMap;
use matchy::DataValue;

let mut data = HashMap::new();
data.insert("country".to_string(), DataValue::String("US".to_string()));
data.insert("asn".to_string(), DataValue::U32(15169));
data.insert("lat".to_string(), DataValue::F64(37.751));
data.insert("lon".to_string(), DataValue::F64(-97.822));
```

## Working with Arrays

```rust
let tags = DataValue::Array(vec![
    DataValue::String("cdn".to_string()),
    DataValue::String("cloud".to_string()),
]);

data.insert("tags".to_string(), tags);
```

## Nested Structures

```rust
let mut location = HashMap::new();
location.insert("city".to_string(), DataValue::String("Mountain View".to_string()));
location.insert("country".to_string(), DataValue::String("US".to_string()));

data.insert("location".to_string(), DataValue::Map(location));
```

## Type Conversion

### Extracting Values

```rust
match value {
    DataValue::String(s) => println!("String: {}", s),
    DataValue::U32(n) => println!("Number: {}", n),
    DataValue::Map(m) => {
        for (k, v) in m {
            println!("{}: {:?}", k, v);
        }
    }
    _ => println!("Other type"),
}
```

### Helper Functions

```rust
fn get_string(val: &DataValue) -> Option<&str> {
    match val {
        DataValue::String(s) => Some(s),
        _ => None,
    }
}

fn get_u32(val: &DataValue) -> Option<u32> {
    match val {
        DataValue::U32(n) => Some(*n),
        _ => None,
    }
}
```

## Complete Example

```rust
use matchy::{DatabaseBuilder, DataValue};
use std::collections::HashMap;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut builder = DatabaseBuilder::new();
    
    // IP with rich data
    let mut ip_data = HashMap::new();
    ip_data.insert("country".to_string(), DataValue::String("US".to_string()));
    ip_data.insert("asn".to_string(), DataValue::U32(15169));
    ip_data.insert("tags".to_string(), DataValue::Array(vec![
        DataValue::String("datacenter".to_string()),
        DataValue::String("cloud".to_string()),
    ]));
    
    builder.add_ip_entry("8.8.8.8/32", Some(ip_data))?;
    
    // Pattern with metadata
    let mut pattern_data = HashMap::new();
    pattern_data.insert("category".to_string(), DataValue::String("search".to_string()));
    pattern_data.insert("priority".to_string(), DataValue::U16(100));
    
    builder.add_pattern_entry("*.google.com", Some(pattern_data))?;
    
    let db_bytes = builder.build()?;
    std::fs::write("database.mxy", &db_bytes)?;
    
    Ok(())
}
```

## Binary Format

DataValue types are serialized to the MMDB binary format:

| DataValue | MMDB Type | Notes |
|-----------|-----------|-------|
| Bool | boolean | 1 bit |
| U16 | uint16 | 2 bytes |
| U32 | uint32 | 4 bytes |
| U64 | uint64 | 8 bytes |
| I32 | int32 | 4 bytes |
| F32 | float | IEEE 754 |
| F64 | double | IEEE 754 |
| String | utf8_string | Length-prefixed |
| Bytes | bytes | Length-prefixed |
| Array | array | Recursive |
| Map | map | Key-value pairs |

See [Binary Format](binary-format.md) for encoding details.

## Size Limits

- **Strings**: Up to 16 MB per string
- **Bytes**: Up to 16 MB per byte array
- **Arrays**: Up to 65,536 elements
- **Maps**: Up to 65,536 key-value pairs
- **Nesting**: Up to 64 levels deep

## Performance

Data types have different serialization costs:

| Type | Cost | Notes |
|------|------|-------|
| Bool, integers | O(1) | Fixed size |
| F32, F64 | O(1) | Fixed size |
| String | O(n) | Length-dependent |
| Bytes | O(n) | Length-dependent |
| Array | O(n × m) | n = length, m = element cost |
| Map | O(n × m) | n = entries, m = value cost |

Prefer smaller types when possible:
- Use U16 instead of U32 if values fit
- Use I32 instead of F64 for integers
- Avoid deep nesting

## Serialization Example

```rust
use matchy::{Database, QueryResult, DataValue};

let db = Database::open("database.mxy")?;

if let Some(QueryResult::Ip { data: Some(data), .. }) = db.lookup("8.8.8.8")? {
    // Extract specific fields
    if let Some(DataValue::String(country)) = data.get("country") {
        println!("Country: {}", country);
    }
    
    if let Some(DataValue::U32(asn)) = data.get("asn") {
        println!("ASN: {}", asn);
    }
    
    if let Some(DataValue::Array(tags)) = data.get("tags") {
        println!("Tags:");
        for tag in tags {
            if let DataValue::String(s) = tag {
                println!("  - {}", s);
            }
        }
    }
}
```

## JSON Conversion

DataValue maps naturally to JSON:

```rust
use serde_json::json;

// DataValue to JSON (conceptual)
fn to_json(val: &DataValue) -> serde_json::Value {
    match val {
        DataValue::Bool(b) => json!(b),
        DataValue::U32(n) => json!(n),
        DataValue::String(s) => json!(s),
        DataValue::Array(arr) => {
            json!(arr.iter().map(to_json).collect::<Vec<_>>())
        }
        DataValue::Map(map) => {
            let obj: serde_json::Map<String, serde_json::Value> = 
                map.iter().map(|(k, v)| (k.clone(), to_json(v))).collect();
            json!(obj)
        }
        _ => json!(null),
    }
}
```

## See Also

- [Data Types Guide](../guide/data-types.md) - Conceptual overview
- [DatabaseBuilder](database-builder.md) - Adding data
- [Database Querying](database-query.md) - Reading data
- [Binary Format](binary-format.md) - Serialization details
