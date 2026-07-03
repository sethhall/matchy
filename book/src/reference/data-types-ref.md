# Data Types Reference

Matchy databases store arbitrary data with each entry using the `DataValue` type system.

## Overview

`DataValue` is a Rust enum supporting these types:

- **Bool**: Boolean values
- **Uint16**: 16-bit unsigned integers
- **Uint32**: 32-bit unsigned integers
- **Uint64**: 64-bit unsigned integers
- **Uint128**: 128-bit unsigned integers
- **Int32**: 32-bit signed integers
- **Float**: 32-bit floating point
- **Double**: 64-bit floating point
- **String**: UTF-8 text
- **Bytes**: Arbitrary binary data
- **Array**: Ordered list of values
- **Map**: Key-value mappings
- **Timestamp**: Unix epoch seconds (compact storage for ISO 8601 timestamps)

See [Data Types](../guide/data-types.md) for conceptual overview.

## DataValue Enum

```rust
pub enum DataValue {
    Pointer(u32),
    String(String),
    Double(f64),
    Bytes(Vec<u8>),
    Uint16(u16),
    Uint32(u32),
    Map(HashMap<String, DataValue>),
    Int32(i32),
    Uint64(u64),
    Uint128(u128),
    Array(Vec<DataValue>),
    Bool(bool),
    Float(f32),
    Timestamp(i64),  // Unix epoch seconds
}
```

## Creating Values

### Direct Construction

```rust
use matchy::DataValue;

let bool_val = DataValue::Bool(true);
let int_val = DataValue::Uint32(42);
let str_val = DataValue::String("hello".to_string());
```

### From JSON

```rust
let val: DataValue = serde_json::from_value(serde_json::json!(42))?;
let val: DataValue = serde_json::from_value(serde_json::json!("text"))?;
let val: DataValue = serde_json::from_value(serde_json::json!(true))?;
```

## Working with Maps

Maps are the most common data structure:

```rust
use std::collections::HashMap;
use matchy::DataValue;

let mut data = HashMap::new();
data.insert("country".to_string(), DataValue::String("US".to_string()));
data.insert("asn".to_string(), DataValue::Uint32(15169));
data.insert("lat".to_string(), DataValue::Double(37.751));
data.insert("lon".to_string(), DataValue::Double(-97.822));
```

## Working with Arrays

```rust
let tags = DataValue::Array(vec![
    DataValue::String("cdn".to_string()),
    DataValue::String("cloud".to_string()),
]);

data.insert("tags".to_string(), tags);
```

## Working with Timestamps

Timestamps store Unix epoch seconds compactly (8 bytes vs 27-byte ISO 8601 strings):

```rust
use matchy::DataValue;

let first_seen = DataValue::Timestamp(1727891071);
data.insert("first_seen".to_string(), first_seen);
```

ISO 8601 strings in JSON input are automatically parsed into Timestamps during deserialization:

```json
{
  "entry": "1.2.3.4",
  "first_seen": "2025-10-02T18:44:31Z"
}
```

When serialized back to JSON, Timestamps render as ISO 8601 strings for readability.

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
    DataValue::Uint32(n) => println!("Number: {}", n),
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
        DataValue::Uint32(n) => Some(*n),
        _ => None,
    }
}
```

## Complete Example

```rust
use matchy::{DatabaseBuilder, DataValue, MatchMode};
use std::collections::HashMap;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut builder = DatabaseBuilder::new(MatchMode::CaseInsensitive);
    
    // IP with rich data
    let mut ip_data = HashMap::new();
    ip_data.insert("country".to_string(), DataValue::String("US".to_string()));
    ip_data.insert("asn".to_string(), DataValue::Uint32(15169));
    ip_data.insert("tags".to_string(), DataValue::Array(vec![
        DataValue::String("datacenter".to_string()),
        DataValue::String("cloud".to_string()),
    ]));
    
    builder.add_entry("8.8.8.8", ip_data)?;
    
    // Pattern with metadata
    let mut pattern_data = HashMap::new();
    pattern_data.insert("category".to_string(), DataValue::String("search".to_string()));
    pattern_data.insert("priority".to_string(), DataValue::Uint16(100));
    
    builder.add_entry("*.google.com", pattern_data)?;
    
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
| Uint16 | uint16 | 2 bytes |
| Uint32 | uint32 | 4 bytes |
| Uint64 | uint64 | 8 bytes |
| Uint128 | uint128 | 16 bytes |
| Int32 | int32 | 4 bytes |
| Float | float | IEEE 754 |
| Double | double | IEEE 754 |
| String | utf8_string | Length-prefixed |
| Bytes | bytes | Length-prefixed |
| Array | array | Recursive |
| Map | map | Key-value pairs |
| Timestamp | ext 128 | 8 bytes, Matchy extension |

See [Binary Format](binary-format.md) for encoding details.

## Size Limits

- **Strings**: Up to about 16.8 MB per encoded string
- **Bytes**: Up to about 16.8 MB per encoded byte array
- **Arrays**: Up to about 16.8 million encoded elements
- **Maps**: Up to about 16.8 million encoded key-value pairs
- **Nesting**: Validation rejects total nesting deeper than 64 levels

## Performance

Data types have different serialization costs:

| Type | Cost | Notes |
|------|------|-------|
| Bool, integers | O(1) | Fixed size |
| Float, Double | O(1) | Fixed size |
| String | O(n) | Length-dependent |
| Bytes | O(n) | Length-dependent |
| Array | O(n × m) | n = length, m = element cost |
| Map | O(n × m) | n = entries, m = value cost |

Prefer smaller types when possible:
- Use Uint16 instead of Uint32 if values fit
- Use Int32 instead of Double for integers
- Avoid deep nesting

## Serialization Example

```rust
use matchy::{Database, QueryResult, DataValue};

let db = Database::from("database.mxy").open()?;

if let Some(QueryResult::Ip { data: DataValue::Map(data), .. }) = db.lookup("8.8.8.8")? {
    // Extract specific fields
    if let Some(DataValue::String(country)) = data.get("country") {
        println!("Country: {}", country);
    }
    
    if let Some(DataValue::Uint32(asn)) = data.get("asn") {
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
        DataValue::Uint32(n) => json!(n),
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
