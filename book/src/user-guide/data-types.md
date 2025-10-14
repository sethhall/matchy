# Data Types

Matchy uses the MaxMind DB (MMDB) data type system to store rich metadata with IP addresses, strings, and patterns.

## Supported Types

### Primitive Types

#### String
UTF-8 encoded text.

```rust
let name = DataValue::String("example.com".to_string());
```

#### Boolean
```rust
let is_blocked = DataValue::Bool(true);
```

#### Bytes
Raw byte arrays.

```rust
let hash = DataValue::Bytes(vec![0x12, 0x34]);
```

### Numeric Types

| Type | Range | Use Case |
|------|-------|----------|
| **Uint16** | 0 to 65,535 | Ports, small counts |
| **Uint32** | 0 to 4.3 billion | Large counts, timestamps |
| **Uint64** | 0 to 18 quintillion | Very large values |
| **Uint128** | Huge numbers | IPv6 addresses |
| **Int32** | -2.1B to 2.1B | Signed values |
| **Float** | 32-bit IEEE 754 | Approximate values |
| **Double** | 64-bit IEEE 754 | Precise decimals |

### Container Types

#### Array
Ordered list of values.

```rust
let tags = DataValue::Array(vec![
    DataValue::String("malware".to_string()),
    DataValue::String("botnet".to_string()),
]);
```

#### Map
Key-value pairs (keys must be strings).

```rust
use std::collections::HashMap;

let mut data = HashMap::new();
data.insert("country".to_string(), DataValue::String("US".to_string()));
data.insert("latitude".to_string(), DataValue::Double(37.774));
```

## Type Conversion

### From CSV

```csv
entry,port,active,score
1.2.3.4,443,true,95
```

Becomes:
- `port` → `Uint16(443)`
- `active` → `Bool(true)`  
- `score` → `Uint16(95)`

### From JSON

```json
{
  "key": "1.2.3.4",
  "data": {
    "threat_level": "high",
    "confidence": 0.95,
    "tags": ["malware", "botnet"]
  }
}
```

Maps naturally to DataValue types.

## Examples

### GeoIP Data

```json
{
  "country": "US",
  "city": "Mountain View",
  "latitude": 37.386,
  "longitude": -122.084
}
```

### Threat Intelligence

```json
{
  "threat_level": "critical",
  "category": "phishing",
  "confidence": 0.95,
  "tags": ["credential-theft", "active"],
  "attribution": {
    "actor": "APT29",
    "country": "RU"
  }
}
```

## See Also

- [Database Builder](database-builder.md) - Building databases with data
- [Querying Databases](querying.md) - Retrieving data
- [Rust API](rust-api.md) - Using DataValue in Rust
