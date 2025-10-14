# Data Types and Values

Matchy stores structured [*data values*][def-data-value] with each entry. This chapter explains the supported data types.

## Supported Types

### String
Text values of any length.

### Numbers
- Unsigned integers (uint16, uint32, uint64, uint128)
- Signed integers (int32)  
- Floating point (float, double)

### Boolean
True or false values.

### Arrays
Ordered lists of values (can contain mixed types).

### Maps
Key-value pairs (like JSON objects or hash maps).

### Null
Explicit null/missing value.

## Tool-Specific Representations

How you specify data types depends on your tool:

**CLI**: Use JSON notation in CSV/JSON files
```csv
key,data
192.0.2.1,"{""threat"": ""high"", ""score"": 95}"
```

**Rust API**: Use the `DataValue` enum
```rust
use matchy::DataValue;
data.insert("score".to_string(), DataValue::Uint32(95));
```

**C API**: Use JSON strings
```c
matchy_builder_add(builder, "192.0.2.1", "{\"score\": 95}");
```

See tool-specific docs for complete details:
- [Rust API: DataValue](../reference/data-types-ref.md)
- [C API: JSON format](../reference/c-building.md)
- [CLI: Input formats](../reference/input-formats.md)

## Nested Data

Maps and arrays can be nested to arbitrary depth:

```json
{
  "threat": {
    "level": "high",
    "categories": ["malware", "c2"],
    "metadata": {
      "first_seen": "2024-01-15",
      "confidence": 0.95
    }
  }
}
```

## Size Limits

Data is stored in compact binary format. Practical limits:
- Strings: Megabytes per string
- Arrays: Thousands of elements
- Maps: Thousands of keys
- Nesting: Dozens of levels deep

Most use cases store kilobytes per entry.

## Next Steps

- [Database Concepts](database-concepts.md) - How data is stored
- [Performance Considerations](performance.md) - Data size impact

[def-data-value]: ../appendix/glossary.md#data-value '"data value" (glossary entry)'
