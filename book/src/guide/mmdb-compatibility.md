# MMDB Compatibility

Matchy reads version 2 [MaxMind MMDB][mmdb] files that use the standard data
types and fit Matchy's documented decoder resource limits. It extends the
format with string and pattern indexes and an optional nonstandard timestamp
type.

## Reading MMDB Files

MaxMind's GeoIP databases use the MMDB format. Matchy can read these files directly:

```rust
use matchy::{Database, QueryResult};

// Open a MaxMind GeoLite2 database
let db = Database::from("GeoLite2-City.mmdb").open()?;

// Query an IP address
match db.lookup("8.8.8.8")? {
    Some(result @ QueryResult::Ip { .. }) => {
        println!("Location data: {:?}", result);
    }
    Some(QueryResult::NotFound) => println!("IP not found"),
    Some(QueryResult::Pattern { .. }) => unreachable!("IP text routes to the IP tree"),
    None => println!("This database has no IP index"),
}
```

The same works from the CLI:

```console
$ matchy query GeoLite2-City.mmdb 8.8.8.8
Found: IP address 8.8.8.8/32
  country: "US"
  city: "Mountain View"
  coordinates: [37.386, -122.0838]
```

## MMDB Format Overview

MMDB files contain:
- **IP tree** - Binary trie mapping IP addresses to data
- **Data section** - Structured data storage (strings, numbers, maps, arrays)
- **Metadata** - Database information (build time, version, etc.)

This is a compact, binary format designed for fast IP address lookups.

## Matchy Extensions

Matchy extends MMDB with additional sections:

### Standard MMDB
```
┌──────────────────────────────┐
│  IP Tree                   │  IPv4 and IPv6 lookup
├──────────────────────────────┤
│  Data Section              │  Structured data
├──────────────────────────────┤
│  Metadata                  │  Database info
└──────────────────────────────┘
```

### Matchy Extended Format
```
┌─────────────────────────────────────────────────┐
│  IP Tree                   │  IPv4 and IPv6 (MMDB compatible)
├─────────────────────────────────────────────────┤
│  Data Section              │  MMDB values + optional Matchy type
├─────────────────────────────────────────────────┤
│  Hash Table                │  Exact string matches (Matchy extension)
├─────────────────────────────────────────────────┤
│  AC Automaton              │  Pattern matching (Matchy extension)
├─────────────────────────────────────────────────┤
│  Metadata                  │  Database info
└─────────────────────────────────────────────────┘
```

The IP tree and standard data types use the MMDB encoding. Matchy's extension
sections are unreferenced by standard MMDB tree records and can be ignored by
standard readers. A value containing Matchy's `Timestamp` type is different:
it uses nonstandard extended type 128 and cannot be decoded by a standard MMDB
reader.

## Compatibility Guarantees

**Reading MMDB files**:
- ✅ Standard MMDB v2 data types are supported
- ✅ Current GeoIP, ASN, and similar databases are supported when they fit the decoder limits
- ⚠️ Pointer depth, nesting, decoded work, and owned allocation are bounded to reject resource-exhaustion inputs

**Writing Matchy databases**:
- ✅ Standard MMDB readers can read IP records whose values use only standard MMDB types
- ⚠️ String and pattern extensions are ignored by standard readers
- ⚠️ Matchy `Timestamp` values are not understood by standard MMDB readers
- ✅ Matchy databases work with Matchy tools (CLI and APIs)

When `DataValue` is deserialized from JSON, an RFC 3339 string is converted to
Matchy's compact `Timestamp` type. If a database must remain readable by
standard MMDB tools, construct `DataValue::String` explicitly for timestamp
text instead of relying on generic `DataValue` deserialization.

## Practical Examples

### Using GeoIP Databases

MaxMind provides free GeoLite2 databases. Download and use them directly:

```console
$ wget https://example.com/GeoLite2-City.mmdb
$ matchy query GeoLite2-City.mmdb 1.1.1.1
```

From Rust:

```rust
let db = Database::from("GeoLite2-City.mmdb").open()?;

if let Some(result @ QueryResult::Ip { .. }) = db.lookup("1.1.1.1")? {
    // Access location data
    println!("Result: {:?}", result);
}
```

### Extending MMDB Files

You can build a database that combines IP data using standard MMDB value types
with patterns stored in Matchy extension sections:

```rust
use matchy::{DatabaseBuilder, MatchMode, DataValue};
use std::collections::HashMap;

let mut builder = DatabaseBuilder::new(MatchMode::CaseInsensitive);

// Add IP data using a standard MMDB string value
let mut ip_data = HashMap::new();
ip_data.insert("country".to_string(), DataValue::String("US".to_string()));
builder.add_entry("8.8.8.8", ip_data)?;

// Add pattern data (Matchy extension)
let mut pattern_data = HashMap::new();
pattern_data.insert("category".to_string(), DataValue::String("search".to_string()));
builder.add_entry("*.google.com", pattern_data)?;

let db_bytes = builder.build()?;
std::fs::write("extended.mxy", &db_bytes)?;
```

Standard MMDB readers can decode this example's IP data because it uses only a
standard string value. Matchy tools also see the pattern data.

## File Format Details

MMDB files are binary and consist of:

1. **IP Tree**: Binary trie where each node represents a network bit
2. **Data Section**: Compact binary encoding of values
3. **Metadata**: JSON with database information

Matchy preserves this structure and adds:

4. **Hash Table**: For O(1) exact string lookups
5. **Aho-Corasick Automaton**: For simultaneous pattern matching

See [Binary Format Specification](../reference/binary-format.md) for complete details.

## Version Compatibility

Matchy supports:
- MMDB format version 2.x (current standard)
- IPv4 and IPv6 address families
- All standard MMDB data types (strings, integers, floats, maps, arrays, bytes, and pointers)
- Bounded decoding: pointer depth 32, total nesting 64, at most one million decoded values, and at most 64 MiB of estimated owned allocation per decode budget; database pattern queries share one budget across all matched values
- Matchy extended type 128 (`Timestamp`) for Matchy-only data

When building databases, Matchy uses MMDB format 2.0 for the IP tree and data section.

## Performance Comparison

MMDB lookup performance depends on the database, data values, hardware, and
cache state. Matchy and standard MMDB readers share the same broad design:

- Binary tree traversal (O(log n) worst case, O(32) for IPv4, O(128) for IPv6)
- Memory mapping without whole-file deserialization
- Direct tree access followed by decoding only the selected data value

Use the built-in benchmark command on the target workload instead of treating
historical throughput numbers as a current guarantee.

## Migration from libmaxminddb

If you're using MaxMind's C library (`libmaxminddb`), Matchy provides similar functionality:

**libmaxminddb**:
```c
MMDB_s mmdb;
MMDB_open("GeoLite2-City.mmdb", 0, &mmdb);

int gai_error, mmdb_error;
MMDB_lookup_result_s result = 
    MMDB_lookup_string(&mmdb, "8.8.8.8", &gai_error, &mmdb_error);
```

**Matchy**:
```c
matchy_t *db = matchy_open("GeoLite2-City.mmdb");
matchy_result_t result = matchy_query(db, "8.8.8.8");
```

Both load the database via memory mapping and provide similar query performance.

## Next Steps

- [Binary Format Specification](../reference/binary-format.md) - Detailed format docs
- [Performance Considerations](performance.md) - Optimization strategies
- [Entry Types](entry-types.md) - Understanding all entry types

[mmdb]: https://maxmind.github.io/MaxMind-DB/
