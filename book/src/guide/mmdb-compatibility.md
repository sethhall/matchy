# MMDB Compatibility

Matchy can read standard [MaxMind MMDB][mmdb] files and extends the format to support
string and pattern matching.

## Reading MMDB Files

MaxMind's GeoIP databases use the MMDB format. Matchy can read these files directly:

```rust
use matchy::Database;

// Open a MaxMind GeoLite2 database
let db = Database::open("GeoLite2-City.mmdb")?;

// Query an IP address
match db.lookup("8.8.8.8")? {
    Some(result) => {
        println!("Location data: {:?}", result);
    }
    None => println!("IP not found"),
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
│  Data Section              │  Structured data (MMDB compatible)
├─────────────────────────────────────────────────┤
│  Hash Table                │  Exact string matches (Matchy extension)
├─────────────────────────────────────────────────┤
│  AC Automaton              │  Pattern matching (Matchy extension)
├─────────────────────────────────────────────────┤
│  Metadata                  │  Database info
└─────────────────────────────────────────────────┘
```

The IP tree and data section remain fully compatible with standard MMDB readers.

## Compatibility Guarantees

**Reading MMDB files**:
- ✅ Matchy can read any standard MMDB file
- ✅ IP lookups work exactly as expected
- ✅ GeoIP, ASN, and other MaxMind databases supported

**Writing Matchy databases**:
- ✅ Standard MMDB readers can read the IP portion
- ⚠️ String and pattern extensions are ignored by standard readers
- ✅ Matchy databases work with Matchy tools (CLI and APIs)

## Practical Examples

### Using GeoIP Databases

MaxMind provides free GeoLite2 databases. Download and use them directly:

```console
$ wget https://example.com/GeoLite2-City.mmdb
$ matchy query GeoLite2-City.mmdb 1.1.1.1
```

From Rust:

```rust
let db = Database::open("GeoLite2-City.mmdb")?;

if let Some(result) = db.lookup("1.1.1.1")? {
    // Access location data
    println!("Result: {:?}", result);
}
```

### Extending MMDB Files

You can build a database that combines IP data (MMDB compatible) with patterns
(Matchy extension):

```rust
use matchy::{DatabaseBuilder, MatchMode, DataValue};
use std::collections::HashMap;

let mut builder = DatabaseBuilder::new(MatchMode::CaseInsensitive);

// Add IP data (MMDB compatible)
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

Standard MMDB readers will see the IP data. Matchy tools will see both IP and pattern data.

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
- All MMDB data types (strings, integers, floats, maps, arrays)

When building databases, Matchy uses MMDB format 2.0 for the IP tree and data section.

## Performance Comparison

MMDB lookups in Matchy have similar performance to MaxMind's official libraries:

```
MaxMind libmaxminddb:  ~5-10 million IP lookups/second
Matchy IP lookups:     ~7 million IP lookups/second

Both use:
- Binary tree traversal (O(log n) worst case, O(32) for IPv4, O(128) for IPv6)
- Memory mapping for instant loading
- Zero-copy data access
```

The extensions (hash table and pattern matching) add minimal overhead to IP lookups.

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
