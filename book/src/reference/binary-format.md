# Binary Format Specification

Detailed binary format specification for Matchy databases.

Matchy databases use the MaxMind DB (MMDB) format with optional extensions for string and pattern matching.

## Overview

The format has three main components:

1. **MMDB Section**: Standard MaxMind DB format for IP address lookups
2. **PARAGLOB Section**: Optional extension for glob pattern matching
3. **String Literals Hash Section**: Optional extension for exact string matching

All components coexist in a single `.mxy` file.

## File Structure

**Note**: The MMDB format is unusual - it has no header or magic bytes at the start. The file begins directly with the IP search tree, and all metadata is stored at the end of the file.

```
┌─────────────────────────────────────────────────────────┐
│  IP Search Tree (Binary Trie)                │  Starts at byte 0
├─────────────────────────────────────────────────────────┤
│  16-byte separator                            │
├─────────────────────────────────────────────────────────┤
│  Data Section (Shared)                        │  MMDB data values
├─────────────────────────────────────────────────────────┤
│  MMDB_PATTERN separator (optional)            │  "MMDB_PATTERN\x00\x00\x00\x00"
├─────────────────────────────────────────────────────────┤
│  PARAGLOB SECTION (optional)                  │  Glob pattern matching
├─────────────────────────────────────────────────────────┤
│  MMDB_LITERAL separator (optional)            │  "MMDB_LITERAL\x00\x00\x00\x00"
├─────────────────────────────────────────────────────────┤
│  STRING LITERALS HASH SECTION (optional)      │  O(1) exact string lookups
├─────────────────────────────────────────────────────────┤
│  Metadata Marker                              │  "\xAB\xCD\xEFMaxMind.com"
├─────────────────────────────────────────────────────────┤
│  MMDB Metadata (within last 128KB)            │  node_count, record_size, etc.
└─────────────────────────────────────────────────────────┘
```

### Section Descriptions

**IP Search Tree**: Binary trie for IP address lookups. This is the first data in the file (offset 0). The tree structure depends on metadata fields that are only available after parsing the metadata at the end of the file.

**Data Section**: Shared MMDB-encoded data values referenced by all query types (IP, pattern, and literal lookups).

**PARAGLOB Section**: Optional section for glob pattern matching. Present when
the database contains inferred wildcard patterns (for example,
`*.example.com`) or entries explicitly forced to `glob:` matching.

**String Literals Hash Section**: Optional hash table for O(1) exact string matching. Only present if the database contains literal strings (non-wildcard patterns).

**MMDB Metadata**: Contains essential database information:
- `node_count`: Number of nodes in the IP search tree
- `record_size`: Size of tree records (24, 28, or 32 bits)
- `ip_version`: IPv4 (4) or IPv6 (6)
- `pattern_section_offset`: Offset to PARAGLOB section (0 if absent)
- `literal_section_offset`: Offset to literal hash section (0 if absent)
- Build timestamp, database type, description, etc.

The metadata marker (`\xAB\xCD\xEFMaxMind.com`) is located within the last 128KB of the file. Parsers search backwards from the end to find it.

## MMDB Section

The file follows the standard MaxMind DB format:
- See [MaxMind DB Spec](https://maxmind.github.io/MaxMind-DB/)

Key characteristics:
- No header at start of file
- File begins with IP search tree data at offset 0
- Metadata stored at end of file for fast tail access
- Memory-mappable with zero-copy access

### Metadata

Standard MMDB metadata map at the end of the file (after metadata marker):

```json
{
  "binary_format_major_version": 2,
  "binary_format_minor_version": 0,
  "build_epoch": 1234567890,
  "database_type": "Matchy",
  "description": {
    "en": "Matchy unified database"
  },
  "ip_version": 6,
  "node_count": 12345,
  "record_size": 28
}
```

### Search Tree

Binary trie for IP address lookups:

- **Record sizes**: 24, 28, or 32 bits
- **Node sizes**: 6, 7, or 8 bytes respectively (two packed records per node)
- **Byte order**: MMDB tree records use the byte layout defined by the MaxMind DB specification

Each node contains a left and right record. A record can identify another tree
node, the not-found sentinel, or a value in the MMDB data section. For example,
the 28-bit layout is:

```
Node (7 bytes):
├─ Left pointer  (28 bits) → next node or data
└─ Right pointer (28 bits) → next node or data
```

### Data Section

Standard MMDB data types supported by Matchy:

| Type | Code | Size | Notes |
|------|------|------|-------|
| Pointer | 1 | Variable | Offset into data section |
| String | 2 | Variable | UTF-8 text |
| Double | 3 | 8 bytes | IEEE 754 |
| Bytes | 4 | Variable | Binary data |
| Uint16 | 5 | 2 bytes | Unsigned integer |
| Uint32 | 6 | 4 bytes | Unsigned integer |
| Map | 7 | Variable | Key-value pairs |
| Int32 | 8 | 4 bytes | Signed integer |
| Uint64 | 9 | 8 bytes | Unsigned integer |
| Uint128 | 10 | 16 bytes | Unsigned integer |
| Array | 11 | Variable | Ordered list |
| Boolean | 14 | 0 bytes | Value in type byte |
| Float | 15 | 4 bytes | IEEE 754 |

See [MaxMind DB Format](https://maxmind.github.io/MaxMind-DB/) for encoding details.

### Matchy Extended Types

Matchy extends the MMDB format with additional types using codes 128+:

| Type | Code | Size | Notes |
|------|------|------|-------|
| Timestamp | 128 | 8 bytes | Unix epoch seconds (signed i64) |

These types are stored using the MMDB extended type mechanism (raw byte = code - 7). Timestamp values are serialized to JSON as ISO 8601 strings (e.g., `2025-10-02T18:44:31Z`) for human readability while stored compactly as 8 bytes instead of 27-byte strings.

Type 128 is not part of the MMDB standard, so standard MMDB readers cannot
decode a value that contains it. Generic JSON deserialization into `DataValue`
converts RFC 3339 strings to this timestamp representation. Construct a
`DataValue::String` explicitly when standard-reader interoperability is
required.

Matchy's decoder accepts all standard types but deliberately bounds resource
use: pointer depth 32, total nesting 64, at most one million decoded values,
and at most 64 MiB of estimated owned allocation per decode budget. Smaller
sections use proportional budgets with floors. A database pattern query shares
one budget across all matched values. These limits are an input-safety policy,
not additional MMDB wire-format rules.

## PARAGLOB Section Format

When glob patterns are present, the PARAGLOB section contains:

```rust
#[repr(C)]
struct ParaglobHeader {
    magic: [u8; 8],           // "PARAGLOB"
    version: u32,             // Format version (currently 5)
    match_mode: u32,          // 0=CaseSensitive, 1=CaseInsensitive
    ac_node_count: u32,       // Number of AC automaton nodes
    ac_nodes_offset: u32,     // Offset to node array
    // ... additional fields for pattern data
}
```

Followed by:
- Aho-Corasick automaton nodes and edges
- Pattern metadata entries
- Glob segment data
- Pattern-to-data mappings

In a combined `.mxy` file, the bytes immediately after the
`MMDB_PATTERN` marker are wrapped as:

```text
total_size: u32
paraglob_size: u32
paraglob_bytes: [u8; paraglob_size]
pattern_count: u32
data_offsets: [u32; pattern_count]
```

`total_size` includes this wrapper header, the PARAGLOB bytes, the mapping
count, and every mapping offset. The outer `data_offsets` are relative to the
start of the shared MMDB data section; offset zero is a valid first value.

See `matchy-paraglob/src/offset_format.rs` for the complete
`ParaglobHeader` structure (112 bytes in v5).

## String Literals Hash Section Format (Version 3)

When literal strings are present, a hash table section provides O(1) lookups using 96-bit truncated XXH3 hashes:

```rust
#[repr(C)]
struct LiteralHashHeader {
    magic: [u8; 4],        // "LHSH"
    version: u32,          // 3
    entry_count: u32,      // Number of patterns
    table_size: u32,       // Hash table capacity
    num_shards: u32,       // Number of shards (power of 2)
    shard_bits: u32,       // Bits used for sharding
    mappings_offset: u32,  // Offset from LHSH start to mappings
    table_offset: u32,     // 8-byte-aligned hash table offset
}

#[repr(C)]
struct HashEntry {
    hash_lo: u64,          // Low 64 bits of XXH3_128
    hash_hi: u32,          // Next 32 bits of XXH3_128
    pattern_id: u32,       // Pattern ID for data lookup
}
```

The 32-byte header is followed by:

```text
shard_offsets: [u32; num_shards + 1]
padding to an 8-byte boundary
hash_entries: [HashEntry; table_size]
mapping_count: u32
mappings: [(pattern_id: u32, data_offset: u32); mapping_count]
```

Header offsets are relative to the start of the `LHSH` bytes. Mapping
`data_offset` values are relative to the containing MMDB data section, and
offset zero is valid.

**Key characteristics:**
- **Hash-only storage**: Original strings are not stored, but low-entropy
  indicators remain dictionary-enumerable; this is not a privacy boundary
- **96-bit hashes**: Collisions are unlikely but possible, with probability
  increasing with the number of stored and queried values; because original
  strings are absent, a collision can produce a false positive
- **Sharded construction**: Parallel building for large datasets
- **16-byte entries**: Same size as v1, but ~50% smaller total (no string pool)

See `matchy-literal-hash` crate for implementation details.

## Data Alignment

Serialized structures have field-specific layout requirements:

- **PARAGLOB typed tables**: 4-byte alignment where required by their fields
- **ACNodeHot**: 20 bytes, 4-byte alignment
- **AC edges and most PARAGLOB tables**: 4-byte alignment
- **Literal hash header and entries**: decoded from bytes; `table_offset` is an 8-byte-aligned offset relative to the `LHSH` start
- **Dense AC lookup tables**: the builder uses cache-line alignment

The builder zero-fills alignment padding. MMDB search-tree nodes are packed
byte records and do not use native struct alignment.

## Offset Encoding

Offset bases are part of each field's contract; there is no universal base or
universal null value.

| Field or structure | Offset base |
|--------------------|-------------|
| MMDB tree data records | Encoded according to the MMDB tree/data-section rules |
| `pattern_section_offset`, `literal_section_offset` metadata | Absolute file offset immediately after the corresponding 16-byte marker |
| PARAGLOB header section offsets | Start of the `PARAGLOB` buffer |
| AC-local node, edge, and pattern references | Start of the serialized AC buffer |
| Inline `PatternDataMapping.data_offset` | Start of the PARAGLOB inline data section |
| Combined-pattern outer mapping offsets | Start of the shared MMDB data section |
| Literal-header offsets | Start of the `LHSH` buffer |
| Literal pattern-mapping data offsets | Start of the shared MMDB data section |

In particular, zero is a valid shared-data offset. Fields that use zero as
"absent" document that behavior individually.

## Version History

### Version 5 (Current)

- Serialized glob segments for zero-copy loading
- Optimized memory layout with 20-byte ACNodeHot records
- Support for patterns, exact strings, and IP addresses
- Aho-Corasick automaton for pattern matching
- Separate hash table for exact literal matches
- Embedded MMDB data format

### Previous Versions

- **v4**: ACNodeHot (20-byte) for 50% memory reduction
- **v3**: Serialized AC literal mapping for direct loading
- **v2**: Data section support for pattern-associated data
- **v1**: Original format, patterns only

These entries describe format history, not a compatibility promise. The current
PARAGLOB reader accepts v5 only; older files require migration or rebuilding.

## Format Validation

Opening a database validates the format identity, supported version, declared
top-level section envelopes, extension markers, and component topology needed
to construct the runtime views. Nested serialized records are bounds-checked
before they are accessed.

The separate strict validator performs deeper, exhaustive checks over
referenced tree records and component relationships. Its checks include:

1. **Magic bytes match**: "\xAB\xCD\xEFMaxMind.com" at end, "PARAGLOB" if pattern section present
2. **Version supported**: PARAGLOB version 5 currently
3. **Section envelopes in bounds**: Declared top-level ranges fit their containing sections
4. **Alignment correct**: Structures with alignment requirements start at valid offsets
5. **Section offsets**: Metadata contains correct `pattern_section_offset` and `literal_section_offset`
6. **File size**: Must be at least large enough for tree + metadata

Validation errors result in format errors. See `matchy validate` command for detailed validation.

## Memory Mapping

The format is designed for memory mapping:

- **No pointer fixups**: Serialized references use documented offsets rather than process pointers
- **No relocations**: Position-independent
- **Byte-oriented reads**: Serialized fields can be checked without creating process pointers
- **Bounds checkable**: Section sizes and offset bases are explicit in their containing format

Example:

```rust
let file = File::open("database.mxy")?;
let mmap = unsafe { Mmap::map(&file)? };

// Direct access to structures
let header = read_paraglob_header(&mmap)?;
let nodes = get_node_array(&mmap, header.nodes_offset)?;
```

## Cross-Platform Compatibility

The MMDB portion follows the portable MaxMind DB encoding. Matchy's extension
sections currently support little-endian targets (including x86-64 and
little-endian ARM):

- **Endianness**: Extension files are emitted and read on little-endian targets. The marker reserves future big-endian support; the current reader does not byte-swap extension structs.
- **Layout**: Fixed-width fields and explicit padding (`u32`, not `size_t`)
- **ABI**: `#[repr(C)]` structures

A database built on Linux/x86-64 works on macOS/ARM64 when the ARM target is
little-endian. Big-endian extension compatibility is not currently supported.

## Future Extensions

Reserved fields for future versions:

- Pattern compilation flags (case sensitivity, etc.)
- Compressed string tables
- Alternative hash functions
- Additional data formats

Version changes will be backward-compatible when possible.

## See Also

- [MMDB Format Spec](https://maxmind.github.io/MaxMind-DB/)
- [Aho-Corasick Algorithm](https://en.wikipedia.org/wiki/Aho%E2%80%93Corasick_algorithm)
- [xxHash / XXH3](https://github.com/Cyan4973/xxHash)
- [Data Types Reference](data-types-ref.md)
