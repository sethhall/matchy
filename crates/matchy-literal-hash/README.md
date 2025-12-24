# matchy-literal-hash

O(1) exact string matching using memory-mapped hash tables with parallel construction.

## Features

- **O(1) lookups**: Hash-based exact string matching
- **96-bit hashes**: Virtually zero false positives (safe at 60M+ lookups/sec)
- **Parallel construction**: Sharded building for large datasets
- **Memory-mapped**: Zero-copy loading from disk
- **Case modes**: Case-sensitive and case-insensitive matching

## Usage

```rust
use matchy_literal_hash::{LiteralHashBuilder, LiteralHash};
use matchy_match_mode::MatchMode;

// Build a hash table
let mut builder = LiteralHashBuilder::new(MatchMode::CaseInsensitive);
builder.add_pattern("example.com", 0);
builder.add_pattern("google.com", 1);

let pattern_data = vec![(0, 100), (1, 200)]; // (pattern_id, data_offset)
let bytes = builder.build(&pattern_data)?;

// Load and query
let hash = LiteralHash::from_buffer(&bytes, MatchMode::CaseInsensitive)?;
assert_eq!(hash.lookup("example.com"), Some(0));
assert_eq!(hash.lookup("EXAMPLE.COM"), Some(0)); // Case-insensitive
```

## Binary Format (Version 3)

```
[Header - 32 bytes]
  magic: "LHSH"
  version: 3
  entry_count, table_size, num_shards, shard_bits
  mappings_offset, table_offset

[Shard Offset Table]
  offsets: [u32; num_shards + 1]

[Hash Table - Array of Structs]
  entries: [HashEntry; table_size]
    hash_lo: u64        // Lower 64 bits of XXH3
    hash_hi: u32        // Upper 32 bits of XXH3
    pattern_id: u32

[Pattern Mappings]
  (pattern_id, data_offset) pairs
```

## Dependencies

- `matchy-match-mode` - Shared MatchMode enum
- `rustc-hash` - Fast FxHashMap
- `xxhash-rust` - XXH3 implementation
- `rayon` - Parallel shard construction
