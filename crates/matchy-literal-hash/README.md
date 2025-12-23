# matchy-literal-hash

O(1) exact string matching using hash tables with parallel construction.

## Overview

A memory-mapped hash table optimized for exact string lookups. Unlike Aho-Corasick (designed for pattern matching), this provides O(1) lookups for literal strings using 96-bit truncated XXH3 hashes with sharded parallel construction.

## Features

- **O(1) lookups**: Hash-based exact string matching
- **Parallel construction**: Sharded building for large datasets
- **Memory-mapped**: Zero-copy loading from disk
- **Case modes**: Case-sensitive and case-insensitive matching
- **Privacy**: Hash-only storage means original strings aren't stored
- **Compact**: ~50% smaller than string-storing formats

## Usage

```rust
use matchy_literal_hash::{LiteralHashBuilder, LiteralHash, MatchMode};

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

## Architecture

- **Sharded hash table**: Distributes entries across multiple shards for parallel construction
- **XXH3_128 hashing**: Fast hash function, truncated to 96 bits
- **Binary format**: Memory-mappable with magic bytes "LHSH"

## Binary Format (Version 2)

```
[Header - 32 bytes]
  magic: "LHSH"
  version: 2
  entry_count, table_size, reserved1, reserved2, num_shards, shard_bits

[Shard Offset Table]
  Offsets to each shard in the table

[Hash Table]
  entries: [hash: [u8; 12], pattern_id: u32]

[Pattern Mappings]
  (pattern_id, data_offset) pairs
```

## Dependencies

- `matchy-match-mode` - Shared MatchMode enum
- `rustc-hash` - Fast FxHashMap
- `xxhash-rust` - XXH3 implementation
- `rayon` - Parallel shard construction
