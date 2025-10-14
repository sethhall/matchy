# Architecture

Technical overview of Matchy's design and implementation.

## Design Goals

Matchy is built around these core principles:

1. **Zero-copy access** - Memory-mapped files for instant loading
2. **Unified database** - Single file for IPs, strings, and patterns
3. **Memory efficiency** - Shared read-only pages across processes
4. **High performance** - Millions of queries per second
5. **Safety first** - Memory-safe Rust core with careful FFI

## System Architecture

```
┌─────────────────────────────────────┐
│         Matchy Database             │
│              (.mxy)                 │
└─────────────────────────────────────┘
           │
           ├─ MMDB Section (IP lookups)
           │  └─ Binary trie for CIDR matching
           │
           ├─ Literal Hash Section
           │  └─ FxHash table for exact strings
           │
           └─ PARAGLOB Section
              ├─ Aho-Corasick automaton
              ├─ Pattern table
              └─ Data section (JSON values)
```

## Core Components

### 1. Binary Trie (IP Lookups)

**Purpose**: Efficient CIDR prefix matching

**Algorithm**: Binary trie with longest-prefix-match
- Each node represents one bit in the IP address
- IPv4: Maximum 32 levels deep
- IPv6: Maximum 128 levels deep
- O(n) lookup where n = address bits

**Memory layout**:
```
Node {
    left_offset: u32,   // Offset to left child (0 bit)
    right_offset: u32,  // Offset to right child (1 bit)
    data_offset: u32,   // Offset to associated data
}
```

**Performance**:
- 5.8M lookups/sec for IPv4
- Cache-friendly sequential traversal
- Zero allocations per query

### 2. Literal Hash Table

**Purpose**: O(1) exact string matching

**Algorithm**: FxHash with open addressing
- Non-cryptographic hash for speed
- Collision resolution via linear probing
- Load factor kept below 0.75

**Memory layout**:
```
HashEntry {
    hash: u64,          // FxHash of the string
    string_offset: u32, // Offset to string data
    data_offset: u32,   // Offset to associated data
}
```

**Performance**:
- 4.58M lookups/sec
- Single memory access for most queries
- Zero string allocations

### 3. Aho-Corasick Automaton (Pattern Matching)

**Purpose**: Parallel multi-pattern glob matching

**Algorithm**: Offset-based Aho-Corasick
- Finite state machine for pattern matching
- Failure links for efficient backtracking
- Glob wildcards: `*` (any), `?` (single), `[a-z]` (class)

**Memory layout**:
```
AcNode {
    edges_offset: u32,      // Offset to edge table
    edges_count: u16,       // Number of outgoing edges
    failure_offset: u32,    // Failure function link
    pattern_ids_offset: u32,// Patterns ending here
    pattern_count: u16,     // Number of patterns
}

AcEdge {
    character: u8,          // Input character
    target_offset: u32,     // Target node offset
}
```

**Performance**:
- 4.57M lookups/sec
- O(n + m) where n = text length, m = pattern length
- All patterns checked in single pass

## Data Flow

### Query Path

```
┌───────────────────────────┐
│  Query (text or IP)  │
└───────────┬──────────────┘
     │
     ├─ Parse as IP?
     │  ├─ Yes → Binary Trie Lookup
     │  └─ No ↓
     │
     ├─ Hash Lookup (Exact)
     │  ├─ Found → Return result
     │  └─ Not found ↓
     │
     └─ Pattern Match (Aho-Corasick)
        ├─ Match → Return first
        └─ No match → Return NULL
```

### Build Path

```
┌──────────────────────────────┐
│  Input (CSV, JSON, etc.)  │
└─────────────┬────────────────┘
     │
     ├─ Parse entries
     │
     ├─ Categorize:
     │  ├─ IP addresses → Binary trie builder
     │  ├─ Exact strings → Hash table builder  
     │  └─ Patterns → Aho-Corasick builder
     │
     ├─ Build data structures
     │
     ├─ Serialize to binary
     │
     └─ Write .mxy file
```

## Memory Management

### Offset-Based Pointers

All internal references use **file offsets** instead of pointers:

```rust
// NOT this:
struct Node {
    left: *const Node,  // Pointer (can't mmap)
}

// But this:
struct Node {
    left_offset: u32,   // Offset (mmap-friendly)
}
```

Benefits:
- Memory-mappable
- Cross-process safe
- Platform-independent

### Memory Layout

```
┌─────────────────────────────────────┐  ← File start (offset 0)
│   MMDB Metadata (128 bytes)        │
├─────────────────────────────────────┤
│   IP Binary Trie                    │
│   (variable size)                   │
├─────────────────────────────────────┤
│   Data Section                      │
│   (JSON values, strings)            │
├─────────────────────────────────────┤
│   "PARAGLOB" Magic (8 bytes)       │
├─────────────────────────────────────┤
│   PARAGLOB Header                   │
│   - Node count                      │
│   - Pattern count                   │
│   - Offsets to sections             │
├─────────────────────────────────────┤
│   AC Automaton Nodes                │
├─────────────────────────────────────┤
│   AC Edges                          │
├─────────────────────────────────────┤
│   Pattern Table                     │
├─────────────────────────────────────┤
│   Literal Hash Table                │
└─────────────────────────────────────┘  ← File end
```

## Thread Safety

### Read-Only Operations

**Thread-safe**:
- Opening databases
- Querying (concurrent reads)
- Inspecting metadata

Multiple threads can safely query the same database:
```rust
// Thread 1
db.lookup("query1")?;

// Thread 2 (safe!)
db.lookup("query2")?;
```

### Write Operations

**Not thread-safe**:
- Building databases (use one builder per thread)
- Modifying entries (immutable after build)

## Performance Characteristics

### Time Complexity

| Operation | Complexity | Notes |
|-----------|------------|-------|
| IP lookup | O(n) | n = address bits (32 or 128) |
| Literal lookup | O(1) | Average case with FxHash |
| Pattern match | O(n+m) | n = text length, m = pattern length |
| Database load | O(1) | Memory-map operation |
| Database build | O(n log n) | n = number of entries |

### Space Complexity

| Component | Space | Notes |
|-----------|-------|-------|
| Binary trie | O(n) | n = unique IP prefixes |
| Hash table | O(n) | n = literal strings |
| AC automaton | O(m) | m = total pattern characters |
| Data section | O(d) | d = JSON data size |

## Optimizations

### 1. Memory Mapping

- Zero-copy file access
- Shared pages between processes
- OS-managed caching
- Instant "load" time

### 2. Offset Compression

Where possible, use smaller integer types:
- `u16` for small offsets (<65K)
- `u32` for medium offsets (<4GB)
- Reduces memory footprint

### 3. Cache Locality

Data structures optimized for sequential access:
- Nodes stored contiguously
- Edges grouped by source node
- Hot paths use adjacent memory

### 4. Zero Allocations

Query path allocates zero heap memory:
- Stack-allocated state
- Borrowed references
- No string copies

## Safety

### Rust Core

Core algorithms in **100% safe Rust**:
- No unsafe blocks in hot paths
- Borrow checker prevents use-after-free
- Bounds checking on all array access

### FFI Boundary

Unsafe code limited to C FFI:
```rust
// Validation at boundary
if ptr.is_null() {
    return ERROR_INVALID_PARAM;
}

// Panic catching
let result = std::panic::catch_unwind(|| {
    // ... safe Rust code ...
});
```

### Validation

Multi-level validation:
1. **Format validation**: Check magic bytes, version
2. **Bounds checking**: All offsets within file
3. **UTF-8 validation**: All strings valid UTF-8
4. **Graph validation**: No cycles in automaton

## See Also

- [Binary Format](binary-format.md) - Detailed format specification
- [Performance Benchmarks](benchmarks.md) - Performance data
- [C API Design](c-api.md) - FFI safety patterns
- [Database Builder](database-builder.md) - Build process details
