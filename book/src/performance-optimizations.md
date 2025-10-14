# Performance Optimizations

Performance optimization techniques in Matchy.

## Key Optimizations

### Memory Mapping

**Zero-copy access** to database files:
- No deserialization overhead
- OS-level page sharing
- <1ms load time

### Offset-Based Structures

**Pointer-free data structures** enable mmap:
```rust
struct Node {
    failure_offset: u32,  // Not a pointer!
    edges_offset: u32,
}
```

### Binary Trie for IPs

**O(log n) lookups** with compact storage:
- Efficient CIDR matching
- Cache-friendly layout
- Minimal memory overhead

### Aho-Corasick for Patterns

**Multi-pattern matching** in single pass:
- All patterns checked simultaneously
- Linear time complexity
- State machine approach

### Hash Table for Literals

**O(1) exact matches**:
- Fast string lookups
- Low collision rate
- Compact storage

## Compiler Optimizations

### LTO (Link Time Optimization)

```toml
[profile.release]
lto = true
```

### Single Codegen Unit

```toml
codegen-units = 1
```

### Target CPU

```bash
RUSTFLAGS="-C target-cpu=native" cargo build --release
```

## Runtime Optimizations

### Trusted Mode

Skip UTF-8 validation for 15-20% speedup:
```rust
let db = Database::open_trusted("db.mxy")?;
```

### Batch Queries

Reuse database handle:
```rust
let db = Database::open("db.mxy")?;
for query in queries {
    db.lookup(query)?;
}
```

## See Also

- [Performance Results](architecture/performance-results.md)
- [System Architecture](architecture/overview.md)
