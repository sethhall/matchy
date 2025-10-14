# Performance Considerations

This chapter covers performance characteristics and optimization strategies for Matchy databases.

## Query Performance

Different entry types have different performance characteristics:

### IP Address Lookups

**Speed**: ~7 million queries/second
**Algorithm**: Binary tree traversal
**Complexity**: O(32) for IPv4, O(128) for IPv6 (address bit length)

```console
$ matchy bench database.mxy
IP address lookups:  7,234,891 queries/sec (138ns avg)
```

IP lookups traverse a binary trie, checking one bit at a time. The depth is fixed
at 32 bits (IPv4) or 128 bits (IPv6), making performance predictable.

### Exact String Lookups

**Speed**: ~8 million queries/second  
**Algorithm**: Hash table lookup
**Complexity**: O(1) constant time

```console
$ matchy bench database.mxy
Exact string lookups: 8,932,441 queries/sec (112ns avg)
```

Exact strings use hash table lookups, making them the fastest entry type.

### Pattern Matching

**Speed**: ~1-2 million queries/second (with thousands of patterns)
**Algorithm**: Aho-Corasick automaton
**Complexity**: O(n + m) where n = query length, m = number of matches

```console
$ matchy bench database.mxy
Pattern lookups: 2,156,892 queries/sec (463ns avg)
  (50,000 patterns in database)
```

Pattern matching searches all patterns simultaneously. Performance depends on:
- Number of patterns
- Pattern complexity
- Query string length

With thousands of patterns, expect 1-2 microseconds per query.

## Loading Performance

### Memory Mapping

Databases load via memory mapping, which is nearly instantaneous:

```console
$ time matchy query large-database.mxy 1.2.3.4
real    0m0.003s  # 3 milliseconds total (includes query)
```

Loading time is independent of database size:
- 1MB database: <1ms
- 100MB database: <1ms
- 1GB database: <1ms

The operating system maps the file into virtual memory without reading it entirely.

### Traditional Loading (for comparison)

If Matchy used traditional deserialization:

```
Database Size    Estimated Load Time
─────────────    ──────────────────
1MB              50-100ms
100MB            5-10 seconds
1GB              50-100 seconds
```

Memory mapping eliminates this overhead entirely.

## Build Performance

Building databases is a one-time cost:

```console
$ time matchy build threats.csv -o threats.mxy
real    0m1.234s  # 1.2 seconds for 100,000 entries
```

Build time depends on:
- Number of entries
- Number of patterns (Aho-Corasick construction)
- Data complexity
- I/O speed (writing output file)

Typical rates:
- IP/strings: ~100,000 entries/second
- Patterns: ~10,000 patterns/second (automaton construction)

## Memory Usage

### Database Size on Disk

```
Entry Type          Overhead per Entry
──────────          ─────────────────
IP address          ~8-16 bytes (tree nodes)
CIDR range          ~8-16 bytes (tree nodes)
Exact string        ~12 bytes + string length (hash table)
Pattern             Varies (automaton states)
```

Plus data storage:
- Small data (few fields): ~20-50 bytes
- Medium data (typical): ~100-500 bytes
- Large data (nested): 1KB+

### Memory Usage at Runtime

With memory mapping:
- **RSS (Resident Set Size)**: Only accessed pages loaded
- **Shared memory**: OS shares pages across processes
- **Virtual memory**: Full database mapped, but not loaded

Example with 64 processes and a 100MB database:
- Traditional: 64 × 100MB = 6,400MB RAM
- Memory mapped: ~100MB RAM (shared across processes)

The OS loads pages on-demand and shares them automatically.

## Optimization Strategies

### Use CIDR Ranges

Instead of adding individual IPs:

```rust
// Slow: 256 individual entries
for i in 0..256 {
    builder.add_entry(&format!("192.0.2.{}", i), data.clone())?;
}

// Fast: Single CIDR entry
builder.add_entry("192.0.2.0/24", data)?;
```

CIDR ranges are more efficient than individual IPs.

### Prefer Exact Strings Over Patterns

When possible, use exact strings:

```rust
// Faster: Hash table lookup
builder.add_entry("exact-domain.com", data)?;

// Slower: Pattern matching
builder.add_entry("exact-domain.*", data)?;
```

Exact strings are 4-8x faster than pattern matching.

### Pattern Efficiency

Some patterns are more efficient than others:

```rust
// Efficient: Suffix patterns
builder.add_entry("*.example.com", data)?;

// Less efficient: Multiple wildcards
builder.add_entry("*evil*bad*malware*", data)?;
```

Simple patterns with few wildcards perform better.

### Batch Builds

Build databases in batches rather than incrementally:

```rust
// Efficient: Build once
let mut builder = DatabaseBuilder::new(MatchMode::CaseInsensitive);
for entry in entries {
    builder.add_entry(&entry.key, entry.data)?;
}
let db_bytes = builder.build()?;

// Inefficient: Don't rebuild for each entry
// (not even possible - shown for illustration)
```

Databases are immutable, so building happens once.

## Benchmarking Your Database

Use the CLI to benchmark your specific database:

```console
$ matchy bench threats.mxy
Database: threats.mxy
Size: 15,847,293 bytes
Entries: 125,000

Running benchmarks...

IP lookups:       6,892,443 queries/sec (145ns avg)
Pattern lookups:  1,823,901 queries/sec (548ns avg)
String lookups:   8,234,892 queries/sec (121ns avg)

Completed 3,000,000 queries in 1.234 seconds
```

This shows real-world performance with your data.

## Performance Expectations

### By Database Size

```
Entries       DB Size     IP Query    Pattern Query
──────────    ────────    ────────    ─────────────
1,000         ~50KB       ~10M/s      ~5M/s
10,000        ~500KB      ~8M/s       ~3M/s
100,000       ~5MB        ~7M/s       ~2M/s
1,000,000     ~50MB       ~6M/s       ~1M/s
```

Performance degrades gracefully as databases grow.

### By Pattern Count

```
Patterns      Pattern Query Time
────────      ──────────────────
100           ~200ns
1,000         ~300ns
10,000        ~500ns
50,000        ~1-2μs
100,000       ~3-5μs
```

Aho-Corasick scales well, but very large pattern counts impact performance.

## Production Considerations

### Multi-Process Deployment

Memory mapping shines in multi-process scenarios:

```
┌──────────┐ ┌──────────┐ ┌──────────┐
│ Worker 1 │ │ Worker 2 │ │ Worker N │
└────┬─────┘ └────┬─────┘ └────┬─────┘
     │            │            │
     └────────────┴────────────┘
                  │
       ┌──────────┴──────────┐
       │   Database File       │
       │   (mmap shared)       │
       └──────────────────────┘
```

All workers share the same memory pages, dramatically reducing RAM usage.

### Database Updates

To update a database:

1. Build new database
2. Write to temporary file
3. Atomic rename over old file

```rust
let db_bytes = builder.build()?;
std::fs::write("threats.mxy.tmp", &db_bytes)?;
std::fs::rename("threats.mxy.tmp", "threats.mxy")?;
```

Existing processes keep reading the old file until they reopen.

### Hot Reloading

For zero-downtime updates:

```rust
let db = Arc::new(Database::open("threats.mxy")?);

// In another thread: watch for updates
// When file changes:
let new_db = Database::open("threats.mxy")?;
// Atomically swap the Arc
```

Old queries complete with the old database. New queries use the new database.

## Next Steps

- [Database Concepts](database-concepts.md) - Understanding database structure
- [Entry Types](entry-types.md) - Choosing the right entry type
- [Performance Benchmarks](../reference/benchmarks.md) - Detailed benchmark results
