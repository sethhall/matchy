# Query Result Caching

Matchy includes an optional least-recently-used (LRU) query-result cache. It
can reduce repeated lookup and decoding work when a workload has a useful hot
set; the benefit depends on hit rate, result size, query type, and hardware.

## Overview

The cache stores query results in memory, eliminating the need to re-execute database lookups for previously seen queries. This is particularly valuable for:

- **Web APIs** serving repeated requests
- **Firewalls** checking the same IPs frequently  
- **Real-time threat detection** with hot patterns
- **High-traffic services** with predictable query patterns

## Performance

A cache hit avoids matcher traversal and data decoding, but returning an owned
`QueryResult` can still clone its data. A miss pays the normal lookup cost plus
cache bookkeeping. Measure with the intended query distribution and report the
cache hit rate; unique batch workloads often do better with caching disabled.

When disabled, Matchy skips cache lookup and insertion. Normal query dispatch
still occurs, so this should be described as removing cache overhead rather
than as a compile-time optimization.

## Configuration

### Enabling the Cache

Use the builder API to configure cache capacity:

```rust
use matchy::{Database, QueryResult};

// Enable cache with 10,000 entry capacity
let db = Database::from("threats.mxy")
    .cache_capacity(10_000)
    .open()?;

// Use the database normally - caching is transparent
if let Some(result @ (QueryResult::Ip { .. } | QueryResult::Pattern { .. })) =
    db.lookup("evil.com")?
{
    println!("Match: {:?}", result);
}
```

### Disabling the Cache

Explicitly disable caching for memory-constrained environments:

```rust
let db = Database::from("threats.mxy")
    .no_cache()  // Disable caching
    .open()?;
```

**Default behavior**: If you do not specify cache configuration, caching is
enabled with a 10,000-entry ceiling per retained generation. Each thread keeps
at most 16 generations under one aggregate retained-heap ceiling; an oversized
result is not cached.

## Cache Management

### Inspecting Cache Size

Check how many entries are currently cached on the calling thread:

```rust
println!("Cache entries: {}", db.cache_size());
```

### Clearing the Cache

Clear this database generation's cached entries on the calling thread:

```rust
db.clear_cache();
println!("Cache cleared: {}", db.cache_size()); // 0
```

This is useful for:
- Memory management in long-running processes
- Testing with fresh cache state
- Resetting after configuration changes

## How It Works

The cache is an LRU cache:

1. **On first query**: Result is computed and stored in cache
2. **On repeated query**: Result is returned from cache (fast!)
3. **When an entry or byte limit is reached**: Least recently used entries are evicted

An opened `Database` is safe to share between threads. Query caches themselves
are thread-local and keyed by database generation, so each querying thread
builds its own hot set without a shared cache lock. The configured entry ceiling
applies to each retained generation. A thread retains at most 16 recent
generations, all sharing one aggregate retained-byte budget.

## Cache Capacity Guidelines

Choose cache capacity based on your workload:

| Workload | Recommended Capacity | Reasoning |
|----------|---------------------|-----------|
| Web API (< 1000 req/s) | 1,000 - 10,000 | Covers hot patterns |
| Firewall (medium traffic) | 10,000 - 50,000 | Covers recent IPs |
| High-traffic service | 50,000 - 100,000 | Maximize hit rate |
| Memory-constrained | Disable cache | Save memory |

**Memory usage**: Entry size is data-dependent. A miss result may be small,
while a pattern result can own vectors, strings, maps, and arrays. Matchy uses
both the configured entry ceiling and a 64 MiB aggregate estimated
retained-heap ceiling per thread across its recent generations. Allocator
overhead and temporary clones can make process RSS differ from that estimate.
Increasing the entry capacity does not raise the byte ceiling.

## When to Use Caching

### ✅ Use Caching For:

- **Web APIs** with repeated queries
- **Firewalls** checking the same IPs
- **Real-time monitoring** with hot patterns
- **Long-running services** with predictable queries

### ❌ Skip Caching For:

- **Batch processing** (all queries unique)
- **One-time scans** (no repeated queries)
- **Memory-constrained** environments
- **Testing** where you need fresh results

## Example: Web API with Caching

```rust
use matchy::{Database, QueryResult};
use std::sync::Arc;

// Create a shared database with caching
let db = Arc::new(
    Database::from("threats.mxy")
        .cache_capacity(50_000)  // High capacity for web API
        .open()?
);

// Share across request handlers
let db_clone = Arc::clone(&db);
tokio::spawn(async move {
    // Handle requests
    loop {
        let query = receive_request().await;
        
        // Cache hit on repeated queries!
        if let Some(result @ (QueryResult::Ip { .. } | QueryResult::Pattern { .. })) =
            db_clone.lookup(&query)?
        {
            send_response(result).await;
        }
    }
});
```

## Benchmarking Cache Performance

Use the provided benchmark to measure cache performance on your workload:

```bash
# Run the cache demo
cargo run --release -p matchy --example cache_demo

# Or run the comprehensive benchmark
cargo bench -p matchy --bench cache_bench
```

See `examples/cache_demo.rs` for a complete working example.

## Comparison with No Cache

Benchmark both policies on the same database and query stream:

```rust
// Without cache (baseline)
let db_uncached = Database::from("db.mxy").no_cache().open()?;

// With the default-sized entry cache
let db_cached = Database::from("db.mxy").cache_capacity(10_000).open()?;
```

Warm each cache deliberately, keep the query order identical, and record both
throughput and memory. Do not infer production speedup from hit rate alone.

## Summary

- **Simple configuration**: Just add `.cache_capacity(size)` to the builder
- **Transparent operation**: No code changes after configuration
- **Workload-dependent benefit**: Measure repeated and unique query mixes
- **Bounded retention**: Entry count and estimated retained bytes are limited
- **Thread-local state**: Safe database sharing without a global cache lock

Query result caching is one of the easiest ways to improve Matchy performance for real-world workloads.
