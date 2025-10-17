# Query Result Caching

Matchy includes a built-in LRU (Least Recently Used) cache for query results, providing 2-10x performance improvements for workloads with repeated queries.

## Overview

The cache stores query results in memory, eliminating the need to re-execute database lookups for previously seen queries. This is particularly valuable for:

- **Web APIs** serving repeated requests
- **Firewalls** checking the same IPs frequently  
- **Real-time threat detection** with hot patterns
- **High-traffic services** with predictable query patterns

## Performance

Cache performance depends on the **hit rate** (percentage of queries found in cache):

| Hit Rate | Speedup vs Uncached | Use Case |
|----------|---------------------|----------|
| 0% | 1.0x (no benefit) | Batch processing, unique queries |
| 50% | 1.5-2x | Mixed workload |
| 80% | 3-5x | Web API, typical firewall |
| 95% | 5-8x | High-traffic service |
| 99% | 8-10x | Repeated pattern checking |

**Zero overhead when disabled**: The cache uses compile-time optimization, so disabling it has no performance cost.

## Configuration

### Enabling the Cache

Use the builder API to configure cache capacity:

```rust
use matchy::Database;

// Enable cache with 10,000 entry capacity
let db = Database::from("threats.mxy")
    .cache_capacity(10_000)
    .open()?;

// Use the database normally - caching is transparent
if let Some(result) = db.lookup("evil.com")? {
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

**Default behavior**: If you don't specify cache configuration, a reasonable default cache is enabled.

## Cache Management

### Inspecting Cache Size

Check how many entries are currently cached:

```rust
println!("Cache entries: {}", db.cache_size());
```

### Clearing the Cache

Clear all cached entries:

```rust
db.clear_cache();
println!("Cache cleared: {}", db.cache_size()); // 0
```

This is useful for:
- Memory management in long-running processes
- Testing with fresh cache state
- Resetting after configuration changes

## How It Works

The cache is an LRU (Least Recently Used) cache:

1. **On first query**: Result is computed and stored in cache
2. **On repeated query**: Result is returned from cache (fast!)
3. **When cache is full**: Least recently used entry is evicted

The cache is **thread-safe** using interior mutability, so multiple queries can safely share the same `Database` instance.

## Cache Capacity Guidelines

Choose cache capacity based on your workload:

| Workload | Recommended Capacity | Reasoning |
|----------|---------------------|-----------|
| Web API (< 1000 req/s) | 1,000 - 10,000 | Covers hot patterns |
| Firewall (medium traffic) | 10,000 - 50,000 | Covers recent IPs |
| High-traffic service | 50,000 - 100,000 | Maximize hit rate |
| Memory-constrained | Disable cache | Save memory |

**Memory usage**: Each cache entry uses ~100-200 bytes, so:
- 10,000 entries ≈ 1-2 MB
- 100,000 entries ≈ 10-20 MB

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
use matchy::Database;
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
        if let Some(result) = db_clone.lookup(&query)? {
            send_response(result).await;
        }
    }
});
```

## Benchmarking Cache Performance

Use the provided benchmark to measure cache performance on your workload:

```bash
# Run the cache demo
cargo run --release --example cache_demo

# Or run the comprehensive benchmark
cargo bench --bench cache_bench
```

See `examples/cache_demo.rs` for a complete working example.

## Comparison with No Cache

Here's a typical performance comparison:

```rust
// Without cache (baseline)
let db_uncached = Database::from("db.mxy").no_cache().open()?;
// 10,000 queries: 2.5s → 4,000 QPS

// With cache (80% hit rate)
let db_cached = Database::from("db.mxy").cache_capacity(10_000).open()?;
// 10,000 queries: 0.8s → 12,500 QPS (3x faster!)
```

## Summary

- **Simple configuration**: Just add `.cache_capacity(size)` to the builder
- **Transparent operation**: No code changes after configuration
- **Significant speedup**: 2-10x for high hit rates
- **Zero overhead**: No cost when disabled
- **Thread-safe**: Safe to share across threads

Query result caching is one of the easiest ways to improve Matchy performance for real-world workloads.
