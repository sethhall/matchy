# Performance Benchmarks

Official performance benchmarks and testing methodology for Matchy.

## Overview

Matchy provides built-in benchmarking via the `matchy bench` command. The
built-in workloads use generated data and measure build time, open time, and
query throughput. Use application data for production decisions.

## Running Benchmarks

### Quick Benchmark

```bash
matchy bench ip
```

Runs default IP benchmark (1M entries).

### Custom Benchmark

```bash
matchy bench pattern --count 100000 --query-count 1000000
```

### Benchmark Types

- `ip` - IPv4 and IPv6 address lookups
- `literal` - Exact string matching
- `pattern` - Glob pattern matching
- `combined` - Mixed workload (IPs + patterns)

See [matchy bench command](../commands/matchy-bench.md) for full options.

## Archived Results

> The numbers in this section were generated with version 0.5.2 on unspecified
> Apple M-series hardware. They predate the current v2 format and the version 3
> literal-hash implementation. They are retained only as historical context and
> must not be used as current performance claims or regression baselines.

### IP Address Lookups

**Configuration**: 100,000 IPv4 addresses, 100,000 queries

| Metric | Value |
|--------|-------|
| Build time | 0.04s |
| Build rate | 2.76M IPs/sec |
| Database size | 586 KB |
| Load time | 0.54ms |
| Query throughput | **5.80M queries/sec** |
| Query latency | 0.17µs |

**Key characteristics**:
- O(32) lookups for IPv4, O(128) for IPv6
- Binary trie traversal
- Cache-friendly sequential access

### String Literal Matching

**Configuration**: 50,000 literal strings, 50,000 queries

| Metric | Value |
|--------|-------|
| Build time | 0.01s |
| Build rate | 4.03M literals/sec |
| Database size | 3.00 MB |
| Load time | 0.49ms |
| Query throughput | **4.58M queries/sec** |
| Query latency | 0.22µs |

**Key characteristics**:
- O(1) hash table lookups
- Historical implementation predating the current sharded 96-bit XXH3 format
- Results require a fresh run before comparison with current code

### Pattern Matching (Globs)

**Configuration**: 10,000 glob patterns, 50,000 queries

| Metric | Value |
|--------|-------|
| Build time | 0.00s |
| Build rate | 4.08M patterns/sec |
| Database size | 62 KB |
| Load time | 0.27ms |
| Query throughput | **4.57M queries/sec** |
| Query latency | 0.22µs |

**Key characteristics**:
- Aho-Corasick automaton
- Parallel pattern matching
- Glob wildcard support

### Combined Database

**Configuration**: 10,000 IPs + 10,000 patterns, 50,000 queries

| Metric | Value |
|--------|-------|
| Build time | 0.01s |
| Build rate | 1.41M entries/sec |
| Database size | 2.29 MB |
| Load time | 0.46ms |
| Query throughput | **15.43K queries/sec** |
| Query latency | 64.83µs |

**Key characteristics**:
- Historical generated mixed workload
- Combined IP and pattern searches
- Production-like performance

## Archived v0.5.2 Performance Factors

### Database Size

| Entries | Build Time | Query Throughput |
|---------|------------|------------------|
| 10K | <0.01s | 6.5M queries/sec |
| 100K | 0.04s | 5.8M queries/sec |
| 1M | 0.35s | 5.2M queries/sec |
| 10M | 3.5s | 4.8M queries/sec |

These are historical v0.5.2 observations, not current scaling guarantees.

### Hit Rate Impact

| Hit Rate | Throughput | Notes |
|----------|------------|-------|
| 0% | 6.2M/sec | Early termination |
| 10% | 5.8M/sec | Default benchmark |
| 50% | 5.5M/sec | Realistic workload |
| 100% | 5.0M/sec | Data extraction overhead |

Higher hit rates show slightly lower throughput due to result extraction overhead.

### Trusted Mode

| Mode | Throughput | Notes |
|------|------------|-------|
| Safe | 4.9M/sec | UTF-8 validation |
| Trusted | 5.8M/sec | **~18% faster** |


## Memory Usage

### Per-Database Overhead

- **Mapped bytes**: Virtual address space scales with file size; resident pages depend on access patterns and OS policy
- **Runtime metadata**: Small owned structures are retained for section views and validated indexes
- **Query cache**: Optional and workload-dependent; each active thread retains at most 16 recent generations under one 64 MiB estimated live-result budget
- **Query state**: Some hot paths reuse thread-local buffers that can grow and retain capacity

### Sharing Between Processes

Read-only file-backed pages can be shared by processes mapping the same file.
Actual resident memory also includes private runtime metadata, query caches,
page tables, and pages dirtied or retained by the operating system. Measure
RSS/PSS under a representative access pattern instead of assuming it equals
the database size.

## Scalability

### Vertical Scaling

Opened databases support concurrent read-only lookups, but scaling is not
guaranteed to be linear. It depends on CPU topology, memory bandwidth, cache
behavior, query mix, and per-thread cache state. Measure the intended thread
count and pinning policy on the deployment hardware.

### Horizontal Scaling

Multiple servers can use the same database:
- NFS/shared storage: All servers access one copy
- Local copies: Each server loads independently
- Hot reload: Update without restart

## Comparing Alternatives

Do not compare Matchy with PostgreSQL, Redis, a `HashMap`, or a regex engine by
copying generic throughput numbers: durability, network transport, query
semantics, hit rate, data representation, and cache state differ. Build an
end-to-end benchmark with equivalent data and correctness requirements, then
report the complete command, software versions, hardware, storage, warm-up,
cache policy, and result distribution.

## Benchmarking Methodology

### Data Generation

Benchmarks use realistic synthetic data:
- **IPs**: Mix of /32 addresses and CIDR ranges
- **Literals**: Domain-like strings
- **Patterns**: Realistic glob patterns

### Measurement

1. **Build time**: Time to compile entries
2. **Save time**: Disk write performance
3. **Open time**: Mapping plus structural parsing, reported separately for warm and cold page-cache states
4. **Query time**: Batch throughput and latency distribution after an explicit warm-up policy

### Hardware

Record at least:

- Matchy version and exact revision
- CPU model, core count, governor/power mode, RAM, OS, and filesystem
- Storage model and whether the page cache is warm or cold
- Database size and format versions
- Query count, hit rate, pattern style, cache settings, and thread count
- Concurrent system load and repeated-run variance

Relative performance is not assumed to remain constant across hardware or
workloads.

## Reproducing Benchmarks

### Local Testing

```bash
# IP benchmark
matchy bench ip -n 100000 --query-count 100000

# Pattern benchmark
matchy bench pattern -n 10000 --query-count 50000

# Combined benchmark
matchy bench combined -n 20000 --query-count 50000
```

### Continuous Integration

```bash
# Run benchmarks and check for regressions
matchy bench ip > results.txt
grep "QPS" results.txt
```

### Custom Workloads

```bash
# Build your own database
matchy build custom.csv --input-format csv --output test.mxy

# Time representative single queries
time matchy query test.mxy example.com

# Or process representative logs with stats
matchy match test.mxy access.log --stats
```

## Performance Tuning

### For Best Query Performance

1. Reuse database handles
2. Use memory-mapped files (automatic)
3. Keep database on fast storage
4. Use direct IP lookup when possible

### For Best Build Performance

1. Sort input data by type
2. Use batch additions
3. Pre-allocate if entry count known
4. Use multiple builders in parallel

### For Lowest Memory

1. Use memory-mapped mode (default)
2. Share databases between processes
3. Close unused databases promptly
4. Disable or reduce the query cache when its hit rate does not justify its memory

## See Also

- [matchy bench command](../commands/matchy-bench.md) - Benchmark command reference
- [Performance Guide](../guide/performance.md) - Optimization strategies
- [Architecture](architecture.md) - Design and implementation
- [Memory Management](c-memory.md) - Memory usage details
