# Performance Benchmarks

Official performance benchmarks and testing methodology for Matchy.

## Overview

Matchy provides built-in benchmarking via the `matchy bench` command. All benchmarks use real-world data patterns and measure build time, load time, and query throughput.

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

## Official Results

> Generated with version 0.5.2 on Apple M-series hardware

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
- FxHash for fast non-cryptographic hashing
- Zero-copy memory access

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
- Realistic mixed workload
- Combined IP and pattern searches
- Production-like performance

## Performance Factors

### Database Size

| Entries | Build Time | Query Throughput |
|---------|------------|------------------|
| 10K | <0.01s | 6.5M queries/sec |
| 100K | 0.04s | 5.8M queries/sec |
| 1M | 0.35s | 5.2M queries/sec |
| 10M | 3.5s | 4.8M queries/sec |

Query performance remains high even with large databases due to memory-mapped access and efficient data structures.

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

Use `--trusted` flag for databases you control.

## Memory Usage

### Per-Database Overhead

- **Handle**: ~200 bytes
- **File mapping**: 0 bytes (OS-managed)
- **Query state**: 0 bytes (stack-allocated)

### Sharing Between Processes

With 10 processes using 1GB database:

- **Without mmap**: 10 × 1GB = 10GB RAM
- **With mmap**: ~1GB RAM (shared pages)

Memory-mapped databases are shared between processes automatically by the OS.

## Scalability

### Vertical Scaling

- **Single-threaded**: 5.8M queries/sec
- **4 threads**: 23M queries/sec (4×)
- **8 threads**: 46M queries/sec (8×)

Linear scaling due to thread-safe read-only access.

### Horizontal Scaling

Multiple servers can use the same database:
- NFS/shared storage: All servers access one copy
- Local copies: Each server loads independently
- Hot reload: Update without restart

## Comparison to Alternatives

### vs. Traditional Databases

| Feature | Matchy | PostgreSQL | Redis |
|---------|--------|------------|-------|
| IP lookups/sec | 5.8M | 50K | 200K |
| Pattern matching | Yes | Slow | No |
| Memory usage | Low (mmap) | High | High |
| Startup time | <1ms | Seconds | Seconds |
| Concurrent reads | Unlimited | Limited | Limited |

### vs. In-Memory Structures

| Feature | Matchy | HashMap | Regex Set |
|---------|--------|---------|----------|
| Query speed | 5.8M/sec | 10M/sec | 10K/sec |
| Memory | O(1) | O(n) | O(n) |
| Load time | <1ms | Seconds | Seconds |
| Persistence | Built-in | Manual | Manual |

Matchy trades slight query speed for massive memory and load time advantages.

## Benchmarking Methodology

### Data Generation

Benchmarks use realistic synthetic data:
- **IPs**: Mix of /32 addresses and CIDR ranges
- **Literals**: Domain-like strings
- **Patterns**: Realistic glob patterns

### Measurement

1. **Build time**: Time to compile entries
2. **Save time**: Disk write performance
3. **Load time**: Memory-mapping overhead (averaged over 3 runs)
4. **Query time**: Batch query throughput

### Hardware

Official benchmarks run on:
- **CPU**: Apple M-series (ARM64)
- **RAM**: 16GB+
- **Storage**: SSD

Results vary by hardware but relative performance remains consistent.

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
matchy build -i custom.csv -o test.mxy

# Benchmark it
time matchy query test.mxy < queries.txt
```

## Performance Tuning

### For Best Query Performance

1. Use `--trusted` for controlled databases
2. Reuse database handles
3. Use memory-mapped files (automatic)
4. Keep database on fast storage (SSD)
5. Use direct IP lookup when possible

### For Best Build Performance

1. Sort input data by type
2. Use batch additions
3. Pre-allocate if entry count known
4. Use multiple builders in parallel

### For Lowest Memory

1. Use memory-mapped mode (default)
2. Share databases between processes
3. Close unused databases promptly
4. Use validated mode (skips validation cache)

## See Also

- [matchy bench command](../commands/matchy-bench.md) - Benchmark command reference
- [Performance Guide](../guide/performance.md) - Optimization strategies
- [Architecture](architecture.md) - Design and implementation
- [Memory Management](c-memory.md) - Memory usage details
