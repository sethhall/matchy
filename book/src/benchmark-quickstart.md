# Benchmark Quick Start

Quick guide to benchmarking Matchy performance.

## Quick Benchmark

```bash
# Quick IP benchmark
matchy bench ip

# Quick pattern benchmark
matchy bench pattern --count 10000
```

## Standard Benchmarks

### IP Lookups

```bash
matchy bench ip --count 100000
```

Expected performance:
- **Build:** ~2.5M IPs/sec
- **Load:** <1ms (mmap)
- **Query:** ~4M queries/sec
- **Latency:** ~0.25µs per query

### Pattern Matching

```bash
matchy bench pattern --count 50000
```

Expected performance:
- **Build:** ~40K patterns/sec
- **Load:** <1ms (mmap)
- **Query:** ~95K queries/sec
- **Latency:** ~10µs per query

### Combined Database

```bash
matchy bench combined --count 100000
```

## Cargo Benchmarks

```bash
# Run all benchmarks
cargo bench

# Specific benchmark
cargo bench pattern_matching

# Save baseline
cargo bench -- --save-baseline main
```

## Comparing Performance

```bash
# Run baseline
cargo bench -- --save-baseline before

# Make changes...

# Compare
cargo bench -- --baseline before
```

## See Also

- [CLI Bench Command](user-guide/cli-bench.md)
- [Benchmarking](dev/benchmarking.md)
- [Performance](architecture/performance.md)
