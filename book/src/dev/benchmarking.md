# Benchmarking

Performance benchmarking for Matchy.

## Running Benchmarks

```bash
# Run all benchmarks
cargo bench

# Run specific benchmark
cargo bench pattern_matching

# Save baseline
cargo bench --bench paraglob_bench -- --save-baseline main

# Compare to baseline
cargo bench --bench paraglob_bench -- --baseline main
```

## Benchmark Categories

- **IP lookups** - Binary trie performance
- **Literal matching** - Hash table performance
- **Pattern matching** - Aho-Corasick performance
- **Database building** - Construction time
- **Database loading** - mmap overhead

## CLI Benchmarking

```bash
# Benchmark IP lookups
matchy bench ip --count 100000

# Benchmark pattern matching
matchy bench pattern --count 50000

# Benchmark combined
matchy bench combined --count 100000
```

## Profiling

```bash
# Install flamegraph
cargo install flamegraph

# Generate flamegraph
cargo flamegraph --bench paraglob_bench
```

## See Also

- [Benchmark Quick Start](../benchmark-quickstart.md)
- [Performance](../architecture/performance.md)
- [CLI Bench Command](../user-guide/cli-bench.md)
