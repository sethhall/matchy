# matchy bench

<!-- Note: Benchmark outputs in this file are from actual runs. To regenerate:
     matchy bench ip --count 10000
     matchy bench pattern --count 5000 --pattern-style prefix
     matchy bench combined --count 3000
-->

Benchmark database performance by generating test databases and measuring build, load, and query performance.

## Synopsis

```bash
matchy bench [OPTIONS] [TYPE]
```

## Description

The `matchy bench` command generates synthetic test databases of various types and sizes, then benchmarks:
- **Build time**: How long it takes to create the database
- **Load time**: How long it takes to open/memory-map the database
- **Query performance**: Throughput and latency for lookups

This is useful for performance testing, capacity planning, and comparing different database types and configurations.

## Arguments

### `[TYPE]`

Type of database to benchmark. Default: `ip`

Options:
- **`ip`** - IP address databases
- **`literal`** - Exact string match databases
- **`pattern`** - Glob pattern databases
- **`combined`** - Mixed database with all entry types

```bash
matchy bench ip         # Benchmark IP lookups
matchy bench pattern    # Benchmark pattern matching
matchy bench combined   # Benchmark mixed workload
```

## Options

### `-n, --count <COUNT>`

Number of entries to test with. Default: `1000000`

```bash
matchy bench ip --count 100000      # Small database
matchy bench ip --count 10000000    # Large database
```

### `-o, --output <OUTPUT>`

Output file for the test database. If not specified, uses a temporary file.

```bash
matchy bench pattern --output test.mxy
```

### `-k, --keep`

Keep the generated database file after benchmarking (otherwise it's deleted).

```bash
matchy bench ip --output bench.mxy --keep
```

### `--load-iterations <LOAD_ITERATIONS>`

Number of load iterations to average. Default: `3`

```bash
matchy bench ip --load-iterations 10
```

### `--query-count <QUERY_COUNT>`

Number of queries for batch benchmark. Default: `100000`

```bash
matchy bench ip --query-count 1000000  # 1M queries
```

### `--hit-rate <HIT_RATE>`

Percentage of queries that should match (0-100). Default: `10`

A lower hit rate tests "not found" performance, while a higher hit rate tests match performance.

```bash
matchy bench ip --hit-rate 50    # 50% of queries find matches
matchy bench ip --hit-rate 90    # 90% of queries find matches
```

### `--pattern-style <PATTERN_STYLE>`

Pattern style for pattern benchmarks. Default: `complex`

Options:
- **`prefix`** - Prefix patterns like `prefix*`
- **`suffix`** - Suffix patterns like `*.suffix`
- **`mixed`** - Mix of prefix and suffix
- **`complex`** - Complex patterns with wildcards and character classes

```bash
matchy bench pattern --pattern-style prefix
matchy bench pattern --pattern-style complex
```

### `-h, --help`

Print help information.

## Examples

### Basic IP Benchmark

```console
$ matchy bench ip --count 1000
<!-- cmdrun matchy bench ip --count 1000 -->
```

### Pattern Benchmark with Custom Settings

```console
$ matchy bench pattern --count 500 --pattern-style prefix
<!-- cmdrun matchy bench pattern --count 500 --pattern-style prefix -->
```

### Combined Benchmark

```console
$ matchy bench combined --count 300
<!-- cmdrun matchy bench combined --count 300 -->
```

### Save Benchmark Database

```bash
matchy bench ip --count 1000000 --output benchmark.mxy --keep
```

This creates a database you can inspect or query later:
```bash
matchy inspect benchmark.mxy
matchy query benchmark.mxy "192.0.2.1"
```

### High Hit Rate Benchmark

```bash
matchy bench ip --hit-rate 90 --query-count 1000000
```

Tests performance when most queries find matches (realistic for allowlist/blocklist scenarios).

### Low Hit Rate Benchmark

```bash
matchy bench ip --hit-rate 5 --query-count 1000000
```

Tests "not found" performance (realistic for threat intelligence databases where most IPs are not threats).

## Benchmark Types

### IP Benchmarks

Generates random IPv4 and IPv6 addresses:
- Mix of /32 addresses and CIDR ranges
- Realistic distribution
- Tests binary trie performance

### Literal Benchmarks

Generates random strings:
- Domain-like strings (e.g., `subdomain.example.com`)
- Tests hash table performance
- O(1) lookup complexity

### Pattern Benchmarks

Generates glob patterns based on style:
- **Prefix**: `prefix*` patterns
- **Suffix**: `*.suffix` patterns
- **Mixed**: Combination of prefix and suffix
- **Complex**: Wildcards, character classes `[abc]`, negation `[!xyz]`

Tests Aho-Corasick automaton performance.

### Combined Benchmarks

Generates databases with all three types:
- Equal distribution (33.3% each)
- Tests mixed workload performance
- Realistic production scenario

## Performance Factors

Benchmark results depend on:

### Database Size
- Larger databases → slightly slower queries
- Build time scales linearly
- Load time remains constant (memory-mapped)

### Entry Type
- **IPs**: Fastest (~7M queries/sec)
- **Literals**: Very fast (~8M queries/sec)
- **Patterns**: Moderate (~1-2M queries/sec)

### Hit Rate
- High hit rate → slightly slower (data extraction overhead)
- Low hit rate → faster (early termination)

### Hardware
- CPU speed affects query throughput
- RAM speed affects load performance
- Storage type affects build time

### Pattern Complexity
- Simple patterns (prefix/suffix) → faster
- Complex patterns → slower
- More patterns → more states to traverse

## Interpreting Results

### Build Time

How long it takes to compile entries into optimized format:
- 1M entries: ~1-3 seconds (typical)
- Scales approximately linearly
- One-time cost

### Load Time

How long it takes to memory-map the database:
- Should be <1ms for any size
- Instant startup time
- Memory-mapped, not loaded into RAM

### Query Performance

**Good performance:**
- IPs: >5M queries/sec
- Literals: >6M queries/sec
- Patterns: >1M queries/sec

**Acceptable performance:**
- IPs: 2-5M queries/sec
- Literals: 3-6M queries/sec
- Patterns: 500k-1M queries/sec

**Investigate if slower:**
- Check system load
- Verify no swap usage
- Check disk I/O (shouldn't be any after load)

## Use Cases

### Capacity Planning

```bash
# Test with production-sized database
matchy bench combined --count 5000000 --query-count 10000000
```

Use results to estimate:
- Queries your system can handle
- Memory requirements
- Build time for updates

### Performance Regression Testing

```bash
# Run before changes
matchy bench pattern --count 1000000 > before.txt

# Make changes...

# Run after changes
matchy bench pattern --count 1000000 > after.txt

# Compare results
diff before.txt after.txt
```

### Hardware Comparison

```bash
# Run same benchmark on different systems
matchy bench combined --count 1000000
```

Compare:
- Query throughput
- Build time
- Load time

## Exit Status

- **0**: Benchmark completed successfully
- **1**: Error (out of memory, disk full, etc.)

## See Also

- [matchy build](matchy-build.md) - Build production databases
- [matchy validate](matchy-validate.md) - Validate databases
- [Performance Considerations](../guide/performance.md) - Optimization guide
- [Performance Benchmarks](../reference/benchmarks.md) - Detailed performance data
