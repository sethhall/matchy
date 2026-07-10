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

### `--cache-size <CACHE_SIZE>`

LRU cache capacity used during the query benchmark. Default: `10000`. Use `0`
to disable the cache.

```bash
matchy bench ip --cache-size 0        # Disable cache
matchy bench ip --cache-size 50000    # Larger query cache
```

### `--cache-hit-rate <CACHE_HIT_RATE>`

Simulated cache hit rate percentage (0-100). Default: `0`, which generates all
unique queries. Higher values model repeated query patterns in production logs.

```bash
matchy bench ip --cache-hit-rate 80
matchy bench combined --cache-hit-rate 90
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
- Memory mapping avoids whole-file deserialization; load results still vary with cache state, storage, extensions, and legacy scanning

### Entry Type
- **IPs**: Bounded tree traversal plus selected-value decoding
- **Literals**: Average-case O(1) sharded hash probing
- **Patterns**: Candidate discovery plus pattern-dependent glob verification

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
- Report entry mix, value sizes, pattern styles, and selected record width
- Measure several sizes before assuming a scaling model
- One-time cost

### Load Time

How long it takes to map and structurally open the database:
- Report the storage medium and warm- or cold-page-cache state
- Compare like-for-like extension layouts and format versions
- Memory-mapped pages are faulted in on demand rather than eagerly copied into a heap representation

### Query Performance

Define a workload-specific baseline on otherwise controlled hardware and
compare distributions, not a universal queries-per-second threshold.

**When investigating a regression:**
- Check system load
- Verify no swap usage
- Record page faults and disk I/O rather than assuming all mapped pages are resident
- Confirm identical database bytes, query mix, cache settings, and Matchy revision

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
