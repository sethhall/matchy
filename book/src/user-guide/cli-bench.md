# `matchy bench` - Benchmark Performance

Run comprehensive performance benchmarks to test database build, load, and query performance.

## Synopsis

```bash
matchy bench [OPTIONS] [TYPE]
```

## Arguments

- `[TYPE]` - Database type to benchmark: `ip`, `literal`, `pattern`, or `combined` (default: `ip`)

## Options

| Option | Description | Default |
|--------|-------------|---------|
| `-n, --count <N>` | Number of entries to test with | 1,000,000 |
| `-o, --output <FILE>` | Output file for the test database | Temp file |
| `-k, --keep` | Keep the generated database file after benchmarking | Delete after |
| `--load-iterations <N>` | Number of load iterations to average | 3 |
| `--query-count <N>` | Number of queries for batch benchmark | 100,000 |
| `--hit-rate <N>` | Percentage of queries that should match (0-100) | 10 |
| `--trusted` | Trust database and skip UTF-8 validation (faster) | Validate UTF-8 |
| `--pattern-style <STYLE>` | Pattern style: `prefix`, `suffix`, `mixed`, or `complex` | `complex` |

## Benchmark Types

### IP Benchmark

Tests IP address lookup performance:

```bash
matchy bench ip --count 100000
```

This generates 100,000 random IP addresses and CIDR ranges, builds them into an optimized database, then measures:
- **Build time**: How long to compile the IPs into a binary trie
- **Save time**: Disk write performance
- **Load time**: Memory-mapping overhead (typically <1ms)
- **Query throughput**: Queries per second (typically 3-5M queries/sec)
- **Average latency**: Per-query time in microseconds

### Literal Benchmark

Tests exact string matching performance:

```bash
matchy bench literal --count 100000 --hit-rate 10
```

Generates realistic literal strings: domains, URLs, file paths, emails, UUIDs, etc.

### Pattern Benchmark

Tests glob pattern matching performance:

```bash
matchy bench pattern --count 50000 --pattern-style complex
```

**Pattern styles:**
- `prefix` - Pure prefix patterns: `prefix-*`
- `suffix` - Pure suffix patterns: `*.domain.com`
- `mixed` - 50% prefix, 50% suffix
- `complex` - Varied patterns with multiple wildcards (default)

### Combined Benchmark

Tests unified database with both IP and pattern data:

```bash
matchy bench combined --count 100000
```

Creates 50% IPs and 50% patterns.

## Trusted Mode

Use `--trusted` to skip UTF-8 validation for **~15-20% faster** performance:

```bash
# Safe mode (default)
matchy bench pattern --count 200000

# Trusted mode - faster
matchy bench pattern --count 200000 --trusted
```

**⚠️ Only use `--trusted` for databases you control!**

## Examples

### Quick IP benchmark

```bash
matchy bench ip
```

### Large-scale benchmark

```bash
matchy bench ip --count 1000000
```

### Pattern benchmark with different styles

```bash
matchy bench pattern --count 50000 --pattern-style prefix
matchy bench pattern --count 50000 --pattern-style suffix
matchy bench pattern --count 50000 --pattern-style complex
```

### Save benchmark database

```bash
matchy bench combined --count 100000 \
  --output benchmark-db.mxy \
  --keep

# Now you can use it
matchy query benchmark-db.mxy test.example.com
matchy inspect benchmark-db.mxy
```

### High-query benchmark

```bash
matchy bench pattern --count 50000 \
  --query-count 1000000 \
  --hit-rate 20
```

### Compare trusted vs safe mode

```bash
echo "=== Safe Mode ==="
matchy bench pattern --count 200000

echo ""
echo "=== Trusted Mode ==="
matchy bench pattern --count 200000 --trusted
```

## Performance Testing Script

```bash
#!/bin/bash
# performance-test.sh - Test different database sizes

for COUNT in 10000 50000 100000 500000; do
    echo "=== Testing with $COUNT entries ==="
    
    # IP benchmark
    echo "IP benchmark:"
    matchy bench ip --count $COUNT
    
    # Literal benchmark
    echo "Literal benchmark:"
    matchy bench literal --count $COUNT
    
    # Pattern benchmark
    echo "Pattern benchmark:"
    matchy bench pattern --count $COUNT
    
    echo ""
done
```

## See Also

- [CLI Overview](cli.md) - Command line tool overview
- [Build Command](cli-build.md) - Building databases
- [Performance](../architecture/performance.md) - Performance details
