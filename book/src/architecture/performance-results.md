# Archived Performance Results

<style>
table {
    margin-left: 0;
    margin-right: auto;
}
</style>

> **Generated for version 0.5.2**  
> **Last updated:** 2025-10-12

> These measurements predate the current v2 workspace and version 3 literal
> hash format. They are retained as historical context only, not as current
> claims or regression thresholds.

Current results must be generated from the target revision and workload using
the commands shown below.

## Benchmark Results

All benchmarks run on the same hardware using `matchy bench`:

### IP Address Lookups

**Test configuration:** 100000 IPv4 addresses, 50000 queries, 1% hit rate

| Metric | Value |
|--------|-------|
| Build time | 0.04s |
| Build rate | 2.76M IPs/sec |
| Database size | 586.42 KB |
| Load time (avg) | 0.544ms |
| Query throughput | 5.80M queries/sec |
| Query latency (avg) | 0.17µs |

<details>
<summary>Command used</summary>

```bash
matchy bench ip -n 100000 --query-count 50000 --hit-rate 1
```
</details>

### String Literal Matching

**Test configuration:** 50000 literal strings, 50000 queries, 1% hit rate

| Metric | Value |
|--------|-------|
| Build time | 0.01s |
| Build rate | 4.03M literals/sec |
| Database size | 3.00 MB |
| Load time (avg) | 0.487ms |
| Query throughput | 4.58M queries/sec |
| Query latency (avg) | 0.22µs |

<details>
<summary>Command used</summary>

```bash
matchy bench literal -n 50000 --query-count 50000 --hit-rate 1
```
</details>

### Pattern Matching (Globs)

**Test configuration:** 10000 glob patterns, 50000 queries, 1% hit rate

| Metric | Value |
|--------|-------|
| Build time | 0.00s |
| Build rate | 4.08M patterns/sec |
| Database size | 62.36 KB |
| Load time (avg) | 0.265ms |
| Query throughput | 4.57M queries/sec |
| Query latency (avg) | 0.22µs |

<details>
<summary>Command used</summary>

```bash
matchy bench pattern -n 10000 --query-count 50000 --hit-rate 1 --pattern-style mixed
```
</details>

### Combined Database (IP + Patterns)

**Test configuration:** 10,000 IPs + 10,000 patterns, 50000 queries, 1% hit rate

| Metric | Value |
|--------|-------|
| Build time | 0.01s |
| Build rate | 1.41M entries/sec |
| Database size | 2.29 MB |
| Load time (avg) | 0.461ms |
| Query throughput | 15.43K queries/sec |
| Query latency (avg) | 64.83µs |

<details>
<summary>Command used</summary>

```bash
matchy bench combined -n 20000 --query-count 50000 --hit-rate 1 --pattern-style mixed
```
</details>

## Historical Implementation Characteristics

### IP Address Lookups

- **Binary trie traversal**: O(32) for IPv4, O(128) for IPv6
- **Memory-mapped**: Direct access to offset-based index data
- **Cache-friendly**: Sequential memory access pattern

### String Literal Matching

- **Hash table lookup**: O(1) average case
- **Historical hash implementation**: These v0.5.2 numbers predate the current sharded 96-bit XXH3 table
- **Do not transplant results**: Current literal performance requires a new run

### Pattern Matching

- **Aho-Corasick candidate discovery**: Scans the query once and emits literal hits
- **Selective verification**: Only candidate globs and pure-wildcard patterns are verified
- **Glob support**: Wildcards (`*`, `?`) and character classes (`[a-z]`)

## Memory Usage

Matchy uses memory-mapped files for zero-copy access:

- **Bounded startup parsing**: Direct binary access without whole-file deserialization
- **Shared pages**: Multiple processes share read-only memory
- **Lazy loading**: OS pages in data on demand
- **Owned runtime state**: Section metadata, validated index views, and optional query caches use heap memory

### Example: 1GB Database

Processes mapping the same file can share clean read-only pages. Actual
resident memory depends on which pages each process touches and also includes
private metadata, page tables, and query caches. Use RSS/PSS measurements under
the production access pattern rather than multiplying only the file size.

## Hot Reload

Database reloads avoid whole-file deserialization through:

- Memory-mapped file reopening
- Bounded structural parsing rather than rebuilding every serialized structure
- Immediate availability after atomic file rename

This enables live updates without service restarts or query interruptions.
