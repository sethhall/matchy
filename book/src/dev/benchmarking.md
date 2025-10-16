# Benchmarking

Performance benchmarking for Matchy.

## Running Benchmarks

```bash
# Run all benchmarks
cargo bench

# Run specific benchmark
cargo bench pattern_matching

# Save baseline
cargo bench --bench matchy_bench -- --save-baseline main

# Compare to baseline
cargo bench --bench matchy_bench -- --baseline main
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

## Memory Profiling

Matchy includes tools for analyzing memory allocations during queries.

### Query Allocation Profiling

Use the `query_profile` tool to analyze query-time allocations:

```bash
# Run with memory profiling enabled
cargo bench --bench query_profile --features dhat-heap

# Output shows allocation statistics
Completed 1,000,000 queries

=== Query-Only Memory Profile ===
dhat: Total:     8,000,894 bytes in 1,000,014 blocks
dhat: At t-gmax: 753 bytes in 11 blocks
dhat: At t-end:  622 bytes in 10 blocks
dhat: Results saved to: dhat-heap.json
```

This runs 1 million queries and tracks every allocation.

### Interpreting Results

Key metrics:

- **Total bytes**: All allocations during profiling period
- **Total blocks**: Number of separate allocations
- **t-gmax**: Peak heap usage (maximum resident memory)
- **t-end**: Memory still allocated at program end

### What to Look For

**Good results** (current state):
```
Total: ~8MB in 1M blocks
```
- **~1 allocation per query**: Only the return Vec is allocated
- **~8 bytes per allocation**: Just the Vec header
- Internal buffers are reused across queries

**Bad results** (if you see this, something regressed):
```
Total: ~50MB in 5M blocks
```
- **5+ allocations per query**: Temporary buffers not reused
- **50+ bytes per allocation**: Excessive copying
- Performance will be degraded

### Viewing Detailed Results

The tool generates `dhat-heap.json` which can be viewed with dhat's viewer:

```bash
# Open in browser (requires dhat repository)
open dhat/dh_view.html
# Then drag and drop dhat-heap.json into the viewer
```

The viewer shows:
- Allocation call stacks
- Peak memory usage over time
- Hotspots (which code allocates most)

### Why This Matters

Query performance is critical. Matchy achieves:
- **~7M queries/second** for IP lookups
- **~2M queries/second** for pattern matching

This is only possible through careful allocation management:

1. **Buffer reuse**: Internal buffers are reused across queries
2. **Zero-copy patterns**: Data is read directly from mmap'd memory
3. **Minimal cloning**: Only the final result Vec is allocated

Each allocation costs ~100ns, so avoiding them matters.

### Allocation Optimization History

Matchy underwent allocation optimization in October 2024:

**Before optimization**:
- 4 allocations per query (~10.4 bytes each)
- ~40MB allocated per 1M queries
- Short-lived temporary vectors

**After optimization**:
- 1 allocation per query (~8 bytes)
- ~8MB allocated per 1M queries
- **75% reduction in allocations**

Key changes:
- Added `result_buffer` to reuse across queries
- Changed `lookup_into()` to write into caller's buffer
- Preserved buffer capacity across `clear()` calls

## CPU Profiling

### Flamegraphs

Visualize where time is spent:

```bash
# Install flamegraph
cargo install flamegraph

# Generate flamegraph
sudo cargo flamegraph --bench matchy_bench

# Opens: flamegraph.svg
```

Flamegraphs show:
- Which functions take the most time (wider = more time)
- Call stack relationships (parent/child)
- Hot paths through your code

### Perf on Linux

```bash
# Record performance data
perf record --call-graph dwarf cargo bench

# View report
perf report
```

### Instruments on macOS

```bash
# Build with debug symbols
cargo build --release

# Profile with Instruments
xcrun xctrace record --template 'Time Profiler' \
  --output profile.trace \
  --launch target/release/matchy bench database.mxy

# Open in Instruments
open profile.trace
```

## Performance Testing Workflow

When optimizing:

1. **Establish baseline**:
   ```bash
   cargo bench -- --save-baseline before
   ```

2. **Make changes**

3. **Compare results**:
   ```bash
   cargo bench -- --baseline before
   ```

4. **Profile allocations**:
   ```bash
   cargo bench --bench query_profile --features dhat-heap
   ```

5. **Profile CPU** (if needed):
   ```bash
   sudo cargo flamegraph --bench matchy_bench
   ```

6. **Validate improvements**:
   - Check allocation counts didn't increase
   - Verify throughput improved (or stayed same)
   - Run full test suite: `cargo test`

## See Also

- [Performance Guide](../guide/performance.md) - Performance characteristics
- [CLI Bench Command](../commands/matchy-bench.md) - Command-line benchmarking
- [Testing](testing.md) - Correctness testing
