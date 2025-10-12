# Benchmarking Strategy for Performance Optimization

This document describes the process for capturing baseline performance and comparing optimization implementations.

## Quick Start

```bash
# 1. Capture baseline (run this NOW before any changes)
./scripts/benchmark_baseline.sh

# 2. After implementing optimizations, compare
./scripts/benchmark_compare.sh <baseline-name>

# 3. View results
./scripts/benchmark_report.sh
```

---

## Overview

We use **Criterion.rs** for statistical benchmarking with three key features:
1. **Baseline comparison** - Compare current code against saved baselines
2. **Statistical analysis** - Detects real changes vs noise
3. **HTML reports** - Visual graphs for analysis

---

## Baseline Capture Process

### Step 1: Clean Build

Always start with a clean release build to ensure consistent results:

```bash
cargo clean
cargo build --release
```

### Step 2: System Preparation

**Critical**: Minimize system noise during benchmarking:

```bash
# Close unnecessary applications
# Disable Spotlight indexing temporarily
sudo mdutil -a -i off

# Ensure machine is plugged in (no battery throttling)
# Disable Wi-Fi/Bluetooth if possible
# Close Docker, VMs, etc.
```

### Step 3: Run Baseline Benchmarks

```bash
# Run all benchmarks and save as baseline
cargo bench --bench matchy_bench -- --save-baseline pre-optimization

# This creates: target/criterion/<test-name>/pre-optimization/
```

**Expected duration**: ~5-10 minutes for full suite.

### Step 4: Backup Results

```bash
# Create timestamped backup
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
cp -r target/criterion benchmarks/baseline_${TIMESTAMP}

# Save metadata
cat > benchmarks/baseline_${TIMESTAMP}/metadata.json <<EOF
{
  "timestamp": "${TIMESTAMP}",
  "git_commit": "$(git rev-parse HEAD)",
  "git_branch": "$(git branch --show-current)",
  "rustc_version": "$(rustc --version)",
  "system": "$(uname -a)",
  "cpu_info": "$(sysctl -n machdep.cpu.brand_string)"
}
EOF
```

---

## Key Metrics to Track

### 1. Build Performance
**What it measures**: Time to construct AC automaton from patterns

**Key scenarios**:
- 10 patterns (small)
- 100 patterns (medium)
- 1000 patterns (large)

**Expected baselines** (rough estimates):
- 10 patterns: ~50-100 µs
- 100 patterns: ~500-1000 µs
- 1000 patterns: ~5-10 ms

**Target improvement**: 5-10% (not the hot path)

---

### 2. Match Performance ⭐ **MOST IMPORTANT**
**What it measures**: Throughput of pattern matching (MB/s)

**Key scenarios**:
- Small patterns (10), small text (100 bytes)
- Medium patterns (100), medium text (1KB)
- Large patterns (1000), large text (10KB)
- Match rate variations (none/low/medium/high)

**Expected baselines**:
- Low match rate: ~100-500 MB/s
- High match rate: ~50-200 MB/s (more matches = more work)

**Target improvement**: 30-50% (from dense/sparse/one encoding)

**What to look for**:
- Linear scaling with text size
- Sublinear scaling with pattern count (good AC property)
- Match rate should affect throughput predictably

---

### 3. Load Performance ⭐ **KEY DIFFERENTIATOR**
**What it measures**: Time to mmap and initialize database

**Expected baselines**:
- Should be near-constant regardless of pattern count
- Typically < 1ms even for 5000 patterns

**Target improvement**: Should stay flat (don't regress!)

**This is your competitive advantage** - heap-based implementations can't match this.

---

### 4. Memory Efficiency
**What it measures**: Bytes per pattern in serialized format

**Expected baselines**:
- Currently: ~40-80 bytes per pattern (varies by complexity)
- With byte classes: 20-40% reduction possible

**Target improvement**: 20-40% reduction with byte class optimization

---

### 5. Case Sensitivity Overhead
**What it measures**: Performance difference between case-sensitive and case-insensitive matching

**Expected baselines**:
- Case-insensitive should be ~10-20% slower (due to normalization)

**Target improvement**: Keep overhead minimal

---

## Running Comparisons

### After Implementing Optimizations

```bash
# Run benchmarks against baseline
cargo bench --bench matchy_bench -- --baseline pre-optimization

# Criterion will show comparison like:
# "change: -32.45% (p < 0.001)"  <- 32% faster!
# "change: +5.23% (p = 0.12)"    <- 5% slower, but not statistically significant
```

### Interpreting Results

**Statistical significance** (p-value):
- `p < 0.05`: Change is real, not noise
- `p > 0.05`: Change might be noise

**Performance change**:
- Negative % = faster (good!)
- Positive % = slower (bad!)

**What to investigate**:
- Changes > 5% (statistically significant)
- Regressions in load time (critical!)
- Memory increases > 10%

---

## Detailed Benchmark Analysis

### HTML Reports

Criterion generates detailed HTML reports:

```bash
open target/criterion/report/index.html
```

**What to look for**:
1. **Violin plots**: Distribution of timings (should be tight, not spread)
2. **Line graphs**: Linear scaling with input size (good)
3. **Comparison charts**: Before/after with confidence intervals

### Manual Analysis

For deeper investigation:

```bash
# Run specific benchmark with verbose output
cargo bench --bench matchy_bench match -- --verbose

# Profile a specific test
cargo bench --bench matchy_bench match/p100_t1000/medium -- --profile-time=10
```

### Checking for Regressions

Create a script to extract key metrics:

```bash
# scripts/extract_metrics.sh
#!/bin/bash
BASELINE=$1

echo "=== Build Performance ==="
rg "time:.*\[" target/criterion/build/${BASELINE}/estimates.json || echo "No data"

echo "=== Match Throughput ==="
rg "throughput:.*" target/criterion/match/${BASELINE}/estimates.json || echo "No data"

echo "=== Load Time ==="
rg "time:.*\[" target/criterion/load/${BASELINE}/estimates.json || echo "No data"
```

---

## Optimization-Specific Benchmarks

### Loop Unrolling (Phase 1)

**Focus areas**:
- `match` benchmarks (all variants)
- Should see 5-15% improvement

**Run**:
```bash
cargo bench --bench matchy_bench match -- --baseline pre-optimization
```

**Expected**: Improvement in all match scenarios, especially with medium pattern counts (100-1000).

---

### Dense/Sparse/One Encoding (Phase 2)

**Focus areas**:
- `match` benchmarks (BIG improvements expected)
- `build` benchmarks (small overhead acceptable)
- `memory_efficiency` (should improve or stay flat)

**Run**:
```bash
cargo bench --bench matchy_bench -- --baseline pre-optimization
```

**Expected**:
- Match: 30-50% improvement (most states use "one" encoding)
- Build: < 10% slower (extra classification work)
- Memory: 10-20% smaller (inline single edges)

---

### Byte Class Reduction (Phase 2)

**Focus areas**:
- `memory_efficiency` (BIG improvements)
- `match` benchmarks (moderate improvements)
- `build` benchmarks (negligible impact)

**Run**:
```bash
cargo bench --bench matchy_bench -- --baseline pre-optimization
```

**Expected**:
- Memory: 20-40% smaller for dense states
- Match: 10-20% faster (better cache utilization)
- Build: < 5% overhead

---

## Micro-benchmarks for Hot Paths

Add focused benchmarks for critical functions:

```rust
// In benches/matchy_bench.rs

fn bench_transition_lookup(c: &mut Criterion) {
    let mut group = c.benchmark_group("transition_lookup");
    
    // Build a test automaton
    let patterns = vec!["test", "testing", "test123"];
    let pg = Paraglob::build_from_patterns(&patterns, MatchMode::CaseSensitive).unwrap();
    
    group.bench_function("find_transition", |b| {
        b.iter(|| {
            // Call the hot path directly
            // This helps isolate the optimization
            black_box(pg.automaton.find_transition(0, b't'));
        });
    });
    
    group.finish();
}
```

---

## Continuous Monitoring

### Git Integration

Tag important baselines:

```bash
# After capturing baseline
git tag -a baseline-v0.5.2 -m "Performance baseline before optimization work"
git push origin baseline-v0.5.2

# Later, compare against tagged version
git checkout baseline-v0.5.2
cargo bench --bench matchy_bench -- --save-baseline v0.5.2
git checkout main
cargo bench --bench matchy_bench -- --baseline v0.5.2
```

### Performance History

Track key metrics over time:

```bash
# scripts/record_performance.sh
#!/bin/bash
COMMIT=$(git rev-parse --short HEAD)
DATE=$(date +%Y-%m-%d)

cargo bench --bench matchy_bench -- --save-baseline ${COMMIT}

# Extract key metrics to CSV
echo "${DATE},${COMMIT},$(extract_match_throughput),$(extract_load_time)" \
    >> benchmarks/history.csv
```

---

## Troubleshooting

### High Variance in Results

**Symptoms**: Wide confidence intervals, inconsistent results

**Solutions**:
1. Increase sample size: `cargo bench -- --sample-size 200`
2. Increase warm-up: `cargo bench -- --warm-up-time 5`
3. Check system load: `top`, `Activity Monitor`
4. Run overnight when system is idle

### Unrealistic Results

**Symptoms**: Benchmarks too fast (< 1µs) or show 1000% improvements

**Solutions**:
1. Check `black_box()` usage - prevents compiler from optimizing away work
2. Verify actual work is being done
3. Profile with `cargo flamegraph` to see what's actually running

### Regressions After Optimization

**Symptoms**: Some benchmarks faster, others slower

**Solutions**:
1. Isolate the regression with micro-benchmarks
2. Profile both versions: `cargo flamegraph --bench matchy_bench`
3. Check if optimization helps some cases but hurts others
4. Consider making optimization conditional based on input characteristics

---

## Final Checklist

Before starting optimization work:

- [ ] Capture baseline with `cargo bench -- --save-baseline pre-optimization`
- [ ] Back up results to `benchmarks/baseline_YYYYMMDD_HHMMSS/`
- [ ] Record metadata (git commit, system info)
- [ ] Verify all benchmarks pass
- [ ] Check that variance is reasonable (< 5% typically)
- [ ] Tag git commit: `git tag baseline-pre-opt`

After each optimization:

- [ ] Run comparison: `cargo bench -- --baseline pre-optimization`
- [ ] Check for statistical significance (p < 0.05)
- [ ] Verify no regressions in critical areas (load time!)
- [ ] Document results in commit message
- [ ] Update PERFORMANCE_OPTIMIZATIONS.md with actual results

---

## Expected Timeline

**Baseline capture**: 10 minutes
**Analysis**: 30 minutes
**Per optimization**: 
- Implementation: varies
- Benchmarking: 10 minutes
- Analysis: 20 minutes
- Iteration: 2-3 cycles

**Total for all optimizations**: 2-3 weeks including testing

---

## Success Criteria

An optimization is successful if:

1. **Match throughput improves by target %** (varies by optimization)
2. **Load time does NOT regress** (within 5%)
3. **Memory stays same or improves** (no > 10% increases)
4. **All tests still pass**: `cargo test`
5. **Statistical significance**: p < 0.05

If all criteria met: merge to main and tag new baseline.
If not: iterate or revert.
