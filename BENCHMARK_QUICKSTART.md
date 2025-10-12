# Benchmark Quick Start

## TL;DR - Do This Now!

```bash
# 1. Capture baseline (10 minutes)
./scripts/benchmark_baseline.sh pre-optimization

# 2. Make your optimizations...

# 3. Compare results (10 minutes)
./scripts/benchmark_compare.sh pre-optimization

# 4. View results
open target/criterion/report/index.html
```

---

## What I've Set Up For You

### 📊 Three Helper Scripts

1. **`benchmark_baseline.sh`** - Captures baseline performance
   - Runs clean build
   - Executes all benchmarks with statistical rigor
   - Saves results with metadata (git commit, system info)
   - Creates timestamped backup
   - Offers to create git tag

2. **`benchmark_compare.sh`** - Compares current code vs baseline
   - Shows % improvement/regression
   - Statistical significance testing
   - Saves comparison metadata
   - Opens HTML report

3. **`benchmark_report.sh`** - Shows all baselines and comparisons
   - Lists captured baselines with metadata
   - Shows recent comparisons
   - System info
   - Quick action menu

### 📁 Directory Structure

```
matchy/
├── scripts/               # Helper scripts (executable)
├── benchmarks/            # Saved baselines and comparisons
│   ├── README.md          # Benchmarking guide
│   ├── baseline_*/        # Timestamped baselines
│   └── comparison_*/      # Timestamped comparisons
├── benches/
│   └── matchy_bench.rs    # Comprehensive benchmark suite (already existed)
├── BENCHMARKING_STRATEGY.md          # Detailed strategy
├── PERFORMANCE_OPTIMIZATIONS.md      # BurntSushi analysis
└── BENCHMARK_QUICKSTART.md           # This file
```

### 🎯 What Gets Benchmarked

Your existing `matchy_bench.rs` already covers:

1. **Build Performance** - Time to construct automaton
2. **Match Performance** ⭐ - Throughput (MB/s) - MOST IMPORTANT
3. **Serialization** - Save time
4. **Load Performance** ⭐ - mmap time - YOUR COMPETITIVE ADVANTAGE
5. **Memory Efficiency** - Bytes per pattern
6. **Realistic Workload** - Batch processing
7. **Case Sensitivity** - Overhead measurement

---

## Recommended Workflow

### Before Optimization

```bash
# 1. Commit or stash your current work
git stash

# 2. Capture baseline
./scripts/benchmark_baseline.sh pre-optimization
# - Follow prompts
# - Create git tag when offered
# - Review HTML report

# 3. Restore your work
git stash pop

# You now have a baseline to compare against!
```

### After Each Optimization

```bash
# 1. Implement optimization (e.g., loop unrolling)

# 2. Run comparison
./scripts/benchmark_compare.sh pre-optimization

# 3. Check results
# Look for:
#   - Match performance improvement (target varies by optimization)
#   - No regression in load time (< 5%)
#   - Statistical significance (p < 0.05)

# 4. If successful
git add -A
git commit -m "optimization: loop unrolling in find_transition

Results vs baseline:
- Match throughput: +12% (p < 0.001)
- Load time: +1.2% (p = 0.45, not significant)
- Memory: unchanged
"

# 5. If unsuccessful
git reset --hard  # Or fix issues and iterate
```

---

## Reading Criterion Output

### Example Output

```
match/p100_t1000/medium
    time:   [2.1234 ms 2.1456 ms 2.1678 ms]
    thrpt:  [461.23 MiB/s 466.01 MiB/s 470.82 MiB/s]
    change: [-12.45% -10.23% -8.01%] (p < 0.001 < 0.05)
    Performance has improved! ✅
```

**What this means:**
- **Time**: Lower is better
- **Throughput (thrpt)**: Higher is better (this is more intuitive!)
- **Change**: Negative % = improvement
- **p < 0.05**: Statistically significant (not random noise)

### What to Look For

✅ **Success indicators:**
- Match throughput increased
- Change is negative %
- p < 0.05 (significant)
- Load time unchanged or faster

❌ **Warning signs:**
- Load time increased (regression!)
- Memory increased significantly
- p > 0.05 (might be noise)

---

## Quick Commands

```bash
# View all baselines
./scripts/benchmark_report.sh

# Run just match benchmarks (faster)
cargo bench --bench matchy_bench match

# Run specific test
cargo bench --bench matchy_bench match/p100_t1000/medium

# Increase sample size if variance is high
cargo bench --bench matchy_bench -- --sample-size 200

# View HTML report
open target/criterion/report/index.html

# Check tests still pass
cargo test
```

---

## Expected Improvements by Phase

### Phase 1: Loop Unrolling (Easy - No Format Change)
- **Match**: +5-15%
- **Load**: unchanged
- **Memory**: unchanged
- **Time**: 1-2 days

### Phase 2: Dense/Sparse/One Encoding (Medium - Format Change)
- **Match**: +30-50% 🎯
- **Build**: -5-10% (acceptable)
- **Memory**: -10-20%
- **Time**: 1 week

### Phase 3: Byte Classes (Medium - Format Change)
- **Match**: +10-20%
- **Memory**: -20-40% 🎯
- **Load**: unchanged
- **Time**: 1 week

---

## System Preparation Tips

For consistent benchmarks:

```bash
# Close apps
# - Docker Desktop
# - IDEs (VSCode, etc.)
# - Browsers with many tabs
# - Slack, Discord, etc.

# macOS specific
# Temporarily disable Spotlight indexing
sudo mdutil -a -i off

# Check what's using CPU
top -o cpu

# After benchmarking, re-enable Spotlight
sudo mdutil -a -i on

# Ensure plugged in (no battery throttling)
pmset -g batt
```

---

## Troubleshooting

### "Baseline not found"
```bash
# List what's available
./scripts/benchmark_report.sh

# Create baseline if missing
./scripts/benchmark_baseline.sh pre-optimization
```

### "High variance (> 10%)"
```bash
# Close more apps, try overnight
cargo bench --bench matchy_bench -- --sample-size 200 --warm-up-time 10
```

### "Unexpected results"
```bash
# Profile to see what's actually running
cargo install flamegraph
cargo flamegraph --bench matchy_bench -- --bench

# Verify tests pass
cargo test

# Check for black_box usage in benchmarks
grep -n "black_box" benches/matchy_bench.rs
```

---

## Files Created

I've created these files for you:

1. ✅ `scripts/benchmark_baseline.sh` - Capture baseline
2. ✅ `scripts/benchmark_compare.sh` - Compare vs baseline  
3. ✅ `scripts/benchmark_report.sh` - View all results
4. ✅ `benchmarks/README.md` - Benchmarking guide
5. ✅ `BENCHMARKING_STRATEGY.md` - Detailed strategy
6. ✅ `PERFORMANCE_OPTIMIZATIONS.md` - BurntSushi analysis
7. ✅ `BENCHMARK_QUICKSTART.md` - This file

All scripts are executable and ready to use!

---

## Next Steps

### Right Now:
```bash
./scripts/benchmark_baseline.sh pre-optimization
```

This will:
- Take ~10 minutes
- Create a baseline for comparison
- Give you current performance numbers
- Let you know if everything is working

### After Baseline:
1. Review `PERFORMANCE_OPTIMIZATIONS.md` for implementation details
2. Start with loop unrolling (easiest, no format change)
3. Use `benchmark_compare.sh` after each change
4. Document results in git commits

---

## Questions?

- **Benchmarking details**: See `BENCHMARKING_STRATEGY.md`
- **What to optimize**: See `PERFORMANCE_OPTIMIZATIONS.md`
- **How benchmarks work**: See `benchmarks/README.md`
- **Criterion docs**: https://bheisler.github.io/criterion.rs/book/

Good luck with the optimizations! 🚀
