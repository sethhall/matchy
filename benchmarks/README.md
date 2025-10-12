# Matchy Benchmarking

This directory contains baseline performance data and comparison results for the matchy library.

## Quick Start

### 1. Capture Baseline (Do This First!)

Before making any optimizations, capture a baseline:

```bash
./scripts/benchmark_baseline.sh pre-optimization
```

This will:
- Run a clean build
- Execute all benchmarks (~5-10 minutes)
- Save results with metadata
- Offer to create a git tag

### 2. Implement Optimizations

Make your code changes...

### 3. Compare Performance

```bash
./scripts/benchmark_compare.sh pre-optimization
```

This shows you if your changes improved performance and by how much.

### 4. View Reports

```bash
# Summary of all baselines and comparisons
./scripts/benchmark_report.sh

# Detailed HTML report
open target/criterion/report/index.html
```

## Directory Structure

```
benchmarks/
├── README.md                           # This file
├── baseline_pre-optimization_YYYYMMDD/ # Baseline captures
│   ├── metadata.json                   # System info, git commit, etc.
│   └── <criterion-data>/               # Raw benchmark data
└── comparison_YYYYMMDD/                # Comparison results
    └── metadata.json                   # Comparison metadata
```

## Key Metrics

### Match Performance (Most Important)
- **What**: Throughput of pattern matching in MB/s
- **Target**: 30-50% improvement from state encoding optimization
- **Command**: `cargo bench --bench matchy_bench match`

### Load Performance (Critical to Preserve)
- **What**: Time to mmap and initialize database
- **Target**: No regression (< 5% variance)
- **Command**: `cargo bench --bench matchy_bench load`

### Memory Efficiency
- **What**: Bytes per pattern in serialized format
- **Target**: 20-40% reduction with byte classes
- **Command**: `cargo bench --bench matchy_bench memory_efficiency`

## Interpreting Results

Criterion output shows comparisons like:

```
change: -32.45% (p < 0.001)  ← 32% faster (good!)
change: +5.23% (p = 0.12)    ← 5% slower, but not significant
```

- **Negative % = faster** ✅
- **Positive % = slower** ❌
- **p < 0.05 = statistically significant**

## Best Practices

1. **Always capture baseline before starting work**
2. **Close applications during benchmarking** (Docker, IDEs, browsers)
3. **Plug in power** (avoid battery throttling)
4. **Check for regressions in load time** (your competitive advantage!)
5. **Document results in commit messages**

## Troubleshooting

### High Variance (> 10%)
- Close more applications
- Run overnight when system is idle
- Increase sample size: `cargo bench -- --sample-size 200`

### Baseline Not Found
- Ensure you ran `./scripts/benchmark_baseline.sh` first
- Check `target/criterion/` directory exists
- List available: `./scripts/benchmark_report.sh`

### Unexpected Results
- Verify `black_box()` usage in benchmarks
- Profile with: `cargo flamegraph --bench matchy_bench`
- Run tests: `cargo test` to ensure correctness

## Advanced Usage

### Run Specific Benchmark

```bash
# Just match benchmarks
cargo bench --bench matchy_bench match

# Specific configuration
cargo bench --bench matchy_bench match/p100_t1000/medium

# With custom parameters
cargo bench --bench matchy_bench -- --sample-size 200 --warm-up-time 5
```

### Compare Against Git Tag

```bash
git checkout baseline-pre-optimization-abc123
cargo bench -- --save-baseline v0.5.2
git checkout main
cargo bench -- --baseline v0.5.2
```

### Export Results

```bash
# JSON format (for automated analysis)
cargo bench --bench matchy_bench -- --output-format json > results.json

# Plot results
# (Criterion automatically generates plots in target/criterion/report/)
```

## Optimization Phases

### Phase 1: Loop Unrolling
- **Expected**: 5-15% improvement in match performance
- **Focus**: `match` benchmarks
- **No format changes**

### Phase 2: State Encoding
- **Expected**: 30-50% improvement in match performance
- **Focus**: All benchmarks (especially `match` and `memory_efficiency`)
- **Format change required**

### Phase 3: Byte Classes
- **Expected**: 10-20% match improvement, 20-40% memory reduction
- **Focus**: `match` and `memory_efficiency` benchmarks
- **Format change required**

## See Also

- [BENCHMARKING_STRATEGY.md](../BENCHMARKING_STRATEGY.md) - Detailed strategy
- [PERFORMANCE_OPTIMIZATIONS.md](../PERFORMANCE_OPTIMIZATIONS.md) - Optimization techniques
- [Criterion.rs docs](https://bheisler.github.io/criterion.rs/book/) - Official documentation
