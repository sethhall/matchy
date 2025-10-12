# Persistent Benchmark Storage

## Problem
By default, Criterion stores benchmark data in `target/criterion/`. When you run `cargo clean`, all benchmark baselines are lost.

## Solution
We use a **symlink** to store benchmark data persistently:

```
target/criterion -> ../benchmarks/criterion_data
```

## Benefits
✅ Benchmark data survives `cargo clean`  
✅ Works transparently with all Criterion commands  
✅ No script modifications needed for normal benchmarking  
✅ All data in one place: `benchmarks/`

## How It Works

When you run `./scripts/benchmark_baseline.sh` or `./scripts/benchmark_compare.sh`, the scripts automatically:

1. Create `benchmarks/criterion_data/` if it doesn't exist
2. Create symlink `target/criterion -> ../benchmarks/criterion_data`
3. All Criterion data is now persistent!

## Manual Setup

If you want to set this up manually:

```bash
mkdir -p benchmarks/criterion_data
mkdir -p target
rm -rf target/criterion  # Remove if exists
ln -s ../benchmarks/criterion_data target/criterion
```

## Directory Structure

```
matchy/
├── target/
│   └── criterion -> ../benchmarks/criterion_data  (symlink)
└── benchmarks/
    ├── criterion_data/                    (actual data)
    │   ├── build/
    │   ├── match/
    │   │   └── p100_t1000/
    │   │       └── medium/
    │   │           ├── new/
    │   │           ├── pre-optimization/  (baseline)
    │   │           └── report/
    │   └── ...
    ├── baseline_pre-optimization_YYYYMMDD/  (timestamped backup)
    └── comparison_YYYYMMDD/                 (comparison metadata)
```

## Cargo Clean

After `cargo clean`:
- ✅ `benchmarks/criterion_data/` still exists with all data
- ❌ `target/criterion` symlink is removed
- Scripts will recreate the symlink automatically on next run

## Troubleshooting

### "Baseline not found" after cargo clean
The symlink was removed. Just run the comparison script again - it will recreate it:
```bash
./scripts/benchmark_compare.sh pre-optimization
```

### Want to start fresh?
Delete the persistent data:
```bash
rm -rf benchmarks/criterion_data
# Next benchmark will create it fresh
```

### Check if symlink is set up
```bash
ls -la target/criterion
# Should show: target/criterion -> ../benchmarks/criterion_data
```

## Why This Works

1. **Symlinks are transparent** - Criterion doesn't know or care that it's writing through a symlink
2. **Relative path** - `../benchmarks/criterion_data` works from `target/` directory
3. **Git-friendly** - Symlink itself can be committed, data directory is in `.gitignore`
4. **Cross-platform** - Works on macOS and Linux (Windows requires admin for symlinks)
