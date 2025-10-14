# Fuzzing Guide

Fuzz testing for Matchy.

## Setup

```bash
# Install cargo-fuzz
cargo install cargo-fuzz

# Initialize fuzzing
cargo fuzz init
```

## Running Fuzzers

```bash
# List fuzz targets
cargo fuzz list

# Run specific target
cargo fuzz run fuzz_glob_matching

# Run with jobs
cargo fuzz run fuzz_glob_matching -- -jobs=4
```

## Fuzz Targets

See [Fuzz Targets](fuzz-targets.md) for details.

## Corpus Management

```bash
# Add to corpus
echo "test input" > fuzz/corpus/fuzz_target/input

# Minimize corpus
cargo fuzz cmin fuzz_target
```

## See Also

- [Fuzz Targets](fuzz-targets.md)
- [Testing](testing.md)
