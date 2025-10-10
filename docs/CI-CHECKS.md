# CI Checks Reference

This document describes how to run all CI checks locally before pushing code, preventing CI failures.

## Quick Start

### Run ALL CI checks (recommended before every push)
```bash
make ci-local
```

This runs the same checks as CI:
- ✅ Code formatting check
- ✅ Clippy lints (warnings as errors)
- ✅ Documentation build (warnings as errors)
- ✅ All Rust tests
- ✅ Doc tests

### Quick feedback loop (fast, run frequently)
```bash
make ci-quick
```

This runs only the fast checks:
- ✅ Code formatting check
- ✅ Clippy lints

## Individual Checks

### Using Make (recommended)

```bash
# Formatting
make fmt              # Check formatting (read-only)
cargo fmt --all       # Fix formatting

# Clippy
make clippy           # Run clippy with -D warnings

# Documentation
make check-docs       # Build docs with warnings as errors
make docs             # Build docs and open in browser

# Tests
make test-rust        # Run all Rust tests
make test-doc         # Run doc tests only
```

### Using Cargo (also works)

We've set up convenient cargo aliases in `.cargo/config.toml`:

```bash
# Check formatting
cargo check-fmt       # Same as: cargo fmt --all -- --check
cargo fmt-fix         # Fix formatting issues

# Check clippy
cargo check-clippy    # Same as: cargo clippy --all-targets --all-features -- -D warnings
cargo clippy-fix      # Auto-fix clippy issues (when possible)

# Check docs
cargo check-docs      # Build docs with warnings as errors

# Tests
cargo test-all        # Run all tests with verbose output
cargo test-doc        # Run doc tests
cargo test-int        # Run integration tests
```

## What CI Actually Runs

Our GitHub Actions CI (`.github/workflows/ci.yml`) runs:

1. **Formatting** (`fmt` job)
   ```bash
   cargo fmt --all -- --check
   ```

2. **Clippy** (`clippy` job)
   ```bash
   cargo clippy --all-targets --all-features -- -D warnings
   ```

3. **Documentation** (`docs` job)
   ```bash
   RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --document-private-items
   ```

4. **Tests** (`test` job)
   ```bash
   cargo test --verbose
   cargo test --test integration_tests --verbose
   ```

5. **Doc Tests** (part of `test` job)
   ```bash
   cargo test --doc
   ```

## Common Issues & Fixes

### Formatting Issues
```bash
# Problem: CI fails with "code is not formatted"
# Fix: Run cargo fmt
cargo fmt --all

# Or use our alias
cargo fmt-fix
```

### Clippy Warnings
```bash
# Problem: CI fails with clippy warnings
# Fix: Run clippy and address warnings
cargo clippy --all-targets --all-features -- -D warnings

# Some issues can be auto-fixed
cargo clippy-fix
```

### Documentation Warnings
```bash
# Problem: CI fails with rustdoc warnings
# Common issues:
# - Unresolved doc links (use `[like this]` -> `\[like this\]`)
# - Bare URLs (use <https://...> instead of https://...)
# - Unclosed HTML tags in docs (use backticks for generic types)

# Check locally with warnings as errors:
make check-docs

# Or:
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --document-private-items
```

### Test Failures
```bash
# Run tests with more output
cargo test -- --nocapture

# Run specific test
cargo test test_name -- --nocapture

# Run with backtrace
RUST_BACKTRACE=1 cargo test
```

## Pre-Commit Workflow

Recommended workflow before every commit:

```bash
# 1. Make your changes
vim src/some_file.rs

# 2. Fix formatting automatically
cargo fmt --all

# 3. Run quick checks (fast feedback)
make ci-quick

# 4. If quick checks pass, run full CI locally
make ci-local

# 5. If all checks pass, commit and push!
git add -A
git commit -m "Your change description"
git push
```

## Git Hook (Optional)

To automatically run checks before every push, create `.git/hooks/pre-push`:

```bash
#!/bin/sh
# Pre-push hook to run CI checks

echo "Running CI checks before push..."
make ci-local

if [ $? -ne 0 ]; then
    echo ""
    echo "❌ CI checks failed! Fix issues before pushing."
    echo "   Or use 'git push --no-verify' to skip (not recommended)"
    exit 1
fi

echo "✅ All checks passed! Pushing..."
```

Then make it executable:
```bash
chmod +x .git/hooks/pre-push
```

## Continuous Improvement

This project maintains high code quality standards:

- **Zero warnings policy**: All compiler, clippy, and rustdoc warnings must be fixed
- **100% test pass rate**: All tests must pass before merging
- **Formatted code**: All code must be formatted with `cargo fmt`

Run `make ci-local` frequently to catch issues early!

## Links

- [CI Workflow](.github/workflows/ci.yml) - The actual GitHub Actions configuration
- [WARP.md](WARP.md) - Full development guide
- [README.md](README.md) - Project overview
- [DEVELOPMENT.md](DEVELOPMENT.md) - Architecture and design details
