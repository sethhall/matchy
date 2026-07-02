---
name: setup
description: Dev environment setup and commands. Load when setting up the project for the first time or when environment issues arise.
triggers:
  - "setup"
  - "install"
  - "environment"
  - "getting started"
  - "how do I run"
  - "local development"
edges:
  - target: context/stack.md
    condition: when specific technology versions or library details are needed
  - target: context/architecture.md
    condition: when understanding how components connect during setup
  - target: context/ffi.md
    condition: when setup involves generated headers or C compatibility tests
  - target: context/processing.md
    condition: when setup involves running match/extract workflows or performance tests
last_updated: 2026-07-02
---

# Setup

## Prerequisites
- Rust toolchain with Rust `1.87` or newer.
- Cargo targets `wasm32-unknown-unknown` and `wasm32-wasip1` for full `make ci-local`.
- `clang` for Makefile-driven C API and MMDB compatibility tests.
- `mdbook` only when building `book/` documentation.

## First-time Setup
1. `cargo build`
2. `cargo test --workspace`
3. `cargo build --release -p matchy` to generate the C header and release library.
4. `make test` to run C API, extension, and MMDB compatibility tests.
5. `make ci-local` before pushing or committing release-sensitive changes.

## Environment Variables
- Required: none for normal build/test.
- Conditional: `RUSTFLAGS="-Z sanitizer=address"` with nightly when running sanitizer tests.
- Optional: `RUST_BACKTRACE=1` for failing tests.
- Optional: `RUST_LOG=debug` or `RUST_LOG=matchy=trace` for debug output.
- Optional/internal: `DOCS_RS` makes `build.rs` skip cbindgen on docs.rs.

## Common Commands
- `cargo build` - development build for the default `matchy` crate.
- `cargo build --release -p matchy` - optimized build, static/cdylib output, generated C header.
- `cargo test --workspace` - full Rust workspace tests.
- `cargo test -p matchy --test cli_tests` - CLI integration tests.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings` - lint as CI does.
- `cargo fmt --all` - format all Rust code.
- `make ci-local` - fmt, clippy, docs, wasm, Rust tests, doc tests, release build, and C tests.
- `cd book && mdbook build` - build user documentation.

## Common Issues
**Wrong build input format:** `cmd_build` warns or errors when text input looks like JSON/CSV/MISP; rerun with `--format json`, `--format csv`, or `--format misp`.
**CSV source fails:** build and match auto-build require an `entry` or `key` column; rename the indicator column before retrying.
**Auto-update open fails:** `.auto_update()` requires a database built with `--update-url` / `DatabaseBuilder::with_update_url`.
**Single huge file is slow in auto routing:** current tests document that a lone massive file may not chunk automatically; pass `--readers=1` or explicit `--threads` when diagnosing.
