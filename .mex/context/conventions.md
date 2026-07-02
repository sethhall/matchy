---
name: conventions
description: How code is written in this project — naming, structure, patterns, and style. Load when writing new code or reviewing existing code.
triggers:
  - "convention"
  - "pattern"
  - "naming"
  - "style"
  - "how should I"
  - "what's the right way"
edges:
  - target: context/architecture.md
    condition: when a convention depends on understanding the system structure
  - target: context/binary-format.md
    condition: when conventions involve offsets, repr(C), validation, or mmap safety
  - target: context/ffi.md
    condition: when conventions involve exported C functions or generated headers
  - target: context/processing.md
    condition: when conventions involve extraction, line scanning, or parallel workers
last_updated: 2026-07-02
---

# Conventions

## Naming
- Rust functions, methods, modules, and files use `snake_case`; public types use `PascalCase`; constants use `UPPER_SNAKE_CASE`.
- CLI command implementations are `*_cmd.rs` files exporting `cmd_*` functions, re-exported from `crates/matchy/src/bin/commands/mod.rs`.
- Internal crates are prefixed `matchy-*` and expose focused builders/readers such as `IpTreeBuilder`, `LiteralHashBuilder`, and `ParaglobBuilder`.
- C ABI items use C-style names: opaque handles such as `matchy_t`, functions such as `matchy_open`, and integer constants such as `MATCHY_ERROR_INVALID_PARAM`.
- Format structs use field names ending in `_offset`, `_size`, `_count`, or `_len` to clarify serialized meaning.

## Structure
- `crates/matchy/src/lib.rs` is the public API surface and re-export hub; keep core implementations in crate modules or component crates.
- `crates/matchy-format` owns `.mxy` assembly; canonical Paraglob `#[repr(C)]` structs live in `crates/matchy-paraglob/src/offset_format.rs`.
- CLI dispatch lives in `crates/matchy/src/bin/matchy.rs`; command behavior lives under `crates/matchy/src/bin/commands/`; match pipeline helpers live under `crates/matchy/src/bin/match_processor/`.
- Public reusable batch APIs live in `crates/matchy/src/processing/`; do not duplicate them in CLI-only code.
- C API code lives under `crates/matchy/src/c_api/`; C tests live in `crates/matchy/tests/test_c_api.c`, `crates/matchy/tests/test_c_api_extensions.c`, and `crates/matchy/tests/test_mmdb_compat.c`, and are run through the Makefile.
- Unit tests live beside implementation modules; CLI integration tests use `crates/matchy/tests/cli_tests.rs`.

## Patterns
Prefer offset-based serialized references:
```rust
// Correct
pub data_offset: u32

// Wrong
pub data: *const DataValue
```

Public APIs return `Result` or `Option<Result-like>` values, while CLI commands add context with `anyhow::Context`:
```rust
let db = Database::from(path)
    .open()
    .with_context(|| format!("Failed to load database: {}", path.display()))?;
```

C ABI functions validate before dereferencing and return codes/nulls:
```rust
if builder.is_null() || key.is_null() {
    return MATCHY_ERROR_INVALID_PARAM;
}
```

Use typed lookups after extraction so IPs avoid string parsing:
```rust
let result_opt = database.lookup_extracted(&item, data)?;
```

## Verify Checklist
Before presenting any code:
- [ ] Public Rust APIs have `///` docs and examples when useful.
- [ ] Serialized structs remain `#[repr(C)]`, offset-based, and covered by size/version validation.
- [ ] FFI functions validate null/UTF-8/path inputs before dereference and never expose Rust ownership ambiguously.
- [ ] CLI changes have `assert_cmd` coverage in `crates/matchy/tests/cli_tests.rs` or focused unit tests.
- [ ] Binary or validation changes run the relevant crate tests plus `cargo test --workspace`.
- [ ] C API changes run `cargo build --release -p matchy` and the relevant `make test-c`, `make test-c-ext`, or `make test-mmdb` target.
- [ ] `cargo fmt --all` and `cargo clippy --workspace --all-targets --all-features -- -D warnings` pass.
