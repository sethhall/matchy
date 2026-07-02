---
name: ffi
description: C ABI, generated headers, MaxMind compatibility, and ownership rules.
triggers:
  - "C API"
  - "FFI"
  - "cbindgen"
  - "matchy.h"
  - "MaxMind"
  - "MMDB"
edges:
  - target: context/architecture.md
    condition: when the Rust API flow behind the C wrapper is needed
  - target: context/binary-format.md
    condition: when C results expose data offsets or MMDB-compatible data
  - target: context/conventions.md
    condition: when checking project-wide safety and testing conventions
  - target: patterns/change-c-api.md
    condition: when adding or changing exported C symbols, structs, constants, or tests
last_updated: 2026-07-02
---

# FFI

## Surfaces
- Main C API: `crates/matchy/src/c_api/matchy.rs`.
- MaxMind compatibility: `crates/matchy/src/c_api/maxminddb_compat.rs` and `mmdb_varargs.c`.
- Generated public header: `crates/matchy/include/matchy/matchy.h`; never edit directly.
- Hand-shipped MaxMind header: `crates/matchy/include/matchy/maxminddb.h`.
- Build glue: `crates/matchy/build.rs` and `crates/matchy/cbindgen.toml`.

## Contract
- Handles are opaque: `matchy_builder_t`, `matchy_t`, and extractor handles wrap internal Rust structs.
- Functions return `MATCHY_SUCCESS`, negative `MATCHY_ERROR_*` codes, null pointers, or by-value result structs instead of Rust `Result`.
- Inputs must be checked for null before `CStr::from_ptr`, raw slice creation, or handle casts.
- Returned strings must be freed with `matchy_free_string`; result/data lists/matches have dedicated free functions.
- `matchy_builder_build` allocates with `libc::malloc` so C callers can `free()`.
- Databases are immutable; update by rebuilding, atomically replacing, and reopening/reloading.

## Generated Header Rules
- `cargo build --release -p matchy` runs `build.rs`, creates `crates/matchy/include/matchy/matchy.h`, and post-processes `sockaddr` spelling.
- `cbindgen.toml` excludes `MMDB_*` compatibility symbols from `matchy.h` because they belong to `maxminddb.h`.
- Changing exported Rust `#[repr(C)]` structs/functions changes generated ABI and must be treated as a C API signature change.

## Known Gap
- The module docs promise panic catching at FFI boundaries, but current exported functions do not use `std::panic::catch_unwind`. Add it before relying on the docs for panic containment.
