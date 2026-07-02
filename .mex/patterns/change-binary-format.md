---
name: change-binary-format
description: Safely change .mxy, Paraglob, LiteralHash, MMDB metadata, or mmap-loaded structures.
triggers:
  - "binary format"
  - "repr(C)"
  - "ParaglobHeader"
  - "LiteralHash"
  - "metadata offset"
  - "validation"
edges:
  - target: context/binary-format.md
    condition: for layout, version, and loader invariants
  - target: context/decisions.md
    condition: before deciding whether a change is compatible or breaking
  - target: patterns/change-c-api.md
    condition: when offsets or data layout are exposed through FFI
last_updated: 2026-07-02
---

# Change Binary Format

## Context
Ask before changing `#[repr(C)]` fields or serialized layout. Canonical Paraglob structs live in `crates/matchy-paraglob/src/offset_format.rs`; `crates/matchy-format/src/offset_format.rs` re-exports them. Unified `.mxy` assembly is in `crates/matchy-format/src/mmdb_builder.rs`; loading and section detection are in `crates/matchy/src/database.rs`.

## Steps
1. Identify the affected format: MMDB tree/data metadata, Paraglob v5, LiteralHash v3, AC buffer, or IP tree records.
2. If struct fields, sizes, marker bytes, version constants, or C-visible layout change, stop and ask for approval.
3. Update the writer and reader together: builder layout, metadata offsets, loader detection, decode path, and validation path.
4. Increment the relevant version constant for breaking serialized layout changes.
5. Update size assertions and version checks near the canonical structs.
6. Add tests that cover new files and old-file behavior: either load successfully or fail gracefully.
7. Update `DEVELOPMENT.md` if the binary format contract changes.

## Gotchas
- `Database` stores self-referential readers into owned mmap/bytes; never let references derived from the backing slice escape.
- New `.mxy` files should write metadata offsets so loading does not scan the whole file.
- Offsets are relative to their documented section starts; IP data offsets are relative to the data section after the 16-byte tree separator.
- `DataValue::Timestamp` is a Matchy extension and standard MMDB readers will not understand it.
- Pattern-only Paraglob files and unified MMDB-compatible `.mxy` files are both loadable paths.

## Verify
- `cargo test -p matchy-paraglob`
- `cargo test -p matchy-literal-hash`
- `cargo test -p matchy-format`
- `cargo test -p matchy --test cli_tests`
- `cargo test --workspace`
- For C-visible changes: `cargo build --release -p matchy` and `make test`

## Debug
- Use `matchy validate <file>.mxy --level strict --verbose` after creating a test database.
- Inspect metadata with `matchy inspect <file>.mxy --json`.
- If loading is slow, check whether `pattern_section_offset` or `literal_section_offset` is missing and forcing separator scans.

## Update Scaffold
- [ ] Update `.mex/ROUTER.md` "Current Project State" if what's working/not built has changed
- [ ] Update any `.mex/context/` files that are now out of date
- [ ] If this is a new task type without a pattern, create one in `.mex/patterns/` and add to `INDEX.md`
