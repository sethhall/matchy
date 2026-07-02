---
name: binary-format
description: Serialized .mxy/MMDB/Paraglob/LiteralHash layout, compatibility rules, and validation boundaries.
triggers:
  - "binary format"
  - ".mxy"
  - "mmap"
  - "offset"
  - "repr(C)"
  - "validation"
edges:
  - target: context/architecture.md
    condition: when you need the full build/open/query flow around serialized sections
  - target: context/decisions.md
    condition: when deciding whether a format change is compatible or breaking
  - target: context/ffi.md
    condition: when serialized offsets are exposed through C handles or MaxMind compatibility
  - target: patterns/change-binary-format.md
    condition: when editing format structs, version constants, metadata offsets, or validators
last_updated: 2026-07-02
---

# Binary Format

## Files and Ownership
- `crates/matchy-format/src/mmdb_builder.rs` assembles unified `.mxy` files from pre-encoded data offsets, IP entries, literal entries, and glob entries.
- `crates/matchy-paraglob/src/offset_format.rs` owns the canonical Paraglob `#[repr(C)]` structs and version constants; `crates/matchy-format/src/offset_format.rs` only re-exports them.
- `crates/matchy-literal-hash/src/lib.rs` owns the `LHSH` literal hash format.
- `crates/matchy/src/database.rs` owns format detection, mmap/owned storage, section loading, and lookup behavior.
- `crates/matchy/src/validation.rs` validates `.mxy` files for offsets, metadata, UTF-8, graph structure, and schema consistency.

## Layout
Unified `.mxy` files are MMDB-compatible:
1. IP search tree bytes, even for pattern-only `.mxy` output from `DatabaseBuilder`.
2. 16-byte zero separator.
3. MMDB-encoded `DataValue` data section.
4. Optional `MMDB_PATTERN\0\0\0\0` marker plus Paraglob section and pattern-to-data mappings.
5. Optional `MMDB_LITERAL\0\0\0\0` marker plus `LHSH` v3 literal hash section.
6. MaxMind metadata marker `\xAB\xCD\xEFMaxMind.com` plus metadata map.

## Compatibility Invariants
- Serialized references are `u32` byte offsets, never raw pointers.
- All format structs that are read from bytes use `#[repr(C)]`; sizes are asserted in tests or compile-time checks.
- Current Paraglob format is v5; `ParaglobHeader` is 112 bytes.
- Current literal hash format is v3; `LiteralHashHeader` is 32 bytes and hash table entries are 16 bytes.
- Metadata should include `pattern_section_offset` and `literal_section_offset`; loaders fall back to separator scans only for older files.
- New format fields require version bumps, validation updates, and old-file load/fail behavior tests.

## Loader Invariants
- `Database` owns the backing mmap/bytes and stores self-referential readers using a documented lifetime transmute; do not let those references escape private fields.
- `lookup_string_uncached` checks literal hash before Paraglob and may return both literal and glob matches.
- `lookup_ref` returns only offsets and compact result metadata for C callers; decode through `decode_at_offset`.
- `DataValue::Pointer` is internal and should not be serialized to JSON.
