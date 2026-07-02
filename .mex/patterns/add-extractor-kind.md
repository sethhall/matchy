---
name: add-extractor-kind
description: Add a new extracted indicator type to Rust, CLI matching, and C extractor APIs.
triggers:
  - "extractor"
  - "indicator"
  - "IoC type"
  - "hash"
  - "crypto"
  - "candidate"
edges:
  - target: context/processing.md
    condition: for extraction flow, default enablement, stats, and match CLI behavior
  - target: context/ffi.md
    condition: when exposing the indicator through C flags, result structs, or type names
  - target: patterns/debug-match-pipeline.md
    condition: when the extractor finds candidates but matching output is wrong
last_updated: 2026-07-02
---

# Add Extractor Kind

## Context
`matchy-extractor` is modular: `crates/matchy-extractor/src/lib.rs` wires `ExtractorBuilder`, `Extractor`, and `ExtractorKind`; concrete extractors live under `crates/matchy-extractor/src/extractors/`; finder reuse lives in `crates/matchy-extractor/src/finders.rs`. CLI matching config is in `crates/matchy/src/bin/match_processor/parallel.rs` and `crates/matchy/src/bin/commands/match_cmd.rs`. C extractor flags and names live in `crates/matchy/src/c_api/matchy.rs`.

## Steps
1. Add the concrete extractor and tests in `crates/matchy-extractor/src/extractors/`.
2. Add a variant to `ExtractorKind` and wire `required_finders()` plus `extract()`.
3. Add `ExtractorBuilder` fields and builder methods in `crates/matchy-extractor/src/lib.rs`.
4. Add an `ExtractedItem` variant and `type_name`/string extraction behavior in `crates/matchy-extractor/src/types.rs`.
5. Update CLI `--extractors` parsing and aliases in `crates/matchy/src/bin/match_processor/parallel.rs` and command defaults in `crates/matchy/src/bin/commands/match_cmd.rs`.
6. Update `WorkerStats`, CLI stats output, and JSON output if the new type should be counted or displayed.
7. If exposed to C, add a `MATCHY_EXTRACT_*` flag, result item type constant, `matchy_item_type_name`, and C tests in `crates/matchy/tests/test_c_api.c`.

## Gotchas
- Defaults are database-capability driven: IP extractors for IP data; domain/email/hash/crypto for string data.
- Shared finders prevent repeated scans; reuse them instead of scanning the same bytes again.
- `Extractor` has unsafe `Send`/`Sync` impls based on no interior mutability; new fields must preserve that invariant.
- `Match::as_str(input)` relies on validated byte spans; do not store borrowed text outside the input lifetime.

## Verify
- `cargo test -p matchy-extractor`
- `cargo test -p matchy --test cli_tests`
- If C-facing: `cargo build --release -p matchy` then `make test-c`
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`

## Debug
- First test extraction alone with `matchy extract --show-candidates`.
- Then test matching with `matchy match <db> <input> --threads 1 --stats`.
- If parallel-only behavior differs, use `--threads auto --debug-routing`.

## Update Scaffold
- [ ] Update `.mex/ROUTER.md` "Current Project State" if what's working/not built has changed
- [ ] Update any `.mex/context/` files that are now out of date
- [ ] If this is a new task type without a pattern, create one in `.mex/patterns/` and add to `INDEX.md`
