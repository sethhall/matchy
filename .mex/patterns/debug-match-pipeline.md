---
name: debug-match-pipeline
description: Diagnose missing matches, bad match output, slow scans, or routing surprises in `matchy match`.
triggers:
  - "missing match"
  - "match pipeline"
  - "debug routing"
  - "slow match"
  - "throughput"
  - "candidate"
edges:
  - target: context/processing.md
    condition: for extraction, worker, output, stats, and routing flow
  - target: context/binary-format.md
    condition: when the database loads, validates, or decodes incorrectly
  - target: patterns/add-extractor-kind.md
    condition: when the failure points to a specific extractor type
last_updated: 2026-07-02
---

# Debug Match Pipeline

## Context
The `match` path has four boundaries: database load or source auto-build, extractor selection, candidate lookup, and sequential/parallel output. Diagnose in that order.

## Steps
1. Validate the database first: `cargo run -p matchy -- validate <db>.mxy --level strict --verbose`.
2. Inspect capabilities: `cargo run -p matchy -- inspect <db>.mxy --json` and confirm IP, literal, or glob data exists.
3. Reproduce in sequential mode: `cargo run -p matchy -- match <db> <log> --threads 1 --format json --stats`.
4. If no candidates appear, run extraction alone: `cargo run -p matchy -- extract <log> --show-candidates --stats`.
5. If candidates exist but no matches, query one directly: `cargo run -p matchy -- query <db> <candidate>`.
6. If sequential works but parallel differs, run `--threads auto --debug-routing --stats`.
7. If source auto-build is involved, test the source format explicitly with `matchy build <source> -o /tmp/test.mxy --format json|csv`.

## Gotchas
- JSON output is NDJSON; parse line by line, not as one JSON array.
- `match` auto-builds only JSON and CSV database arguments; text inputs need `build` first.
- CSV sources require `entry` or `key`.
- Default extractors depend on database capabilities. Use `--extractors=ip,domain` for explicit exclusive mode or `--extractors=-crypto` to disable only a group.
- Single huge files may not chunk under auto routing; explicit `--readers=1` can test whether chunking helps.

## Verify
- Add a focused fixture to `crates/matchy/tests/cli_tests.rs` when the bug is CLI-visible.
- Add processing unit tests in `crates/matchy/src/processing/mod.rs` or `crates/matchy/src/processing/parallel.rs` for routing/worker bugs.
- Run `cargo test -p matchy --test cli_tests`.
- Run `cargo test -p matchy`.

## Debug
- For load/decode errors, follow `context/binary-format.md`.
- For C-only mismatches, follow `patterns/change-c-api.md`.
- For throughput, read stderr sections: `Thread Allocation`, `File Routing`, and `Performance Analysis`.

## Update Scaffold
- [ ] Update `.mex/ROUTER.md` "Current Project State" if what's working/not built has changed
- [ ] Update any `.mex/context/` files that are now out of date
- [ ] If this is a new task type without a pattern, create one in `.mex/patterns/` and add to `INDEX.md`
