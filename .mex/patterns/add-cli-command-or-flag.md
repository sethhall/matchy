---
name: add-cli-command-or-flag
description: Add or change matchy CLI commands, flags, output, or exit behavior.
triggers:
  - "CLI"
  - "command"
  - "flag"
  - "clap"
  - "matchy build"
  - "matchy match"
edges:
  - target: context/architecture.md
    condition: when the command needs database build/open/query flow
  - target: context/processing.md
    condition: when changing `matchy match`, extraction, stats, progress, or routing
  - target: context/conventions.md
    condition: before verifying naming, docs, and tests
last_updated: 2026-07-02
---

# Add CLI Command Or Flag

## Context
CLI definitions live in `crates/matchy/src/bin/matchy.rs`. Command bodies live in `crates/matchy/src/bin/commands/` files such as `crates/matchy/src/bin/commands/build_cmd.rs`, and are re-exported from `crates/matchy/src/bin/commands/mod.rs`. Match-specific helpers live under `crates/matchy/src/bin/match_processor/`.

## Steps
1. Add or update the `Commands` enum variant in `crates/matchy/src/bin/matchy.rs` using `clap` derive attributes.
2. Put behavior in a focused command module under `crates/matchy/src/bin/commands/`, not directly in the dispatch match.
3. Re-export new command functions from `crates/matchy/src/bin/commands/mod.rs`.
4. Add context-rich errors with `anyhow::Context`; CLI operational info goes to stderr when it is diagnostics/stats.
5. Preserve established output contracts: `query` prints JSON arrays and exits 0/1, `match --format json` emits NDJSON, `validate` exits 1 on invalid databases.
6. Add or update `assert_cmd` tests in `crates/matchy/tests/cli_tests.rs`.

## Gotchas
- `matchy match` can accept JSON or CSV source databases and auto-build them in memory; do not assume the database path is always `.mxy`.
- Positive `--extractors=ip,domain` means exclusive mode; negative `--extractors=-crypto` means defaults minus those extractors.
- `query` and `validate` intentionally call `std::process::exit` for exit-code behavior.
- `build` uses temp-file then rename; do not regress atomic CLI output writes.

## Verify
- `cargo test -p matchy --test cli_tests`
- `cargo test -p matchy`
- `cargo fmt --all`
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`

## Debug
- Run `cargo run -p matchy -- <command> --help` to inspect clap output.
- For `match`, compare `--threads 1` against `--threads auto` to separate command behavior from parallel routing.
- Use `--stats` and `--debug-routing` for throughput or routing issues.

## Update Scaffold
- [ ] Update `.mex/ROUTER.md` "Current Project State" if what's working/not built has changed
- [ ] Update any `.mex/context/` files that are now out of date
- [ ] If this is a new task type without a pattern, create one in `.mex/patterns/` and add to `INDEX.md`
