---
name: router
description: Session bootstrap and navigation hub. Read at the start of every session before any task. Contains project state, routing table, and behavioural contract.
edges:
  - target: context/architecture.md
    condition: when working on system design, integrations, or understanding how components connect
  - target: context/stack.md
    condition: when working with specific technologies, libraries, or making tech decisions
  - target: context/conventions.md
    condition: when writing new code, reviewing code, or unsure about project patterns
  - target: context/decisions.md
    condition: when making architectural choices or understanding why something is built a certain way
  - target: context/setup.md
    condition: when setting up the dev environment or running the project for the first time
  - target: context/binary-format.md
    condition: when touching .mxy/MMDB/Paraglob/LiteralHash layout, mmap loading, validation, or offsets
  - target: context/ffi.md
    condition: when touching c_api, generated headers, C tests, or MaxMind compatibility
  - target: context/processing.md
    condition: when touching extraction, match CLI scanning, batch processing, or routing/performance
  - target: patterns/INDEX.md
    condition: when starting a task — check the pattern index for a matching pattern file
last_updated: 2026-07-02
---

# Session Bootstrap

If you haven't already read `AGENTS.md`, read it now — it contains the project identity, non-negotiables, and commands.

Then read this file fully before doing anything else in this session.

## Current Project State
**Working:**
- Rust workspace with focused crates for format, IP trie, literal hash, Paraglob, AC, extractor, data format, match mode, WASM, and main integration.
- `matchy build`, `query`, `inspect`, `validate`, `match`, `extract`, and `bench` CLI commands.
- Unified `.mxy` files with IP trie, MMDB data, literal hash, optional Paraglob section, and metadata section offsets.
- Native mmap loading, in-memory/WASM loading, thread-local query cache, and optional native live reload/auto-update.
- C API with opaque handles plus MaxMind compatibility tests driven by the Makefile.

**Not yet built:**
- No server/daemon API, auth, web UI, persistent service database, or deployment pipeline in this repo.
- No in-place incremental database mutation; updates require rebuilding and replacing files.
- No automatic parallel chunking for a single uniform massive file unless caller supplies routing options.

**Known issues:**
- C API docs promise panic catching at FFI boundaries, but no `catch_unwind` usage is currently present in `crates/matchy/src/c_api/`.
- Older databases without `pattern_section_offset` or `literal_section_offset` metadata fall back to a full-file separator scan.
- `matchy_builder_save` writes directly to the target path, while CLI `cmd_build` uses temp-file then rename.

## Routing Table

Load the relevant file based on the current task. Always load `context/architecture.md` first if not already in context this session.

| Task type | Load |
|-----------|------|
| Understanding how the system works | `context/architecture.md` |
| Working with a specific technology | `context/stack.md` |
| Writing or reviewing code | `context/conventions.md` |
| Making a design decision | `context/decisions.md` |
| Setting up or running the project | `context/setup.md` |
| Changing binary format, mmap loading, or validation | `context/binary-format.md` |
| Changing C API, generated headers, or MaxMind compatibility | `context/ffi.md` |
| Changing extraction, matching, or parallel processing | `context/processing.md` |
| Any specific task | Check `patterns/INDEX.md` for a matching pattern |

## Behavioural Contract

For every task, follow this loop:

1. **CONTEXT** - Load the relevant context file(s) from the routing table above. Check `patterns/INDEX.md` for a matching pattern. If one exists, follow it. Narrate what you load: "Loading architecture context..."
2. **BUILD** - Do the work. If a pattern exists, follow its Steps. If you are about to deviate from an established pattern, say so before writing any code; state the deviation and why.
3. **VERIFY** - Load `context/conventions.md` and run the Verify Checklist item by item. State each item and whether the output passes. Do not summarise; enumerate explicitly.
4. **DEBUG** - If verification fails or something breaks, check `patterns/INDEX.md` for a debug pattern. Follow it. Fix the issue and re-run VERIFY.
5. **GROW** - After completing the task:
   - If no pattern exists for this task type, create one in `patterns/` using the format in `patterns/README.md`. Add it to `patterns/INDEX.md`. Flag it: "Created `patterns/<name>.md` from this session."
   - If a pattern exists but you deviated from it or discovered a new gotcha, update it with what you learned.
   - If any `context/` file is now out of date because of this work, update it surgically — do not rewrite entire files.
   - Update the "Current Project State" section above if the work was significant.
