---
name: architecture
description: How the major pieces of this project connect and flow. Load when working on system design, integrations, or understanding how components interact.
triggers:
  - "architecture"
  - "system design"
  - "how does X connect to Y"
  - "integration"
  - "flow"
edges:
  - target: context/stack.md
    condition: when specific technology details are needed
  - target: context/decisions.md
    condition: when understanding why the architecture is structured this way
  - target: context/binary-format.md
    condition: when touching DatabaseBuilder, mmap loading, validation, offsets, or serialized structures
  - target: context/processing.md
    condition: when working on match/extract CLI flow, batch processing, or parallel routing
  - target: context/ffi.md
    condition: when changing c_api, C tests, generated headers, or MaxMind compatibility
last_updated: 2026-07-02
---

# Architecture

## System Overview
`matchy build` reads text/CSV/JSON/MISP inputs -> `DatabaseBuilder::add_entry` auto-detects `ip:`, `literal:`, `glob:`, IP/CIDR, literal, or glob entries.
`DatabaseBuilder::build` deduplicates `DataValue` metadata -> builds an IP trie, literal hash table, and Paraglob section -> writes one MMDB-compatible `.mxy` file.
`Database::from(...).open()` mmap-loads native files or owns bytes on WASM -> detects IP-only, pattern-only, or combined format -> wires self-references into owned read-only storage.
`Database::lookup` parses IPs into `lookup_ip`; other strings go through literal hash first, then Paraglob glob matching.
`matchy match` opens or auto-builds the database -> configures `Extractor` from database capabilities and CLI overrides -> extracts candidates from logs -> calls `lookup_extracted`.
Native parallel matching routes files between reader threads and worker threads using workload simulation; sequential mode scans line by line.
The C API wraps the same builder/database with opaque handles, integer error codes, and generated headers.

## Key Components
- **`matchy::Database`** - unified query API, owns mmap/bytes plus self-referential `MmdbHeader`, `LiteralHash`, and `Paraglob`; cache is per-thread LRU keyed by generation.
- **`matchy_format::DatabaseBuilder`** - canonical builder for `.mxy`, depends on `IpTreeBuilder`, `LiteralHashBuilder`, `ParaglobBuilder`, and `DataEncoder`.
- **`matchy_extractor::Extractor`** - extracts domains, IPs, emails, hashes, and crypto addresses; `matchy match` enables extractors from database capabilities unless CLI overrides are explicit.
- **`matchy::processing`** - reusable `FileReader`, `Worker`, `DataBatch`, and native `process_files_parallel` pipeline for log scanning.
- **`matchy::c_api`** - opaque C handles and MaxMind compatibility wrappers around the Rust API; generated header lives under `crates/matchy/include/matchy/`.

## External Dependencies
- **MaxMind DB format/libmaxminddb API** - `.mxy` files are MMDB-compatible and `crates/matchy/src/c_api/maxminddb_compat.rs` exposes `MMDB_*` wrappers; maintain record sizes and metadata expectations.
- **MISP JSON format** - `matchy build --format misp` streams threat intel through `MispImporter`; schema/metadata behavior differs from generic JSON arrays.
- **Update URL over HTTP** - optional `auto-update` feature stores `update_url` metadata and uses native-only update machinery; `auto_update()` fails if the database lacks an embedded URL.
- **CSV/JSON source files** - CLI requires `entry` or `key` for CSV and `[{ "key": ..., "data": ... }]` for JSON; `match` can auto-build from CSV or JSON inputs.

## What Does NOT Exist Here
- No server, web app, auth system, SQL database, ORM, migrations, or background job queue.
- No in-place database mutation: databases are immutable; update by building a new file and atomically replacing/reopening.
- No direct editing of generated C headers; Rust signatures plus `cbindgen.toml` drive header output.
- No pointer-based serialized structures; mmap-compatible data uses offsets and explicit bounds checks.
