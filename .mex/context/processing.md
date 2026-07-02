---
name: processing
description: Extraction, match CLI scanning, batch processing, and native parallel routing.
triggers:
  - "match command"
  - "extractor"
  - "parallel"
  - "batch"
  - "routing"
  - "performance"
edges:
  - target: context/architecture.md
    condition: when connecting processing behavior to database build/open/query flow
  - target: context/stack.md
    condition: when concurrency or compression library details matter
  - target: context/conventions.md
    condition: when adding extractor, CLI, or worker APIs
  - target: patterns/add-extractor-kind.md
    condition: when adding or changing extracted indicator types
  - target: patterns/debug-match-pipeline.md
    condition: when `match` output, throughput, or routing is wrong
last_updated: 2026-07-02
---

# Processing

## Flow
`matchy match` loads a `.mxy` database or auto-builds JSON/CSV sources in memory.
It configures `Extractor` based on database capabilities: IP extractors for IP data, domains/email/hash/crypto for string data, unless positive `--extractors` flags switch to exclusive mode.
Sequential mode uses `LineScanner`, extracts candidates per line, and calls `lookup_ip` for IPs or `lookup` for strings.
Parallel mode calls `process_parallel`, which wraps `matchy::processing::process_files_parallel` and converts library matches into CLI JSON/text output.

## Library Processing API
- `FileReader` chunks files on newline boundaries and delegates compression opening to `crate::file_reader::open`.
- `Worker` owns an `Extractor`, one or more `Arc<Database>` handles, and `WorkerStats`.
- `Worker::process_bytes` extracts once per batch, tracks candidate counts, and calls `Database::lookup_extracted`.
- `process_files_parallel` has a main routing thread, optional reader threads, worker threads, bounded queues, and routing stats.

## Routing Rules
- Many files usually go straight to workers as whole-file work units.
- Large compressed files may route through reader threads to amortize decompression.
- Last few outlier files may chunk to avoid stragglers.
- A single uniform massive file currently does not chunk by default; use explicit `--readers`/`--threads` when needed.
- `--debug-routing` prints workload stats, per-file routing decisions, reader count, and worker count.

## Output and Stats
- JSON output is NDJSON with `timestamp`, `source`, `matched_text`, and `match_type`.
- IP matches add `prefix_len`, `cidr`, and decoded data.
- Pattern matches add `pattern_count` and optional data array.
- `--stats` writes counts, timing samples, cache hit rate, routing stats, and bottleneck recommendations to stderr.
