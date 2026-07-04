# Analyst Workbench Website Design

## Summary

Matchy's next public-facing step is a local-first analyst workbench for the
browser. The current WASM demo proves the building blocks work, but it is aimed
at users who already know what Matchy is. The new first-run experience should
let detection engineers and analysts drop log files into the page, scan them
locally against a bundled threat database, and immediately review matched
indicators with enough context to decide whether to investigate further.

The website should lead with an outcome:

> Drop logs. Match indicators locally. Find threat intel hits without uploading
> evidence.

## Audience

The primary audience is SOC analysts, detection engineers, and threat hunters
who work with logs, alerts, and threat intelligence feeds. They care less about
the internal Rust architecture at first contact and more about whether the tool
helps them find suspicious activity quickly, privately, and with low setup
friction.

The secondary audience is platform and systems engineers who may later embed
Matchy. The site should still link to CLI, Rust, C, and binary format
documentation, but those routes should not dominate the first screen.

## Goals

- Make the browser demo the primary public experience, not a hidden utility.
- Show that matching happens locally in the user's browser.
- Let a user drop one or more files and see matches without configuring a feed.
- Ship a static prebuilt `.mxy` demo database as a site asset.
- Preserve a path for Feedforge to generate or refresh the bundled database
  later.
- Show analyst-friendly results instead of raw lookup JSON.
- Provide a direct handoff from browser success to local CLI usage.

## Non-Goals

- Do not build a full SIEM, case management system, or hosted analysis backend.
- Do not call live ThreatFox, URLhaus, or other third-party feed APIs from the
  public browser demo.
- Do not require user accounts, API keys, or a server-side upload path.
- Do not replace the existing mdBook documentation.
- Do not solve automatic feed freshness in the first implementation.

## First-Run Experience

The first page should be the product:

1. A bundled threat database loads as a static asset.
2. A short privacy/status line says matching runs locally in the browser.
3. The main interaction is a large file drop zone.
4. Dropping a file starts scanning immediately.
5. Hits stream into the UI as they are found.
6. The user can inspect matched lines, metadata, and timing.
7. The user can copy or view equivalent `matchy` CLI commands.

The existing builder, import, query, and extractor tools should move behind an
advanced area. They are valuable for technical users, but they should not be the
default path for analysts.

## Feed Strategy

For the first version, the site ships a static prebuilt database such as
`demo-threats.mxy` plus a small metadata sidecar such as `demo-threats.json`.
The browser fetches those static assets from the same site and loads the
database into Matchy WASM. It does not call feed APIs and it does not include
secrets in client-side JavaScript.

The first database can be generated offline from a real public feed or from a
Feedforge-produced normalized feed when that pipeline is ready. The website code
should treat the database as a generic Matchy feed asset, not as a permanent
ThreatFox-specific integration.

Suggested sidecar fields:

- Feed display name
- Generated timestamp
- Entry count
- Source attribution
- Short freshness or sample disclaimer
- Optional source URLs for human review

The UI should make the state clear:

- "Using bundled threat feed sample"
- "Processed locally in this browser"
- "No files are uploaded"

## Data Flow

The browser workbench has two independent inputs:

- Static feed assets loaded on page start
- User-dropped evidence files processed locally

The scan flow is:

1. Fetch `demo-threats.mxy`.
2. Initialize Matchy WASM and construct `Database`.
3. Initialize `Extractor`.
4. Wait for file drop.
5. Read file chunks in JavaScript.
6. Decode bytes with `TextDecoder`.
7. Buffer complete lines and carry the final partial line across chunks.
8. Extract IoCs from each line batch.
9. De-duplicate repeated indicator lookups within the scan.
10. Query `Database.lookup()` for each extracted indicator.
11. Append matching hits and matching source lines to the UI.
12. Update progress and summary metrics.

For small files, scanning can complete in one pass. For large files, scanning
should yield between batches or run inside a Web Worker so the UI stays
responsive.

## UI Components

### Status Header

Shows the loaded feed name, entry count, generated timestamp, Matchy version,
and local-processing privacy status.

### Drop Zone

Accepts log files, text files, CSVs, JSONL, and generic text-like evidence.
Dropping a file starts scanning immediately. A secondary button can open the
file picker for users who do not drag files.

### Summary Strip

Shows:

- Files scanned
- Bytes or lines scanned
- Indicators extracted
- Unique indicators queried
- Matches found
- Elapsed time

### Hits Table

Columns should prioritize analyst triage:

- Indicator
- Type
- Severity or confidence
- Source or feed
- Malware family or threat type
- First seen
- Match count
- Sample line

The table should support filtering by match type, severity or confidence,
source, and text search.

### Evidence Viewer

Shows the original lines that produced hits. Matched indicators are highlighted.
The first implementation can store only matching lines plus optional nearby
context to avoid keeping large files in memory.

### Hit Detail Drawer

Shows full metadata for a selected indicator, all matching lines captured for
that indicator, and copyable fields. If the feed metadata includes references,
show source links.

### Advanced Area

Preserve and improve the existing lower-level demo tools:

- Build a database manually
- Import CSV, JSON, or text feeds
- Query individual indicators
- Test extraction behavior
- Download generated `.mxy` files

## Incremental Scanning Model

Incremental scanning is a progressive enhancement. The required behavior is
"drop a file and get matches." The preferred behavior is that large files scan
in batches and show hits as they arrive.

The first implementation should use line-buffered chunking:

- Stream file bytes from the browser File API where available.
- Decode bytes incrementally.
- Split on newlines.
- Keep the last partial line for the next chunk.
- Scan complete line batches.
- Keep UI state bounded by storing summary metrics and matching lines.

This model is sufficient for log files because indicators are usually contained
within a single line. It avoids the complexity of arbitrary byte-level streaming
across unknown text formats.

## Error Handling

The workbench should have clear, recoverable states:

- WASM failed to load: show build/deploy issue and link to docs.
- Demo database failed to load: keep the UI visible and offer manual feed import.
- File is binary or unreadable: explain that text-like logs are expected.
- Scan is too large for current memory limits: suggest using the CLI.
- Feed metadata is missing: fall back to generic bundled-feed labels.
- Individual lookup errors: record them in scan diagnostics without stopping the
  whole scan.

No panics or raw stack traces should appear in the user-facing interface.

## Privacy and Trust

The site should repeatedly but tersely communicate the privacy model:

- Static feed assets are downloaded to the browser.
- Evidence files are read locally.
- Matching happens in WebAssembly in the browser.
- Files are not uploaded.

This should be stated in the status header and near the drop zone. It should not
be buried in documentation.

## CLI Handoff

After a scan, show the equivalent local workflow:

```bash
matchy match demo-threats.mxy suspicious.log --stats
```

If the user imported or generated a custom database, provide commands that match
that workflow. The handoff should make the browser demo feel like the first
step toward real daily use, not a separate toy.

## Relationship to Feedforge

Feedforge should remain optional in this first public story. The public message
is that Matchy is the local matching engine. Feedforge can later become the
curated feed producer that publishes refreshed `.mxy` assets or normalized feed
inputs.

The interface should leave space for wording such as:

- "Feed curated by Feedforge"
- "Generated from public threat intel"
- "Refresh cadence"

Those fields should come from the metadata sidecar, not hardcoded UI text.

## Testing

Implementation should include focused tests and browser verification:

- Unit tests for any feed metadata parser or scan state reducer.
- Browser tests for loading the bundled database, dropping a fixture file, and
  rendering at least one hit.
- Tests for line chunking across partial chunk boundaries.
- Tests for de-duplicating extracted indicators before lookup.
- A smoke test that verifies the advanced existing builder/query path still
  works.
- Manual responsive checks for desktop and mobile layouts.

If implementation touches Rust or WASM exports, run the relevant Rust tests,
`cargo fmt`, and `cargo clippy` according to the repository rules.

## Rollout Plan

1. Build the workbench foundation inside the existing WASM demo path.
2. Add static demo feed asset loading.
3. Add drag-and-drop file scanning with line-batched extraction and lookup.
4. Replace raw JSON display with analyst-oriented hits and evidence views.
5. Move existing builder/import/query/extractor tools into an advanced section.
6. Link to the workbench prominently from README and the mdBook introduction.
7. Add a later Feedforge-generated asset path without changing the browser scan
   workflow.

