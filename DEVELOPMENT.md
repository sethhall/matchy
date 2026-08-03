# Matchy - Developer Guide

This document covers architecture, implementation details, and performance characteristics for engineers working on or integrating with Matchy.

## What Matchy Does

Matchy is a unified database for IP address and pattern matching. Single file format, single query API. You build a database with IPs (including CIDRs), exact strings, and glob patterns, then query it with anything—IP addresses, domain names, file paths, whatever. The system detects the query type and routes it to the appropriate index.

Key capabilities:
- **IP lookups**: Binary trie with at most 32 IPv4 or 128 IPv6 tree steps
- **Exact string matching**: Hash table, O(1) lookups
- **Glob pattern matching**: Aho-Corasick + glob engine, performance varies by pattern complexity
- **Memory-mapped opening**: Avoids whole-file deserialization and allows read-only pages to be shared across processes; observed startup time depends on storage, page-cache state, platform, extensions, and whether legacy section scanning is needed
- **Rich metadata**: JSON-like structured data attached to each entry
- **MMDB compatibility**: Extended MaxMind format with a documented subset of standard MMDB types and APIs

## Architecture Overview

### File Format

Matchy extends the MaxMind DB (MMDB) binary format. An `.mxy` file is a valid MMDB file with an additional embedded section for patterns:

```
┌─────────────────────────────────────────┐
│  IP Search Tree (binary trie)           │  ← IPv4/IPv6 addresses
├─────────────────────────────────────────┤
│  Data Section (deduplicated)            │  ← JSON-like structured data
├─────────────────────────────────────────┤
│  PARAGLOB Section (optional)            │  ← Glob patterns
│    - AC nodes/edges                     │     (Aho-Corasick + glob engine)
├─────────────────────────────────────────┤
│  Literal Hash Section (optional)        │  ← Exact string matching
│    - Sharded hash table (96-bit XXH3)   │
├─────────────────────────────────────────┤
│  MMDB Metadata (last 128KB)             │  ← Binary format info,
│                                         │     section offsets
└─────────────────────────────────────────┘
```

**Why this works**: MMDB format includes a metadata section that can hold arbitrary key-value pairs. Matchy stores the offset and size of the PARAGLOB section there. Standard MMDB readers ignore it and just use the IP tree. Matchy reads both.

### Query Path

When you call `db.lookup("something")`:

1. **Detection**: Is it an IP address?
   - Attempt to parse as IPv4/IPv6
   - If successful → search IP tree (binary trie)
   - Return immediately if found

2. **Literal match**: Check exact string hash table
   - O(1) lookup using 96-bit XXH3 hash
   - Common for domain blocklists with exact matches
   - Return if found

3. **Glob match**: Run Aho-Corasick
   - Scan input for literals extracted from glob patterns
   - For each AC match, verify with glob engine
   - Return all matching globs

4. **Cache**: Optional per-thread LRU, constrained by both entry count and a 64 MiB estimated retained-heap budget

### Workspace Structure

Matchy is organized as a Cargo workspace with specialized crates:

```
matchy/
├── crates/
│   ├── matchy/              # Main crate: CLI + library + C API
│   │   ├── src/
│   │   │   ├── lib.rs       # Public API surface
│   │   │   ├── database.rs  # Unified Database API
│   │   │   ├── processing/  # Batch processing (Worker, parallel)
│   │   │   ├── c_api/       # C FFI layer
│   │   │   └── bin/         # CLI implementation
│   │   ├── tests/           # Integration tests
│   │   ├── benches/         # Benchmarks
│   │   ├── examples/        # Example programs
│   │   └── include/         # Generated C headers (matchy.h) ⚠️ Don't edit!
│   │
│   ├── matchy-format/       # Binary format, MMDB builder, mmap
│   ├── matchy-ip-trie/      # IP address lookups via binary trie
│   ├── matchy-literal-hash/ # O(1) exact string matching
│   ├── matchy-paraglob/     # Glob pattern matching with Aho-Corasick
│   ├── matchy-ac/           # Offset-based Aho-Corasick automaton
│   ├── matchy-extractor/    # Extract IPs, domains, emails from text
│   ├── matchy-data-format/  # DataValue type for database entries
│   ├── matchy-match-mode/   # CaseSensitive/CaseInsensitive enum
│   └── matchy-wasm/         # WebAssembly bindings
│
├── book/                    # mdbook documentation
├── fuzz/                    # Fuzzing tests
└── scripts/                 # Build and benchmark scripts
```

### Crate Dependency Graph

```
matchy (main crate)
├── matchy-match-mode (shared enum)
├── matchy-ac (Aho-Corasick)
├── matchy-ip-trie (IP lookups)
├── matchy-data-format (data encoding)
├── matchy-paraglob (glob patterns)
│   ├── matchy-match-mode
│   ├── matchy-ac
│   ├── matchy-data-format
│   └── matchy-ip-trie
├── matchy-literal-hash (exact strings)
│   └── matchy-match-mode
├── matchy-format (database format)
│   ├── matchy-ip-trie
│   ├── matchy-data-format
│   ├── matchy-paraglob
│   ├── matchy-literal-hash
│   └── matchy-match-mode
├── matchy-extractor (text extraction)
└── matchy-wasm (WASM bindings)
    └── matchy
```

### Crate Responsibilities

| Crate                    | Purpose                                            | Key Types                                          |
|--------------------------|----------------------------------------------------|----------------------------------------------------|
| **matchy**               | Main crate: CLI, public API, Database, processing  | `Database`, `DatabaseBuilder`, `DataValue`         |
| **matchy-format**        | Binary format, MMDB builder, mmap handling         | `DatabaseBuilder`, `EntryType`, `FormatError`      |
| **matchy-ip-trie**       | IP address lookups via binary trie                 | `IpTreeBuilder`, `RecordSize`, `IpTreeError`       |
| **matchy-literal-hash**  | O(1) exact string matching                         | `LiteralHashBuilder`, `LiteralHash`, `HashEntry`   |
| **matchy-paraglob**      | Glob pattern matching with Aho-Corasick            | `Paraglob`, `ParaglobBuilder`, `GlobError`         |
| **matchy-ac**            | Offset-based Aho-Corasick automaton                | `ACAutomaton`, `ACNodeHot`, `ACEdge`               |
| **matchy-extractor**     | Extract IPs, domains, emails from text             | `Extractor`, `ExtractorBuilder`, `ExtractedItem`   |
| **matchy-data-format**   | DataValue type for database entries                | `DataValue`, `DataEncoder`, `DataDecoder`          |
| **matchy-match-mode**    | CaseSensitive/CaseInsensitive configuration        | `MatchMode`                                        |
| **matchy-wasm**          | WebAssembly bindings for browser/Node.js           | `Database`, `DatabaseBuilder`, `Extractor`         |

### Key Source Files

**Main Crate (`matchy/`)**:
- `src/database.rs` - Unified `Database` struct, query API, result caching
- `src/processing/` - Batch processing infrastructure (Worker, parallel execution)
- `src/c_api/matchy.rs` - Native C API (opaque handles)
- `src/c_api/maxminddb_compat.rs` - MaxMind-compatible C API

**Format & Builders (`matchy-format/`)**:
- `src/mmdb_builder.rs` - Unified builder, entry type detection
- `src/offset_format.rs` - `#[repr(C)]` structures for binary format
- `src/validation.rs` - Format validation

**Pattern Matching (`matchy-paraglob/`)**:
- `src/paraglob_offset.rs` - Glob matching engine (AC + glob)
- `src/glob.rs` - Glob matching (wildcards, character classes)
- `src/literal_hash.rs` - Literal-to-glob-ID mapping
- `src/offset_format.rs` - PARAGLOB section format structures

**Core Data Structures**:
- `matchy-ac/src/lib.rs` - Offset-based Aho-Corasick automaton
- `matchy-ip-trie/src/lib.rs` - Binary trie for IP addresses
- `matchy-literal-hash/src/lib.rs` - Hash table for exact matching
- `matchy-data-format/src/lib.rs` - Data encoding/deduplication

**Extraction (`matchy-extractor/`)**:
- `src/lib.rs` - SIMD-accelerated extraction
- `src/extractors/` - Type-specific extractors (IP, domain, email, hash, crypto)

### Data Structure Design

**Offset-based, not pointer-based**: Serialized references use integer offsets
(`u32`/`u64`) instead of process pointers. Each field has a documented base;
this is critical for mmap:

```rust
// ❌ Won't work with mmap (pointers invalid after load)
struct Node {
    next: *const Node,
}

// ✅ Works with mmap (offset into mapped region)
#[repr(C)]
struct Node {
    next_offset: u32,
}
```

Each offset has a documented base (for example, the file, the MMDB data
section, the PARAGLOB buffer, or the AC buffer). Opening validates the fixed
set of top-level section envelopes and component topology. Nested records are
bounds-checked before access; strict validation performs deeper exhaustive
checks over referenced records.

**Why `#[repr(C)]`**: Gives the supported little-endian targets a predictable
field order and padding for serialized extension structs. Fixed-width fields,
explicit format versions, and checked decoding are still required for binary
compatibility; `#[repr(C)]` alone is not a cross-platform wire-format guarantee.

`matchy-ac` also exposes a standalone case-automaton image. Version 1 uses a
160-byte `MACCASE\0` header followed by densely packed, four-byte-aligned AC
buffers, little-endian `u32` pattern-length and pattern-ID tables, and the
sidecars needed for mixed per-pattern case semantics. All offsets are relative
to the beginning of the image. `ACCaseAutomatonView::from_image` verifies the
complete envelope, embedded AC topology, sidecar topology, IDs, lengths, and
exact-case byte ranges before returning a zero-copy borrowed view. Streaming
cursors remain process-local and are never serialized.

## Performance Characteristics

Performance varies significantly based on query type, database size, and glob pattern complexity. General behaviors:

### IP Lookups

**Algorithm**: Binary trie traversal, depth = address bit length (max 128 bits for IPv6).

**Scaling**: Tree depth is bounded by address width rather than entry count.
Database size can still affect cache locality and page-fault behavior.

**Database size**: Depends on prefix sharing, selected 24/28/32-bit record width,
and associated data.

**Build time**: Depends on entry distribution, metadata encoding, record-width selection, and hardware; benchmark representative inputs.

**Notes**:
- IPv4-only databases use 32-bit address space for efficiency
- IPv6 databases use a 128-bit tree and can place IPv4 entries beneath the conventional 96-bit IPv4 subtree
- Tree depth auto-selected based on addresses present in database
- CIDR ranges supported via prefix matching
- Opening uses mmap and bounded structural parsing for current files; actual latency depends on storage, cache state, platform, extensions, and legacy fallback scanning

### Exact String Matching

**Algorithm**: Sharded hash table with 96-bit XXH3 hashes, O(1) expected case.

**How it works**:
1. Compute 128-bit XXH3 hash, truncate to 96 bits (u64 + u32)
2. Route to shard based on lower bits
3. Linear probe within shard until match or empty slot

**Scaling**: Excellent. Sharded construction parallelizes across cores. 96-bit hashes provide virtually zero false positives even at high volumes. The ~60% load factor keeps probe chains short.

**Database size**: 16 bytes per hash table entry (hash_lo: u64, hash_hi: u32, pattern_id: u32), plus shard offset table and pattern mappings.

**Build time**: Fast and parallel. Large datasets (100K+ entries) build quickly via sharded construction with configurable parallelism.

**Use case**: Exact domain/URL/path matching before falling back to glob matching.

### Glob Matching

Performance varies **dramatically** based on glob complexity. Not all globs are created equal.

**How it works**:
1. Extract literals from each glob at build time (e.g., "evil.com" from `*.evil.com`)
2. Build Aho-Corasick automaton from extracted literals
3. At query time: scan input with AC, then verify full glob match for each AC hit

**Pattern complexity hierarchy** (fastest to slowest):

1. **Suffix patterns** (`*.evil.com`, `*.log`)
   - Fastest: AC finds literal, verify it's at end of string
   - Scales well even with tens of thousands of globs
   - Recommended for domain blocklists

2. **Prefix patterns** (`error-*`, `temp_*`)
   - Moderate: AC finds literal, verify it's at start
   - Scales reasonably well
   - Recommended for log files, file matching

3. **Mixed simple** (`prefix-*.suffix`)
   - Moderate: AC finds one literal, glob verifies both ends
   - Performance depends on literal uniqueness

4. **Complex patterns** (`*[0-9][0-9]*.evil.*`)
   - Multiple wildcards and character classes require more verification work
   - Performance depends on candidate selectivity, text length, and pattern shape
   - Bounded query APIs cap aggregate candidate and verification work

**Why the huge difference?** 

Suffix pattern `*.evil.com`: The literal "evil.com" uniquely identifies the glob. After AC matches, one suffix check and we're done. Simple, fast, scales.

Complex pattern `*[0-9][0-9]*.evil.*`: Candidate discovery can emit patterns that still require character-class and wildcard verification. The matcher is iterative and stack-safe, but a broad literal can make many candidates expensive.

**Recommendation**: Prefer selective literal anchors and simple globs where they express the same rule. Benchmark before expanding one rule into many concrete patterns: expansion trades verification complexity for a larger index and candidate set.

### Build & Load Times

**Build**: Work generally grows with entries and serialized metadata. Complex globs add parsing, literal extraction, and automaton construction; measure current code on the target feed.

**Load**: The main database bytes are memory-mapped, so opening avoids
whole-file deserialization and the OS pages data in on demand. Matchy still
performs bounded structural parsing and retains small component metadata; the
observed latency depends on storage, page-cache state, platform, extensions,
and whether a legacy marker scan is required.

**Memory efficiency in multi-process setups**:

Unlike whole-file heap deserialization, clean file-backed pages can be shared
across processes. Actual RSS/PSS also includes touched pages, page tables,
validated runtime views, scratch buffers, and optional query caches; measure the
production access pattern rather than multiplying only the file size.

## Implementation Details

### Glob Engine

Supports standard glob syntax:
- `*` - matches any sequence (including empty)
- `?` - matches exactly one character
- `[abc]` - character class (matches a, b, or c)
- `[!abc]` or `[^abc]` - negated character class
- `[a-z]` - range syntax

**Implementation** (`matchy-paraglob/src/paraglob_offset.rs`): Iterative,
stack-safe matching keeps the most recent `*` backtracking point. Public bounded
methods share an aggregate work budget across automaton traversal, candidate
mapping, sorting, and verification; compatibility methods remain unbounded.

### Aho-Corasick Automaton

Classic AC implementation with failure links (`matchy-ac/src/lib.rs`):
1. Build a trie from pattern literals
2. Compute failure links (BFS from root)
3. At query time, traverse based on input, following failure links on mismatch

**Critical fix** (historical): Original implementation broke after following a failure link, preventing detection of overlapping matches. Fixed by continuing the loop after failure transitions.

### Data Deduplication

The data section deduplicates identical metadata across entries (`matchy-data-format/`). If 1000 IPs all have `{"threat_level": "high"}`, we store it once and reference it 1000 times. Implemented via content-addressed storage (hash the data, check for existing entry).

Deduplication benefit depends on how often complete encoded values repeat in the feed.

### FFI Design

Two C APIs provided (`matchy/src/c_api/`):
1. **Native API** (`matchy_*` functions) - Full Matchy functionality
2. **MaxMind-compatible API** (`MMDB_*` functions) - Source-level compatibility subset for commonly used libmaxminddb operations; see the documented limitations

Both use opaque handles and C-compatible return values. String inputs are
null-terminated `const char*` unless a function explicitly takes a byte length.
No C++ exceptions cross the FFI boundary.

**Panic safety**: All `extern "C"` functions wrapped in `catch_unwind()`. Panics convert to error codes rather than aborting.

## Data Extraction

The `matchy-extractor` crate finds structured data in unstructured text: IPs, domains, emails, file hashes, crypto addresses.

**Supported types**:
- **IPv4/IPv6**: Standard address formats
- **Domains**: Validated against Public Suffix List (PSL)
- **Emails**: RFC-like validation with PSL TLD checks
- **File hashes**: MD5, SHA1, SHA256, SHA384, SHA512 (hex, length-based detection)
- **Crypto addresses**: Bitcoin (Base58Check + Bech32), Ethereum (EIP-55), Monero (Keccak256)

**Performance**: Uses `memchr`-style anchor detection (dots, `@`, `0x`
prefix), then expands boundaries and validates checksums where applicable.
Measure throughput with representative input and enabled extractor types.

**Usage**:
```rust
let extractor = Extractor::new()?;
for item in extractor.extract_from_line(log_line.as_bytes()) {
    println!("{}: {}", item.item.type_name(), item.as_str(log_line.as_bytes()));
}
```

## Batch Processing

The `matchy/src/processing/` module provides infrastructure for scanning files against databases:

**Key types**:
- `LineFileReader` - Streams file in chunks, handles gzip automatically
- `Worker` - Combines extractor + database(s), processes batches
- `MatchResult` - Match result with source and byte-offset context
- `WorkerStats` - Accumulates processing statistics

**Multi-database support**: One `Worker` can query multiple databases. Useful for cross-referencing threat feeds and allowlists.

```rust
let mut worker = processing::Worker::builder()
    .extractor(extractor)
    .add_database("threats", threat_db)
    .add_database("allow", allow_db)
    .build();

let reader = processing::LineFileReader::new("log.gz", 128 * 1024)?;
for batch in reader.batches() {
    for match_item in worker.process_lines(&batch?)? {
        println!("{}:{} - {} in {}",
            match_item.source.display(),
            match_item.byte_offset,
            match_item.matched_text,
            match_item.database_id);
    }
}
```

## Database Validation

For untrusted databases, use validation before loading. Validation logic is distributed across crates, with each crate validating its own structures.

**Two levels**:
1. **Standard**: Runtime-equivalent header and section-envelope checks, plus sampled decoding of reachable MMDB data (up to 20 tree nodes)
2. **Strict**: Exhaustive MMDB tree-record and reachable-data checks, plus deep graph and component consistency analysis

**What's checked**:
- Binary format integrity
- Top-level section bounds in both levels; referenced nested offsets are checked before access
- UTF-8 validity in sampled reachable values for Standard and exhaustive reachable values for Strict
- AC automaton structure (no cycles in failure links)
- Data section consistency

**CLI**:
```bash
matchy validate untrusted.mxy --level strict
```

**API**:
```rust
use matchy::validation::{validate_database, ValidationLevel};

let report = validate_database(
    Path::new("db.mxy"),
    ValidationLevel::Standard
)?;

if !report.is_valid() {
    return Err("Validation failed");
}
```

Database loading always validates UTF-8 on string reads for safety. There is no "trusted mode" that skips validation.

## Future Optimizations

Current performance is good for most use cases. If you need more:

### 1. Glob-Specific Data Structures

**Problem**: AC candidate discovery is shared, while some pattern shapes still
pay serialized verification costs after selection. Current fixed-window fast
paths already specialize common prefix, suffix, and contains shapes.

**Solution**: Detect glob types at build time, route to specialized structures:
- **Suffix globs** (`*.evil.com`) → reverse suffix trie
- **Prefix globs** (`error-*`) → prefix trie
- **Exact strings** already use hash table (fast)
- **Complex globs** → keep using AC + glob engine (no better alternative)

**Impact**: Unknown until prototyped and measured on representative pattern
sets. Any new serialized sections require an explicit compatibility decision.

**Effort**: Medium. Would require new binary format sections.

### 2. Query Result Caching

**Already implemented**: `DatabaseOpener::cache_capacity(n)` enables LRU cache.

**Impact**: Workload-dependent. Cache hits avoid matcher traversal and decoding,
but owned results can still be cloned. Measure hit rate, throughput, and memory;
disable caching for mostly unique queries.

### 3. Glob Simplification

**Problem**: Complex globs (`*[0-9][0-9].evil.com`) can require more candidate
verification and bounded backtracking than simple fixed-window patterns.

**Solution**: Explode to concrete globs (`*00.evil.com`, `*01.evil.com`, ..., `*99.evil.com`).

**Impact**: Expansion increases pattern count and database size, sometimes
substantially. Benchmark both build and query costs before adopting it.

**When to do this**: If you have complex globs and query performance matters more than build time.

## Building & Testing

```bash
# Development
cargo build
cargo test
cargo clippy
cargo fmt

# Release
cargo build --release
cargo bench

# Documentation
cargo doc --no-deps --open
cd book && mdbook serve  # User guide at localhost:3000
```

See [AGENTS.md](AGENTS.md) for complete development workflow, including CI checks and commit guidelines.

## Additional Documentation

- **README.md** - Project overview, quick start, features
- **AGENTS.md** - Development guide (workflow, best practices, boundaries)
- **CONTRIBUTING.md** - How to contribute, PR process
- **book/** - User documentation (mdbook)
- **examples/** - Working code examples
- **Cargo docs** - API reference (`cargo doc --open`)

## Summary

Matchy is a production-ready unified database for IP addresses and pattern matching. Key architectural decisions:

1. **Multi-crate workspace** - Clean separation of concerns, each crate has single responsibility
2. **Extended MMDB format** - Backward compatible, standards-based
3. **Offset-based structures** - Enable zero-copy mmap with shared memory
4. **Unified query API** - Automatic detection (IP vs string vs glob)
5. **Multiple data structures** - Binary trie (IPs), hash table (literals), AC+glob engine
6. **Safety first** - UTF-8 validation, comprehensive validation modules per crate

Performance is excellent for typical workloads. Glob performance varies dramatically by complexity - keep globs simple when possible. Multi-process deployments benefit massively from mmap (98% memory savings).
