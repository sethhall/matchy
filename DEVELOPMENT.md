# Matchy - Developer Guide

This document covers architecture, implementation details, and performance characteristics for engineers working on or integrating with Matchy.

## What Matchy Does

Matchy is a unified database for IP address and pattern matching. Single file format, single query API. You build a database with IPs (including CIDRs), exact strings, and glob patterns, then query it with anything—IP addresses, domain names, file paths, whatever. The system figures out what you're looking for and returns results in microseconds.

Key capabilities:
- **IP lookups**: Binary trie, sub-microsecond queries
- **Exact string matching**: Hash table, O(1) lookups
- **Glob pattern matching**: Aho-Corasick + glob engine, performance varies by pattern complexity
- **Zero-copy mmap**: Database loads in ~1ms regardless of size, shared across processes
- **Rich metadata**: JSON-like structured data attached to each entry
- **MMDB compatibility**: Extended MaxMind format, works with existing tooling

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

4. **Cache**: Results cached in LRU (optional, enabled via `DatabaseOpener::cache_capacity()`)

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

**Offset-based, not pointer-based**: Everything uses file offsets (u32/u64) instead of pointers. This is critical for mmap:

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

At query time, we add the offset to the base address of the mapped region. Validated at load time to prevent out-of-bounds access.

**Why `#[repr(C)]`**: Guarantees stable field layout across Rust versions and platforms. Required for binary format compatibility.

## Performance Characteristics

Performance varies significantly based on query type, database size, and glob pattern complexity. General behaviors:

### IP Lookups

**Algorithm**: Binary trie traversal, depth = address bit length (max 128 bits for IPv6).

**Scaling**: Near-constant time regardless of database size. Adding 10× more IPs has minimal impact on query latency.

**Database size**: Compact. ~6 bytes per IP for just the tree structure, plus data storage.

**Build time**: Fast and scales linearly. Databases with 100K+ IPs build in milliseconds.

**Notes**:
- IPv4-only databases use 32-bit address space for efficiency
- IPv6 databases use 128-bit address space (can include IPv4-mapped addresses)
- Tree depth auto-selected based on addresses present in database
- CIDR ranges supported via prefix matching
- Load time ~1ms via mmap regardless of DB size

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
   - Slow: Multiple wildcards trigger extensive backtracking
   - Performance degrades severely with scale (10-100× slower than suffix)
   - Each AC match requires expensive glob verification

**Why the huge difference?** 

Suffix pattern `*.evil.com`: The literal "evil.com" uniquely identifies the glob. After AC matches, one suffix check and we're done. Simple, fast, scales.

Complex pattern `*[0-9][0-9]*.evil.*`: Might extract 10+ literals. Each AC match triggers recursive backtracking through the glob engine. At high scale, you're doing thousands of expensive glob matches per query.

**Recommendation**: Keep globs simple. If you have `*[0-9][0-9].evil.com`, consider exploding it to 100 concrete globs (`*00.evil.com` through `*99.evil.com`). Build time increases slightly, query time drops 10-100×.

### Build & Load Times

**Build**: Fast and scales linearly with entry count. Databases with 100K entries typically build in tens of milliseconds. Complex globs take longer to build than simple globs due to literal extraction overhead.

**Load**: Memory-mapped via single `mmap()` syscall, typically <1ms regardless of database size. No deserialization, no copies. OS pages in data on-demand.

**Memory efficiency in multi-process setups**:

Traditional approach (heap deserialization): Each process loads its own copy. 50 workers × 100 MB database = 5,000 MB RAM.

Matchy approach (mmap): OS shares physical pages across processes. 50 workers reading same file = 100 MB RAM total. **98% savings**.

## Implementation Details

### Glob Engine

Supports standard glob syntax:
- `*` - matches any sequence (including empty)
- `?` - matches exactly one character
- `[abc]` - character class (matches a, b, or c)
- `[!abc]` or `[^abc]` - negated character class
- `[a-z]` - range syntax

**Implementation** (`matchy-paraglob/src/glob.rs`): Recursive backtracking matcher with step limit to prevent pathological cases. Fast for simple globs where wildcards have few choices. Slow for complex globs with multiple wildcards that generate many backtracking paths. This is why suffix/prefix globs outperform complex globs by 100×+.

### Aho-Corasick Automaton

Classic AC implementation with failure links (`matchy-ac/src/lib.rs`):
1. Build a trie from pattern literals
2. Compute failure links (BFS from root)
3. At query time, traverse based on input, following failure links on mismatch

**Critical fix** (historical): Original implementation broke after following a failure link, preventing detection of overlapping matches. Fixed by continuing the loop after failure transitions.

### Data Deduplication

The data section deduplicates identical metadata across entries (`matchy-data-format/`). If 1000 IPs all have `{"threat_level": "high"}`, we store it once and reference it 1000 times. Implemented via content-addressed storage (hash the data, check for existing entry).

Typical compression: 50-80% for threat feeds with similar metadata.

### FFI Design

Two C APIs provided (`matchy/src/c_api/`):
1. **Native API** (`matchy_*` functions) - Full Matchy functionality
2. **MaxMind-compatible API** (`MMDB_*` functions) - Drop-in replacement for libmaxminddb

Both use opaque handles and return error codes. All string data passed as `const char*` with explicit lengths. No C++ exceptions across FFI boundary.

**Panic safety**: All `extern "C"` functions wrapped in `catch_unwind()`. Panics convert to error codes rather than aborting.

## Data Extraction

The `matchy-extractor` crate finds structured data in unstructured text: IPs, domains, emails, file hashes, crypto addresses.

**Supported types**:
- **IPv4/IPv6**: Standard address formats
- **Domains**: Validated against Public Suffix List (PSL)
- **Emails**: RFC-like validation with PSL TLD checks
- **File hashes**: MD5, SHA1, SHA256, SHA384 (hex, length-based detection)
- **Crypto addresses**: Bitcoin (Base58Check + Bech32), Ethereum (EIP-55), Monero (Keccak256)

**Performance**: ~450 MB/s single-threaded. Uses SIMD via `memchr` for anchor detection (dots, @, 0x prefix). Expands boundaries, validates checksums where applicable.

**Usage**:
```rust
let extractor = Extractor::new()?;
for item in extractor.extract_from_line(log_line.as_bytes()) {
    // item.text, item.match_type
}
```

## Batch Processing

The `matchy/src/processing/` module provides infrastructure for scanning files against databases:

**Key types**:
- `LineFileReader` - Streams file in chunks, handles gzip automatically
- `Worker` - Combines extractor + database(s), processes batches
- `LineMatch` - Match result with file/line context
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
            match_item.line_number,
            match_item.match_result.matched_text,
            match_item.match_result.database_id);
    }
}
```

## Database Validation

For untrusted databases, use validation before loading. Validation logic is distributed across crates, with each crate validating its own structures.

**Three levels**:
1. **Basic** (~1ms): Magic bytes, version, critical offsets
2. **Standard** (~5ms): All offsets, UTF-8, structure integrity
3. **Strict** (~10ms): Graph analysis, cycle detection, efficiency warnings

**What's checked**:
- Binary format integrity
- Offset bounds (prevent out-of-bounds reads)
- UTF-8 validity of all strings
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

**Problem**: All globs go through AC + glob verification, even simple ones.

**Solution**: Detect glob types at build time, route to specialized structures:
- **Suffix globs** (`*.evil.com`) → reverse suffix trie
- **Prefix globs** (`error-*`) → prefix trie
- **Exact strings** already use hash table (fast)
- **Complex globs** → keep using AC + glob engine (no better alternative)

**Impact**: Potentially 2-3× speedup for workloads dominated by suffix/prefix globs.

**Effort**: Medium. Would require new binary format sections.

### 2. Query Result Caching

**Already implemented**: `DatabaseOpener::cache_capacity(n)` enables LRU cache.

**Impact**: 2-10× speedup for high-traffic scenarios with query repetition (web servers, DNS filtering).

**No code changes needed** - just use the API.

### 3. Glob Simplification

**Problem**: Complex globs (`*[0-9][0-9].evil.com`) are slow due to recursive backtracking in glob engine.

**Solution**: Explode to concrete globs (`*00.evil.com`, `*01.evil.com`, ..., `*99.evil.com`).

**Impact**: Build time increases slightly, query time can drop 10-100×.

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
