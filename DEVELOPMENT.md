# Matchy - Development Notes

## Project Summary

Matchy is a **production-ready** unified database for IP addresses, string literals, and glob pattern matching. Built in Rust, it provides:
- Fast IP address lookups using binary trie (O(log n))
- Exact string matching with hash tables (O(1))
- Multi-pattern glob matching with Aho-Corasick algorithm (O(n))
- Zero-copy memory-mapped file support
- Extended MMDB format with backwards compatibility

**Status**: ✅ Production-ready (all tests passing, excellent performance)

## Architecture

### Three-Layer Design

```
┌─────────────────────────────────────┐
│     Application Layer               │
│     (C or Rust consumers)           │
└─────────────────────────────────────┘
              │
              │
      ┌───────▼───────┐
      │    C API      │
      │  (extern C)   │
      └───────┬───────┘
              │
      ┌───────▼───────────────┐
      │     Rust Core         │
      │ - IP Binary Trie      │
      │ - String Hash Table   │
      │ - AC Pattern Engine   │
      │ - Glob Matching       │
      │ - MMDB Format I/O     │
      │ - Memory Mapping      │
      └───────────────────────┘
```
      │ - Mmap        │
      └───────────────┘
```

### Core Implementation

- **Unified Query Interface**: Single API automatically detects IP addresses vs. patterns
- **Extended MMDB Format**: Backwards-compatible with MaxMind databases, adds string/pattern sections
- **Offset-Based Data Structures**: All data uses file offsets instead of pointers for zero-copy mmap support
- **Binary Format**: Uses `#[repr(C)]` structures for stable cross-platform compatibility
- **Memory Safety**: Rust's safety guarantees with minimal unsafe code (FFI boundary only)

## Performance Characteristics

### Test Environment

All benchmarks measured on **M4 MacBook Air (2024)**. Results are representative of modern Apple Silicon performance.

### IP Address Lookups

| Database Size | Build Rate | Build Time | DB Size | Load Time | Throughput | Latency |
|--------------|------------|-----------|---------|-----------|------------|----------|
| 10,000 IPs | 2.65M/sec | 3.8ms | 59 KB | 0.34ms | **4.00M q/s** | 0.25µs |
| 100,000 IPs | 2.78M/sec | 36ms | 586 KB | 0.72ms | **3.87M q/s** | 0.26µs |

**Analysis:**
- Sub-microsecond latency across all scales
- Binary trie lookup is extremely efficient
- Load time stays under 1ms regardless of size
- Near-linear scaling with database size

### String Literal Matching

| Database Size | Build Rate | Build Time | DB Size | Load Time | Throughput | Latency | Hit Rate |
|--------------|------------|-----------|---------|-----------|------------|---------|----------|
| 10,000 literals | 1.96M/sec | 5.1ms | 607 KB | 0.91ms | **1.14M q/s** | 0.88µs | 10% |
| 100,000 literals | 2.31M/sec | 43ms | 6.00 MB | 0.94ms | **165K q/s** | 6.07µs | 10% |

**Analysis:**
- Excellent performance for small-to-medium datasets
- Performance degrades with very large literal sets (100K+) due to hash collision overhead
- Still provides O(1) average case lookup
- Best for known exact matches: domains, URLs, file paths

### Pattern Matching Performance by Style

Pattern complexity dramatically affects performance:

#### Comprehensive Pattern Comparison

| Pattern Style | Description | 1K Patterns | 10K Patterns | 50K Patterns | Speedup vs Complex |
|--------------|-------------|-------------|--------------|--------------|-------------------|
| **Suffix** | `*.domain.com` | 3.38M q/s | 3.08M q/s | 3.32M q/s | **262×** @ 50K |
| **Mixed** | 50% prefix + 50% suffix | 1.96M q/s | 1.95M q/s | 1.98M q/s | **156×** @ 50K |
| **Prefix** | `errorlog-*` | 939K q/s | 956K q/s | 956K q/s | **75×** @ 50K |
| **Complex** | Multi-wildcard + char classes | 429K q/s | 59K q/s | 12.7K q/s | **1×** baseline |

#### Pattern Style Details

**Suffix Patterns (`*.domain.com`):**
- **Use case:** Domain blocklists, file extensions, URL suffixes
- **Performance:** 3-3.4M q/s across all scales
- **Why fast:** Simple suffix check after Aho-Corasick literal match
- **Scaling:** Excellent - maintains speed even with 50K patterns
- **Database size:** Larger (1.58 MB @ 10K) due to full suffix indexing

**Mixed Patterns (50% prefix, 50% suffix):**
- **Use case:** Threat intelligence with varied indicators
- **Performance:** ~2M q/s consistently
- **Why fast:** Averages fast suffix and moderate prefix performance
- **Scaling:** Excellent - linear across all tested sizes
- **Database size:** Compact (66 KB @ 10K)

**Prefix Patterns (`prefix-*`):**
- **Use case:** Log files, API keys, error codes
- **Performance:** ~950K q/s consistently  
- **Why moderate:** Requires AC match + prefix verification
- **Scaling:** Good - stable across scales
- **Database size:** Medium (421 KB @ 10K)

**Complex Patterns (`*[0-9].*.evil-*`):**
- **Use case:** Advanced threat detection with flexible matching
- **Performance:** Degrades significantly with scale (429K → 12.7K q/s)
- **Why slow:** Multiple wildcards trigger extensive backtracking in glob engine
- **Scaling:** Poor - exponential degradation
- **Database size:** Large (3.66 MB @ 10K) due to many extracted literals

### Build Performance

| Operation | 1K Entries | 10K Entries | 50K Entries | 100K Entries |
|-----------|-----------|-------------|-------------|-------------|
| **IP Database** | 0.4ms (2.29M/s) | 3.8ms (2.65M/s) | 18ms (2.73M/s) | 36ms (2.78M/s) |
| **Literals** | 0.6ms (1.58M/s) | 5.1ms (1.96M/s) | 24ms (2.05M/s) | 43ms (2.31M/s) |
| **Suffix Patterns** | 2.6ms (384K/s) | 19ms (516K/s) | 94ms (531K/s) | - |
| **Prefix Patterns** | 1.8ms (544K/s) | 10ms (1.03M/s) | 39ms (1.29M/s) | - |
| **Mixed Patterns** | 0.8ms (1.26M/s) | 3.9ms (2.57M/s) | 16ms (3.10M/s) | - |
| **Complex Patterns** | 4.2ms (241K/s) | 40ms (253K/s) | 246ms (203K/s) | - |

**Analysis:**
- Build time is a **one-time cost** - even 50K complex patterns build in <250ms
- Mixed patterns (prefix+suffix) build fastest due to compact representation
- IP and literal builds scale near-linearly with entry count
- Complex patterns have higher overhead due to multiple literal extractions per pattern
- All builds complete in milliseconds for typical datasets (<10K entries)

### Load Time Analysis

Memory-mapped databases load in **<1 millisecond** regardless of size:

| Database Type | Size | Load Time | Technology |
|--------------|------|-----------|------------|
| 10K IPs | 59 KB | 0.34ms | mmap() syscall |
| 100K IPs | 586 KB | 0.72ms | Zero-copy |
| 10K Suffix Patterns | 1.58 MB | 0.91ms | Direct memory access |
| 50K Suffix Patterns | 7.61 MB | 0.91ms | OS page sharing |

**Why so fast:**
- No deserialization - direct access to on-disk structures
- OS handles paging automatically
- Shared across processes (99% memory savings)
- Critical for hot-reloading threat feeds

### Memory Efficiency

**Traditional Approach (heap deserialization):**
```
50 worker processes × 100 MB database = 5,000 MB RAM
```

**Matchy Approach (memory-mapped):**
```  
50 worker processes sharing 100 MB = 100 MB RAM
**Savings: 4,900 MB (98% reduction)**
```

OS automatically shares physical pages across processes reading the same file.

## Key Implementation Details

### Critical Bug Fixes

Two major bugs were fixed during development:

1. **AC Literal-to-Pattern Mapping**: The mapping was lost after deserialization. Fixed by adding `reconstruct_literal_mapping()` that properly distinguishes literal (type 0) vs glob (type 1) patterns.

2. **AC Traversal After Failure Links**: The automaton was breaking after following failure links, preventing overlapping pattern matches. Fixed by allowing the loop to continue and retry transitions.

### Test Coverage

- ✅ 79/79 unit tests passing
- ✅ Serialization/deserialization roundtrip tests
- ✅ Correctness tests for IP, string, and pattern matching
- ✅ Performance benchmarks

## File Organization

```
src/
├── lib.rs                    # Public API
├── offset_format.rs          # C-compatible binary structures
├── ac_offset.rs              # Offset-based AC automaton
├── paraglob_offset.rs        # Offset-based Paraglob (primary impl)
├── serialization.rs          # Save/load/mmap API
├── glob.rs                   # Glob pattern matching
├── error.rs                  # Error types
└── mmap.rs                   # Memory mapping utilities

examples/
├── README.md                 # Examples documentation
├── demo.rs                   # Basic usage demo
├── perf.rs                   # Performance benchmark
└── production_test.rs        # Production workload simulation

tests/
└── integration.rs            # Integration tests
```

## Usage Examples

### Rust API
```rust
use paraglob_rust::Paraglob;

let patterns = vec!["*.txt", "*.log", "data_*"];
let pg = Paraglob::new(patterns)?;
let matches = pg.find_all("data_file.txt")?;
```

### Serialization
```rust
// Save to disk
paraglob_rust::save(&pg, "patterns.pgb")?;

// Load with zero-copy mmap
let pg = paraglob_rust::load("patterns.pgb")?;
```

## Design Decisions

### Why Offset-Based?

Traditional heap-based deserialization:
- Requires file read → deserialize → heap allocation
- ~100ms+ for large files
- Each process has separate memory

Offset-based with mmap:
- Single mmap() syscall (~1ms)
- No copying, no deserialization
- All processes share physical RAM pages
- ~99% memory savings in multi-process scenarios

### FFI Strategy

- **Rust Core**: Idiomatic Rust with `Result<T, E>`, ownership, lifetimes
- **C API**: Stable `extern "C"` with opaque handles, error codes

This approach provides a stable C API that can be consumed from any language.

## Database Validation

Matchy provides comprehensive validation for `.mxy` database files to ensure safety before loading, especially important for untrusted sources.

### Validation Module (`src/validation.rs`)

The validation module performs thorough checks without loading the database into the query engine:

**Validated Components:**
- Binary format integrity (magic bytes, version, alignment)
- All offsets are within buffer bounds
- UTF-8 validity of all string data
- AC automaton structure (nodes, edges, transitions)
- Graph integrity (no cycles, valid failure links)
- Pattern entries and data mappings
- Data section consistency (if present)

### Validation Levels

**Basic** (~1ms):
- Magic bytes and version check
- Critical offset validation
- Fast failure for obviously corrupt files

**Standard** (~5ms, default):
- All offset bounds checking
- UTF-8 validation for all strings
- Structure integrity (arrays, mappings)
- AC automaton basic validation

**Strict** (~10ms):
- Deep graph analysis
- Cycle detection in failure links
- State encoding distribution analysis
- Efficiency warnings (old format, suspicious sizes)

### Validation Report

Validation produces a detailed report with:
- **Errors**: Critical issues that make the database unsafe
- **Warnings**: Non-fatal issues (old format, inefficiencies)
- **Info**: Database properties and statistics
- **Stats**: Version, node count, pattern count, encoding distribution

### CLI Usage

```bash
# Validate before using
matchy validate untrusted.mxy

# Strict validation
matchy validate untrusted.mxy --level strict

# JSON output for automation
matchy validate untrusted.mxy --json
```

### API Usage

```rust
use matchy::validation::{validate_database, ValidationLevel};

let report = validate_database(
    Path::new("database.mxy"),
    ValidationLevel::Standard
)?;

if !report.is_valid() {
    eprintln!("Database validation failed:");
    for error in &report.errors {
        eprintln!("  - {}", error);
    }
    return Err("Unsafe database");
}
```

### Security Model

**Safe Mode (default):**
- Validates UTF-8 on every string read
- Safe for untrusted databases
- ~15-20% slower than trusted mode

**Trusted Mode:**
- Skips UTF-8 validation
- **Only for validated or self-built databases**
- Undefined behavior if database has invalid UTF-8

**Validation Recommendation:**
Always validate external databases with `matchy validate` before using `Database::open_trusted()` for better performance.

## Optimization Opportunities

### Pattern-Specific Optimizations

Based on comprehensive benchmarking, we've identified significant optimization potential for specific pattern types:

#### 1. Dedicated Suffix Trie (High Value)

**Current Performance:** 3.08M q/s @ 10K patterns  
**Potential:** 5-10M q/s (1.6-3.2× improvement)

**Approach:**
- Build reverse suffix trie for patterns like `*.domain.com`
- Skip glob verification entirely - direct pattern ID lookup
- Store reversed suffixes: "moc.niamod." for backward matching

**Value Proposition:**
- Domain blocklists are the most common use case
- Already fast, but could be faster than IP lookups
- Simple implementation, high impact

**Recommendation:** ⭐⭐⭐⭐⭐ **Implement if 50%+ of patterns are suffix-style**

#### 2. Dedicated Prefix Trie (Medium Value)

**Current Performance:** 956K q/s @ 10K patterns  
**Potential:** 2-3M q/s (2-3× improvement)

**Approach:**
- Build prefix trie for patterns like `errorlog-*`
- Mark terminal nodes with wildcard flag
- Direct lookup without glob verification

**Value Proposition:**
- Common for log files, API keys, error codes
- Moderate gains but simpler than suffix trie

**Recommendation:** ⭐⭐⭐ **Implement if 30%+ are prefix patterns**

#### 3. Pattern Type Auto-Detection (Low Effort, High Value)

**Current:** All patterns go through Aho-Corasick + glob verification  
**Opportunity:** Classify at build time and route to optimal data structure

```rust
enum OptimizedPattern {
    PurePrefix { prefix: String, id: u32 },
    PureSuffix { suffix: String, id: u32 },
    PrefixSuffix { prefix: String, suffix: String, id: u32 },
    Complex { ac_literal: String, glob: GlobPattern, id: u32 },
}
```

**Benefits:**
- Zero API changes - automatic optimization
- Mix-and-match: some patterns optimized, others use AC+glob
- Incremental implementation

**Recommendation:** ⭐⭐⭐⭐ **High-value architectural improvement**

### General Optimizations

#### 4. AC Node Pattern IDs (Complex Patterns Only)

**Value:** 10-20× speedup for **complex patterns only**  
**Effort:** High (requires binary format change)

**Current bottleneck:**
- Complex patterns: 12.7K q/s @ 50K patterns
- High match rates cause many glob verifications

**Approach:**
- Store pattern IDs directly in AC nodes
- Eliminate intermediate literal-to-pattern mapping
- Only helps when AC matches are frequent

**Recommendation:** ⭐⭐ **Only if complex patterns dominate AND you have 10K+ patterns**

#### 5. Trusted Mode Default

**Current:** UTF-8 validation on every string read (safe mode)  
**Opportunity:** 15-20% faster with `--trusted` flag

**Recommendation:** ⭐⭐⭐⭐ **Use trusted mode for databases you build yourself**

### Workload-Specific Recommendations

**Domain Blocklist (95% suffix patterns):**
- ✅ Current: 3.08M q/s @ 10K
- 🚀 With suffix trie: 5-8M q/s (potential)
- **Action:** Implement dedicated suffix trie

**Threat Intel (mixed patterns):**
- ✅ Current: 1.95M q/s @ 10K  
- 🚀 With auto-detection: 2.5-3M q/s (potential)
- **Action:** Pattern type classification + routing

**Complex Threat Detection (90% complex patterns):**
- ⚠️ Current: 59K q/s @ 10K
- **Action:** Accept current performance or reduce pattern complexity
- Consider splitting into multiple simpler patterns

**Log Processing (80% prefix patterns):**
- ✅ Current: 956K q/s @ 10K
- 🚀 With prefix trie: 2M q/s (potential)
- **Action:** Implement prefix trie optimization

## References

### Original Planning Documents (Archived)

The `llm_docs/` directory contains phase completion reports from the original port:
- PHASE_0_COMPLETE.md through PHASE_7_COMPLETE.md
- BUGFIX_SUMMARY.md

These are preserved for historical reference but represent development history, not current state.

### Additional Documentation

- `examples/README.md` - Example programs and how to run them
- `README.md` - Project overview and API reference
- `API_REDESIGN.md` - Detailed API specification

## Building & Testing

```bash
# Build
cargo build --release

# Run all tests
cargo test

# Run benchmarks
cargo bench

# Run examples
cargo run --release --example perf
cargo run --release --example production_test

# Generate documentation
cargo doc --no-deps --open
```

## Key Takeaways

1. **Implementation is complete and production-ready**
2. **Unified database** supports IP addresses, exact strings, and glob patterns
3. **Zero-copy mmap provides massive memory savings** in multi-process scenarios
4. **Backwards-compatible** with standard MaxMind MMDB format
5. **All tests passing** with comprehensive coverage

The architecture is sound, the implementation is correct, and performance is excellent for typical use cases.
