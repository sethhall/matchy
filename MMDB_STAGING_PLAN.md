# MMDB Integration - Detailed Staging Plan

**Project**: paraglob-rs MMDB Integration
**Document**: Operational Staging Plan
**Date**: January 9, 2025

This document breaks down the MMDB integration into actionable tasks with clear deliverables, testing requirements, and success criteria for each phase.

---

## Overview

**Total Estimated Time**: 3-4 weeks (15-20 working days)

**Approach**: Incremental development with continuous testing. Each phase produces a working, testable artifact.

**Branch Strategy**: `feature/mmdb-integration` → PR to `main` after Phase 7

---

## Phase 0: Foundation & Setup

**Duration**: 1-2 days
**Goal**: Set up project structure and dependencies

### Tasks

#### 0.1 Create Module Structure
```bash
mkdir -p src/mmdb
mkdir -p src/unified
mkdir -p src/cli
touch src/mmdb/mod.rs
touch src/mmdb/format.rs
touch src/mmdb/tree.rs
touch src/mmdb/data.rs
touch src/mmdb/metadata.rs
touch src/mmdb/types.rs
touch src/unified/mod.rs
touch src/unified/database.rs
touch src/unified/format.rs
```

**Deliverable**: Clean module structure committed to branch

#### 0.2 Update Cargo.toml

Add dependencies:
```toml
[dependencies]
# Existing
libc = "0.2"
memmap2 = "0.9.8"

# New
clap = { version = "4.5", features = ["derive", "cargo"] }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
anyhow = "1.0"  # For CLI error handling
thiserror = "1.0"  # For library errors

[dev-dependencies]
# Existing
criterion = "0.7"
proptest = "1.4"
tempfile = "3.8"
rand = "0.9"

# New
assert_cmd = "2.0"  # For CLI testing
predicates = "3.0"  # For CLI assertions
```

**Deliverable**: Updated Cargo.toml, `cargo check` passes

#### 0.3 Create Basic Type Definitions

In `src/mmdb/types.rs`:
- Define `MmdbValue` enum
- Define `MmdbError` error type
- Define basic constants (METADATA_MARKER, etc.)

**Deliverable**: Types compile, basic doc comments added

#### 0.4 Set Up Test Infrastructure

```bash
mkdir -p tests/data
# Download a small test database
curl -o tests/data/GeoLite2-Country-Test.mmdb \
  https://github.com/maxmind/MaxMind-DB/raw/main/test-data/GeoIP2-Country-Test.mmdb
```

Create `tests/mmdb_basic.rs` with skeleton:
```rust
#[test]
fn test_load_test_database() {
    // Will implement in Phase 1
}
```

**Deliverable**: Test database downloaded, test skeleton exists

### Success Criteria
- ✅ All modules created and compile
- ✅ Dependencies added, no conflicts
- ✅ Test database available
- ✅ `cargo build` succeeds
- ✅ `cargo test` runs (tests may be empty)

---

## Phase 1: MMDB Reader Implementation

**Duration**: 3-5 days
**Goal**: Read and parse standard MMDB files

### Tasks

#### 1.1 Implement Binary Format Parsing (1 day)

**File**: `src/mmdb/format.rs`

Tasks:
1. Implement `find_metadata_marker()` - search for "\xAB\xCD\xEFMaxMind.com"
2. Implement `MmdbHeader::from_metadata()` - extract node_count, record_size, ip_version
3. Add record size helpers (24/28/32-bit reading)

Tests:
```rust
#[test]
fn test_find_metadata_marker() {
    let data = include_bytes!("../../tests/data/GeoLite2-Country-Test.mmdb");
    let marker_offset = find_metadata_marker(data);
    assert!(marker_offset.is_some());
}

#[test]
fn test_parse_header() {
    let data = include_bytes!("../../tests/data/GeoLite2-Country-Test.mmdb");
    let header = MmdbHeader::from_file(data).unwrap();
    assert!(header.node_count > 0);
    assert!(header.record_size == 24 || header.record_size == 28 || header.record_size == 32);
}
```

**Deliverable**: Can find and parse MMDB metadata, tests pass

#### 1.2 Implement Search Tree Traversal (1-2 days)

**File**: `src/mmdb/tree.rs`

Tasks:
1. Implement `SearchTree` struct
2. Implement `read_record()` for 24/28/32-bit records
3. Implement `lookup()` for IPv4 and IPv6
4. Handle IPv4-in-IPv6 trees
5. Calculate netmask from tree depth

Tests:
```rust
#[test]
fn test_lookup_ipv4() {
    let db = MmdbDatabase::open("tests/data/GeoLite2-Country-Test.mmdb").unwrap();
    let result = db.lookup("1.1.1.1".parse().unwrap()).unwrap();
    assert!(result.is_some());
}

#[test]
fn test_lookup_ipv6() {
    let db = MmdbDatabase::open("tests/data/GeoLite2-Country-Test.mmdb").unwrap();
    let result = db.lookup("2001:4860:4860::8888".parse().unwrap()).unwrap();
    assert!(result.is_some());
}

#[test]
fn test_lookup_not_found() {
    let db = MmdbDatabase::open("tests/data/GeoLite2-Country-Test.mmdb").unwrap();
    let result = db.lookup("127.0.0.1".parse().unwrap()).unwrap();
    assert!(result.is_none());
}
```

**Deliverable**: Can traverse MMDB tree and find data offsets

#### 1.3 Implement Data Section Decoder (1-2 days)

**File**: `src/mmdb/data.rs`

Tasks:
1. Implement `DataSection::decode()` main decoder
2. Implement all MMDB type decoders:
   - Extended types
   - Pointers (follow pointer chains)
   - Strings
   - Doubles/floats
   - Bytes
   - Unsigned integers (16/32/64/128)
   - Signed integers
   - Maps
   - Arrays
   - Booleans
3. Handle pointer resolution
4. Add bounds checking

Tests:
```rust
#[test]
fn test_decode_string() {
    // Test data with known string
    let data_section = DataSection::new(...);
    let value = data_section.decode(offset).unwrap();
    assert!(matches!(value, MmdbValue::String(_)));
}

#[test]
fn test_decode_map() {
    let db = MmdbDatabase::open("tests/data/GeoLite2-Country-Test.mmdb").unwrap();
    let offset = db.lookup("1.1.1.1".parse().unwrap()).unwrap().unwrap();
    let value = db.decode_data(offset).unwrap();
    
    match value {
        MmdbValue::Map(map) => {
            assert!(map.iter().any(|(k, _)| k == "country"));
        }
        _ => panic!("Expected map"),
    }
}

#[test]
fn test_decode_all_types() {
    // Test database with all MMDB types
    // Verify each type decodes correctly
}
```

**Deliverable**: Can decode all MMDB data types, tests pass

#### 1.4 Implement Metadata Parser (0.5 days)

**File**: `src/mmdb/metadata.rs`

Tasks:
1. Parse metadata map (it's just MMDB data)
2. Extract common metadata fields:
   - node_count
   - record_size
   - ip_version
   - database_type
   - build_epoch
   - description
   - languages

Tests:
```rust
#[test]
fn test_parse_metadata() {
    let db = MmdbDatabase::open("tests/data/GeoLite2-Country-Test.mmdb").unwrap();
    let metadata = db.metadata();
    assert_eq!(metadata.database_type, "GeoIP2-Country");
    assert!(metadata.build_epoch > 0);
}
```

**Deliverable**: Can parse and expose metadata

#### 1.5 Integration: Complete MMDB Reader (0.5 days)

**File**: `src/mmdb/mod.rs`

Tasks:
1. Create public `MmdbDatabase` struct
2. Implement `open()` and `from_bytes()`
3. Implement high-level `lookup()` API
4. Add convenience methods (e.g., `get_country()`, `get_value_at_path()`)

Tests:
```rust
#[test]
fn test_complete_lookup_flow() {
    let db = MmdbDatabase::open("tests/data/GeoLite2-Country-Test.mmdb").unwrap();
    let result = db.lookup("1.1.1.1".parse().unwrap()).unwrap();
    
    assert!(result.is_some());
    let (value, netmask) = result.unwrap();
    
    // Verify we got country data
    match value {
        MmdbValue::Map(map) => {
            assert!(map.iter().any(|(k, _)| k == "country"));
        }
        _ => panic!("Expected map"),
    }
    
    assert!(netmask > 0);
}
```

**Deliverable**: Working MMDB reader library

### Success Criteria
- ✅ Can open and parse real MaxMind databases
- ✅ Can lookup IPv4 and IPv6 addresses
- ✅ Can decode all MMDB data types
- ✅ Can parse metadata
- ✅ All tests pass (aim for 20+ tests)
- ✅ Compare results against libmaxminddb for validation

### Validation Command
```bash
# Test against real database
cargo test test_complete_lookup_flow -- --nocapture

# Compare with libmaxminddb
mmdblookup --file tests/data/GeoLite2-Country-Test.mmdb \
  --ip 1.1.1.1
```

---

## Phase 2: Unified Database API

**Duration**: 2-3 days
**Goal**: Unified interface for MMDB, patterns, and combined files

### Tasks

#### 2.1 Implement Format Detection (0.5 days)

**File**: `src/unified/format.rs`

Tasks:
1. Implement `detect_mmdb()` - looks for METADATA_MARKER
2. Implement `detect_patterns()` - looks for PARAGLOB magic or MMDB_PATTERN separator
3. Implement `extract_pattern_section()` - splits combined file

Tests:
```rust
#[test]
fn test_detect_mmdb_only() {
    let data = std::fs::read("tests/data/GeoLite2-Country-Test.mmdb").unwrap();
    assert!(detect_mmdb(&data));
    assert!(!detect_patterns(&data));
}

#[test]
fn test_detect_patterns_only() {
    let data = std::fs::read("tests/data/patterns.pgb").unwrap();
    assert!(!detect_mmdb(&data));
    assert!(detect_patterns(&data));
}
```

**Deliverable**: Can detect file formats

#### 2.2 Implement Unified Database (1 day)

**File**: `src/unified/database.rs`

Tasks:
1. Create `Database` struct with optional components
2. Implement `open()` with auto-detection
3. Implement `lookup_ip()`
4. Implement `match_patterns()`
5. Implement unified `lookup()` (tries IP first, then patterns)

Tests:
```rust
#[test]
fn test_open_mmdb_only() {
    let db = Database::open("tests/data/GeoLite2-Country-Test.mmdb").unwrap();
    assert!(db.has_ip_support());
    assert!(!db.has_pattern_support());
}

#[test]
fn test_open_patterns_only() {
    let db = Database::open("tests/data/patterns.pgb").unwrap();
    assert!(!db.has_ip_support());
    assert!(db.has_pattern_support());
}

#[test]
fn test_unified_lookup_ip() {
    let db = Database::open("tests/data/GeoLite2-Country-Test.mmdb").unwrap();
    let result = db.lookup("1.1.1.1").unwrap();
    assert!(matches!(result, LookupResult::Ip { .. }));
}

#[test]
fn test_unified_lookup_pattern() {
    let db = Database::open("tests/data/patterns.pgb").unwrap();
    let result = db.lookup("test.txt").unwrap();
    assert!(matches!(result, LookupResult::Pattern { .. }));
}
```

**Deliverable**: Unified API works for both formats

#### 2.3 Update Public API (0.5 days)

**File**: `src/lib.rs`

Tasks:
1. Export unified API: `pub use unified::Database;`
2. Export MMDB types: `pub use mmdb::{MmdbValue, MmdbDatabase};`
3. Update documentation

Tests:
```rust
// In examples/
#[test]
fn test_public_api() {
    use paraglob_rs::Database;
    let db = Database::open("tests/data/GeoLite2-Country-Test.mmdb").unwrap();
    // ...
}
```

**Deliverable**: Clean public API

### Success Criteria
- ✅ Unified API works for MMDB-only files
- ✅ Unified API works for pattern-only files
- ✅ Auto-detection works correctly
- ✅ All tests pass
- ✅ Documentation updated

---

## Phase 3: Combined Format Support

**Duration**: 2 days
**Goal**: Support MMDB+pattern combined files

### Tasks

#### 3.1 Implement Pattern Section Writer (1 day)

**File**: `src/unified/format.rs`

Tasks:
1. Implement `append_pattern_section()` - adds patterns to MMDB
2. Format: `[SEPARATOR][size][paraglob_data][pattern_to_offset_mapping]`
3. Verify MMDB portion remains valid
4. Verify backward compatibility

Tests:
```rust
#[test]
fn test_append_patterns_to_mmdb() {
    let mmdb_data = std::fs::read("tests/data/GeoLite2-Country-Test.mmdb").unwrap();
    let patterns = vec!["*.evil.com", "*.malware.org"];
    
    let combined = append_pattern_section(&mmdb_data, &patterns, /* data mappings */).unwrap();
    
    // Verify MMDB still readable
    let db_mmdb_only = MmdbDatabase::from_bytes(&mmdb_data).unwrap();
    let db_combined = MmdbDatabase::from_bytes(&combined).unwrap();
    
    // Same IP lookup results
    let ip: IpAddr = "1.1.1.1".parse().unwrap();
    assert_eq!(
        db_mmdb_only.lookup(ip).unwrap(),
        db_combined.lookup(ip).unwrap()
    );
}
```

**Deliverable**: Can create combined files

#### 3.2 Implement Combined File Loading (0.5 days)

**File**: `src/unified/database.rs`

Tasks:
1. Update `Database::open()` to handle combined format
2. Extract both MMDB and pattern sections
3. Set up both engines

Tests:
```rust
#[test]
fn test_load_combined_file() {
    // Create combined file
    let combined = create_test_combined_file();
    
    let db = Database::open(&combined).unwrap();
    assert!(db.has_ip_support());
    assert!(db.has_pattern_support());
}

#[test]
fn test_combined_ip_lookup() {
    let db = Database::open("tests/data/combined.mmdb").unwrap();
    let result = db.lookup("1.1.1.1").unwrap();
    assert!(matches!(result, LookupResult::Ip { .. }));
}

#[test]
fn test_combined_pattern_lookup() {
    let db = Database::open("tests/data/combined.mmdb").unwrap();
    let result = db.lookup("evil.com").unwrap();
    assert!(matches!(result, LookupResult::Pattern { .. }));
}
```

**Deliverable**: Can load and use combined files

#### 3.3 Verify Backward Compatibility (0.5 days)

Tests:
```rust
#[test]
fn test_backward_compat_with_libmaxminddb() {
    // Create combined file
    let combined = create_test_combined_file();
    std::fs::write("tests/data/test_combined.mmdb", &combined).unwrap();
    
    // Try loading with libmaxminddb (via command line)
    let output = std::process::Command::new("mmdblookup")
        .args(&["--file", "tests/data/test_combined.mmdb", "--ip", "1.1.1.1"])
        .output()
        .unwrap();
    
    assert!(output.status.success());
    // Verify it found the IP data and didn't error on extra bytes
}
```

**Deliverable**: Combined files work with standard MMDB tools

### Success Criteria
- ✅ Can create combined MMDB+pattern files
- ✅ Can load combined files
- ✅ IP lookups work in combined files
- ✅ Pattern matching works in combined files
- ✅ Backward compatible with libmaxminddb
- ✅ All tests pass

---

## Phase 4: MMDB Builder

**Duration**: 4-5 days
**Goal**: Build custom MMDB files from structured data

### Tasks

#### 4.1 Implement IP Tree Builder (2 days)

**File**: `src/mmdb/builder.rs`

Tasks:
1. Implement `MmdbBuilder` struct
2. Implement IP insertion into binary tree
3. Handle IPv4 and IPv6
4. Handle CIDR ranges
5. Optimize tree structure (minimize depth)
6. Calculate optimal record size (24/28/32)

Implementation:
```rust
pub struct MmdbBuilder {
    entries: Vec<(IpNetwork, MmdbValue)>,
    record_size: u16,  // 24, 28, or 32
}

impl MmdbBuilder {
    pub fn new() -> Self { /* ... */ }
    
    pub fn insert(&mut self, network: IpNetwork, data: MmdbValue) -> Result<(), BuildError> {
        // Insert IP/CIDR with associated data
    }
    
    pub fn build(self) -> Result<Vec<u8>, BuildError> {
        // Build the complete MMDB file
    }
}
```

Tests:
```rust
#[test]
fn test_build_simple_db() {
    let mut builder = MmdbBuilder::new();
    builder.insert("1.0.0.0/8".parse().unwrap(), 
                   MmdbValue::Map(vec![("country".into(), MmdbValue::String("US".into()))])).unwrap();
    
    let db_bytes = builder.build().unwrap();
    let db = MmdbDatabase::from_bytes(&db_bytes).unwrap();
    
    let result = db.lookup("1.2.3.4".parse().unwrap()).unwrap();
    assert!(result.is_some());
}

#[test]
fn test_build_overlapping_ranges() {
    // Test that more specific ranges override less specific
    let mut builder = MmdbBuilder::new();
    builder.insert("0.0.0.0/0".parse().unwrap(), /* default */);
    builder.insert("1.0.0.0/8".parse().unwrap(), /* specific */);
    // ...
}
```

**Deliverable**: Can build binary IP search tree

#### 4.2 Implement Data Section Writer (1 day)

**File**: `src/mmdb/builder.rs`

Tasks:
1. Implement data section encoder
2. Support all MMDB data types
3. Deduplicate identical data entries
4. Handle pointer generation
5. Optimize data layout

Tests:
```rust
#[test]
fn test_data_deduplication() {
    let mut builder = MmdbBuilder::new();
    let same_data = MmdbValue::Map(vec![("country".into(), MmdbValue::String("US".into()))]);
    
    builder.insert("1.0.0.0/8".parse().unwrap(), same_data.clone());
    builder.insert("2.0.0.0/8".parse().unwrap(), same_data.clone());
    
    let db_bytes = builder.build().unwrap();
    
    // Verify data section is deduplicated (should only store data once)
    // This is important for the pattern-to-data mapping use case!
}
```

**Deliverable**: Can encode and deduplicate data section

#### 4.3 Implement Metadata Writer (0.5 days)

**File**: `src/mmdb/builder.rs`

Tasks:
1. Generate metadata map
2. Add required fields (node_count, record_size, etc.)
3. Add optional fields (description, build_epoch, etc.)
4. Write metadata marker

Tests:
```rust
#[test]
fn test_metadata_generation() {
    let mut builder = MmdbBuilder::new();
    builder.set_database_type("Custom-DB");
    builder.set_description("en", "Test database");
    // ...
    
    let db_bytes = builder.build().unwrap();
    let db = MmdbDatabase::from_bytes(&db_bytes).unwrap();
    
    assert_eq!(db.metadata().database_type, "Custom-DB");
}
```

**Deliverable**: Can write complete metadata section

#### 4.4 Input Parsers (1 day)

**File**: `src/mmdb/input.rs`

Tasks:
1. CSV parser: IP/CIDR → data columns
2. JSON parser: flexible schema
3. Support data type inference
4. Handle nested structures

Format examples:
```csv
# CSV format
network,country,asn,org
1.0.0.0/24,US,13335,Cloudflare
8.8.8.0/24,US,15169,Google
```

```json
// JSON format
[
  {
    "network": "1.0.0.0/24",
    "data": {
      "country": "US",
      "asn": 13335,
      "org": "Cloudflare"
    }
  }
]
```

Tests:
```rust
#[test]
fn test_parse_csv() {
    let csv = "network,country\n1.0.0.0/24,US\n";
    let entries = parse_csv(csv.as_bytes()).unwrap();
    assert_eq!(entries.len(), 1);
}
```

**Deliverable**: Can load data from CSV/JSON

#### 4.5 Integration & CLI (0.5 days)

**File**: `src/cli/build_mmdb.rs`

Add `build-mmdb` subcommand:
```bash
paraglob build-mmdb data.csv -o custom.mmdb \
  --ip-column network \
  --database-type "Custom-GeoIP"

paraglob build-mmdb data.json -o custom.mmdb \
  --format json
```

Tests:
```rust
#[test]
fn test_build_mmdb_cli() {
    Command::cargo_bin("paraglob")
        .unwrap()
        .args(&["build-mmdb", "tests/data/test.csv", "-o", "test.mmdb"])
        .assert()
        .success();
    
    // Verify created file is valid
    let db = MmdbDatabase::open("test.mmdb").unwrap();
}
```

**Deliverable**: Complete MMDB builder with CLI

### Success Criteria
- ✅ Can build MMDB files from scratch
- ✅ Data deduplication works (same data = same offset)
- ✅ Can load CSV and JSON input
- ✅ Built databases are valid and readable
- ✅ CLI command works
- ✅ All tests pass

### Why This is Important

With the builder early, you can:
1. **Create combined databases** with both IPs and patterns pointing to shared data
2. **Test the unified format** end-to-end
3. **Build custom threat intelligence databases** from your own data sources
4. **Experiment with the format** without depending on MaxMind databases

**Example Use Case**:
```rust
let mut builder = MmdbBuilder::new();

// IP resolves to data at offset X
builder.insert("1.2.3.4/32".parse()?, threat_data.clone());

// Domain pattern will also point to offset X (deduplicated!)
builder.add_pattern("example.com", threat_data);

// Both queries return the same data, stored once
let db = builder.build()?;
```

---

## Phase 5: C API Extension

**Duration**: 2 days
**Goal**: Expose MMDB functionality via C FFI (native API only)

### Tasks

#### 5.1 Extend C API for Unified Database (1 day)

**File**: `src/c_api/mmdb.rs`

Tasks:
1. Add `paraglob_db_open()`
2. Add `paraglob_db_lookup()`
3. Add result accessors
4. Add `paraglob_db_close()`
5. Add builder functions

Implementation:
```rust
#[no_mangle]
pub extern "C" fn paraglob_db_open(path: *const c_char) -> *mut Database {
    // ...
}

#[no_mangle]
pub extern "C" fn paraglob_db_lookup(
    db: *mut Database,
    query: *const c_char
) -> *mut LookupResult {
    // ...
}

// Builder API
#[no_mangle]
pub extern "C" fn paraglob_builder_new() -> *mut MmdbBuilder {
    // ...
}

#[no_mangle]
pub extern "C" fn paraglob_builder_insert(
    builder: *mut MmdbBuilder,
    network: *const c_char,
    data_json: *const c_char
) -> i32 {
    // ...
}
```

Tests (in C):
```c
// tests/c_api_test.c
void test_mmdb_lookup() {
    paraglob_database_t* db = paraglob_db_open("tests/data/GeoLite2-Country-Test.mmdb");
    assert(db != NULL);
    
    paraglob_lookup_result_t* result = paraglob_db_lookup(db, "1.1.1.1");
    assert(result != NULL);
    assert(paraglob_result_has_ip_data(result));
    
    paraglob_result_free(result);
    paraglob_db_close(db);
}

void test_mmdb_builder() {
    paraglob_builder_t* builder = paraglob_builder_new();
    paraglob_builder_insert(builder, "1.0.0.0/8", "{\"country\":\"US\"}");
    // ...
}
```

**Deliverable**: C API for unified database and builder

#### 5.2 Update C Headers (0.5 days)

Tasks:
1. Update `include/paraglob_rs.h` with new functions
2. Generate with cbindgen
3. Add documentation comments
4. Add usage examples in comments

**Deliverable**: Updated C headers

#### 5.3 C++ Wrapper Updates (0.5 days)

**File**: `include/paraglob_rs.hpp`

Tasks:
1. Add C++ wrapper for Database
2. Add C++ wrapper for MmdbBuilder
3. Add RAII semantics
4. Add iterators for results

```cpp
namespace paraglob {
    class Database {
    public:
        static Database open(const std::string& path);
        LookupResult lookup(const std::string& query);
        ~Database();
    };
    
    class MmdbBuilder {
    public:
        MmdbBuilder();
        void insert(const std::string& network, const json& data);
        std::vector<uint8_t> build();
    };
}
```

**Deliverable**: C++ API updated

### Success Criteria
- ✅ C API compiles and links
- ✅ C tests pass
- ✅ C++ wrapper compiles
- ✅ Headers generated correctly
- ✅ Example C/C++ programs work

**Note**: libmaxminddb compatibility layer is deferred to future work (Phase 8+)

---

## Phase 6: CLI Tool

**Duration**: 3-4 days
**Goal**: User-friendly command-line tool

### Tasks

#### 5.1 CLI Infrastructure (0.5 days)

**File**: `src/cli/main.rs`

Tasks:
1. Set up clap argument parsing
2. Define subcommands: query, inspect, combine, build
3. Add version, help, etc.

```rust
#[derive(Parser)]
#[command(name = "paraglob")]
#[command(about = "MMDB and pattern matching tool")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Query(QueryArgs),
    Inspect(InspectArgs),
    Combine(CombineArgs),
    Build(BuildArgs),
}
```

**Deliverable**: CLI skeleton compiles

#### 5.2 Query Subcommand (1 day)

**File**: `src/cli/query.rs`

Tasks:
1. Implement `query` subcommand
2. Support IP and pattern queries
3. Pretty-print results (human-readable and JSON)
4. Add color output
5. Handle errors gracefully

```bash
paraglob query db.mmdb 1.1.1.1
paraglob query db.mmdb "*.evil.com"
paraglob query db.mmdb 1.1.1.1 --json
```

Tests:
```rust
#[test]
fn test_query_ip() {
    let output = Command::cargo_bin("paraglob")
        .unwrap()
        .args(&["query", "tests/data/GeoLite2-Country-Test.mmdb", "1.1.1.1"])
        .assert()
        .success();
    
    // Check output contains expected data
}
```

**Deliverable**: Working query command

#### 5.3 Inspect Subcommand (0.5 days)

**File**: `src/cli/inspect.rs`

Tasks:
1. Show database metadata
2. Show database type (MMDB, pattern, combined)
3. Show statistics (node count, pattern count, etc.)

```bash
paraglob inspect db.mmdb
paraglob inspect combined.mmdb --show-patterns
```

**Deliverable**: Working inspect command

#### 5.4 Combine Subcommand (0.5 days)

**File**: `src/cli/combine.rs`

Tasks:
1. Load MMDB file
2. Load pattern file or patterns from text
3. Combine them
4. Write output

```bash
paraglob combine \
  --mmdb GeoIP2-Country.mmdb \
  --patterns malicious.txt \
  --output combined.mmdb
```

**Deliverable**: Working combine command

#### 5.5 Build Subcommand (0.5 days)

**File**: `src/cli/build.rs`

Tasks:
1. Load patterns from text file (one per line)
2. Load patterns from JSON
3. Build paraglob database
4. Write output

```bash
paraglob build patterns.txt -o patterns.pgb
paraglob build patterns.json -o patterns.pgb --format json
```

**Deliverable**: Working build command

#### 5.6 Polish & UX (1 day)

Tasks:
1. Add progress bars for slow operations
2. Add colorful output
3. Improve error messages
4. Add shell completions
5. Write CLI help text

**Deliverable**: Polished CLI

### Success Criteria
- ✅ All subcommands work
- ✅ CLI tests pass
- ✅ Good error messages
- ✅ Nice formatting
- ✅ Documentation (--help) is clear

---

## Phase 7: Documentation & Polish

**Duration**: 2-3 days
**Goal**: Production-ready release

### Tasks

#### 7.1 Update Documentation (1 day)

Files to update:
- `README.md` - Add MMDB features
- `DEVELOPMENT.md` - Update architecture section
- Rust docs (`cargo doc`)
- Examples (`examples/`)

Tasks:
1. Write "Getting Started with MMDB" section
2. Write migration guide from libmaxminddb
3. Document unified API
4. Document C API
5. Document CLI tool
6. Add architecture diagrams (optional)

**Deliverable**: Comprehensive documentation

#### 7.2 Add Examples (0.5 days)

Create:
- `examples/mmdb_lookup.rs` - Basic IP lookup
- `examples/combined_db.rs` - Using combined files
- `examples/c_example.c` - C API usage
- `examples/build_combined.rs` - Creating combined files

**Deliverable**: Working examples

#### 7.3 Performance Benchmarks (0.5 days)

**File**: `benches/mmdb_bench.rs`

Tasks:
1. Benchmark IP lookups vs libmaxminddb
2. Benchmark pattern matching (already done)
3. Benchmark combined file performance
4. Document results

**Deliverable**: Performance report

#### 7.4 CI/CD Updates (0.5 days)

**File**: `.github/workflows/ci.yml`

Tasks:
1. Add MMDB tests to CI
2. Add C API tests
3. Add CLI tests
4. Test on multiple platforms (Linux, macOS, Windows)

**Deliverable**: CI passes on all platforms

#### 7.5 Final Polish (0.5 days)

Tasks:
1. Run clippy, fix warnings
2. Run rustfmt
3. Review all error messages
4. Check for TODO comments
5. Final testing pass

**Deliverable**: Clean, polished code

### Success Criteria
- ✅ All documentation complete
- ✅ Examples work
- ✅ Benchmarks run successfully
- ✅ CI passes
- ✅ Code is clean and well-documented

---

## Testing Strategy Summary

### Unit Tests (Throughout)
- Test each module independently
- Aim for >80% code coverage
- Test edge cases and error paths

### Integration Tests
- Test real MaxMind databases
- Test combined files
- Test C API from C code
- Test CLI from shell

### Compatibility Tests
- Compare results against libmaxminddb
- Verify backward compatibility
- Test on multiple platforms

### Performance Tests
- Benchmark against libmaxminddb
- Verify no regressions in pattern matching
- Test with large databases

---

## Risk Management

### High-Risk Areas

1. **MMDB Format Complexity**
   - **Risk**: More complex than expected
   - **Mitigation**: Study spec thoroughly, test early with real databases
   - **Contingency**: Focus on most common record sizes (24/28), defer 32-bit

2. **Combined Format Backward Compatibility**
   - **Risk**: Standard readers break on combined files
   - **Mitigation**: Test with libmaxminddb frequently
   - **Contingency**: Adjust separator placement, add padding if needed

3. **Performance Degradation**
   - **Risk**: Slower than libmaxminddb
   - **Mitigation**: Profile early, optimize hot paths
   - **Contingency**: Use unsafe code if needed (carefully)

### Medium-Risk Areas

1. **C API Compatibility**
   - **Risk**: Hard to match libmaxminddb exactly
   - **Mitigation**: Focus on core functions first
   - **Contingency**: Mark compatibility layer as "experimental"

2. **Windows Support**
   - **Risk**: mmap issues on Windows
   - **Mitigation**: Test on Windows early
   - **Contingency**: Document Windows limitations if needed

---

## Progress Tracking

### Daily Checklist

Each day:
1. [ ] Write code
2. [ ] Write tests
3. [ ] Run `cargo test`
4. [ ] Run `cargo clippy`
5. [ ] Update this document with progress
6. [ ] Commit work

### Phase Completion Checklist

Before marking a phase complete:
1. [ ] All tasks completed
2. [ ] All tests pass
3. [ ] Code reviewed (self or peer)
4. [ ] Documentation updated
5. [ ] Success criteria met

---

## Next Steps

1. **Review both design documents** with stakeholders
2. **Answer open questions** from design doc
3. **Get approval** to proceed
4. **Create branch**: `git checkout -b feature/mmdb-integration`
5. **Start Phase 0**: Set up foundation
6. **Daily commits**: Keep progress visible
7. **Weekly check-ins**: Review progress, adjust plan

---

## Contact & Questions

If you have questions during implementation:
- Refer to MMDB_INTEGRATION_DESIGN.md for architectural decisions
- Check MaxMind DB spec: https://maxmind.github.io/MaxMind-DB/
- Look at libmaxminddb source for reference
- Test with real databases frequently

**Remember**: Build incrementally, test continuously, commit often!
