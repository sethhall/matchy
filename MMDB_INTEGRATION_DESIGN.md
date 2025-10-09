# MaxMind DB Integration Design Document

**Project**: Integrate MaxMind DB (MMDB) IP lookup functionality directly into paraglob-rs

**Date**: January 9, 2025

**Status**: Planning

---

## Executive Summary

This document outlines the design for integrating MaxMind DB functionality into paraglob-rs, creating a unified library that supports both IP address lookups (using MaxMind's binary tree format) and pattern matching (using Aho-Corasick automaton).

### Key Goals

1. **Native MMDB Support**: Read and query MaxMind databases (GeoIP2, ASN, custom) directly from Rust
2. **Backward Compatibility**: Support unmodified MaxMind databases from their distribution
3. **Unified Format**: Allow a single file to contain both IP lookup trees and pattern matching data
4. **Clean API**: Provide Rust, C, and C++ APIs with consistent design
5. **Easy Installation**: Eliminate C dependency, simplify build/deployment
6. **libmaxminddb Compatibility Wrapper**: Optionally provide drop-in replacement for existing code

### Benefits

- ✅ No coordination with MaxMind developers needed
- ✅ Simpler installation (pure Rust, no C compiler required for library users)
- ✅ Eliminate C code vulnerabilities
- ✅ Unified tooling for building, querying, and managing databases
- ✅ Memory safety guarantees from Rust
- ✅ Potential for better error messages and developer experience

---

## Architecture Overview

### High-Level Structure

```
┌──────────────────────────────────────────────────────────────┐
│                     paraglob-rs                               │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌────────────────────┐         ┌──────────────────────┐    │
│  │   Pattern Engine   │         │    MMDB Engine       │    │
│  │                    │         │                      │    │
│  │  • AC Automaton    │         │  • IP Search Tree    │    │
│  │  • Glob Matching   │         │  • Data Section      │    │
│  │  • String Patterns │         │  • Metadata          │    │
│  └────────────────────┘         └──────────────────────┘    │
│                                                               │
│  ┌──────────────────────────────────────────────────────┐   │
│  │           Unified Database Format                     │   │
│  │  • Supports standalone MMDB files (backward compat)   │   │
│  │  • Supports standalone pattern files (.pgb)           │   │
│  │  • Supports combined files (IP + pattern)             │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                               │
│  ┌──────────────────────────────────────────────────────┐   │
│  │                  API Layers                           │   │
│  │  • Rust API (native, idiomatic)                       │   │
│  │  • C API (FFI, paraglob-rs style)                     │   │
│  │  • C++ API (RAII wrapper)                             │   │
│  │  • libmaxminddb Compatibility API (C, drop-in)        │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                               │
└──────────────────────────────────────────────────────────────┘
```

### Database Format Strategy

We'll support **three database types** with a unified loading interface:

#### 1. **Pure MMDB Files** (100% Backward Compatible)
- Original MaxMind format, unmodified
- Can load GeoIP2, ASN, and any custom MMDB files directly
- No pattern matching support

```
┌─────────────────────────────┐
│   IP Search Tree            │
│   (Binary Tree, IP->Data)   │
├─────────────────────────────┤
│   Data Section              │
│   (Type-Length-Value pairs) │
├─────────────────────────────┤
│   Metadata Section          │
│   (Database description)    │
│   Marker: "\xAB\xCD\xEF     │
│            MaxMind.com"     │
└─────────────────────────────┘
```

#### 2. **Pattern Files with Data** (.pgb, enhanced)
- Enhanced paraglob-rs format (extends `src/offset_format.rs`)
- Pattern matching with optional associated data
- **Unified format** for standalone and MMDB-embedded use

```
┌─────────────────────────────┐
│   ParaglobHeader (extended) │  ← Magic: "PARAGLOB" (unchanged!)
│   • magic: "PARAGLOB"       │     version: 2 (bumped from 1)
│   • version: 2              │
│   • match_mode              │
│   • node counts, offsets    │
│   • data_section_offset     │  ← NEW in v2: offset to data
│   • data_section_size       │  ← NEW in v2: size (0 = no data)
│   • mapping_table_offset    │  ← NEW in v2: pattern→data map
│   • mapping_count           │  ← NEW in v2: number of mappings
├─────────────────────────────┤
│   AC Automaton Nodes        │  ← Same as v1
├─────────────────────────────┤
│   AC Edges                  │  ← Same as v1
├─────────────────────────────┤
│   Pattern Entries           │  ← Same as v1
├─────────────────────────────┤
│   Pattern Strings           │  ← Same as v1
├─────────────────────────────┤
│   Meta-word Mappings        │  ← Same as v1
├─────────────────────────────┤  ⎫
│   Data Section (optional)   │  ⎪ NEW in v2
│   • MMDB-encoded values     │  ⎬ Can be empty (size=0)
│   • Or any serialized data  │  ⎪ Or reference external data
│   • Or external offsets     │  ⎭
├─────────────────────────────┤  ⎫
│   Pattern→Data Mapping      │  ⎪ NEW in v2
│   • pattern_id → offset     │  ⎬ Always present in v2
│   • data_type flags         │  ⎪ Maps patterns to data
│   (pattern_count entries)   │  ⎭
└─────────────────────────────┘

**Backward Compatibility**:
- v1 files: Magic="PARAGLOB", version=1 (no data section)
- v2 files: Magic="PARAGLOB", version=2 (with data section)
- Magic bytes never change, only version number
```

#### 3. **Unified MMDB+Pattern Files**
- Extends MMDB format by appending pattern section
- Maintains MMDB compatibility (readers ignore extra data)
- Adds pattern matching capabilities
- **Compatible with existing libmaxminddb extension format**
- **Uses same enhanced .pgb format (v2) with external data references**

```
┌─────────────────────────────┐
│   IP Search Tree            │  ← Standard MMDB format
├─────────────────────────────┤     (readable by any MMDB reader)
│   Data Section              │  ← Shared by IPs AND patterns!
│   • IP data                 │     Same data, no duplication
│   • Pattern data            │     (deduplication in action)
├─────────────────────────────┤
│   Metadata Section          │
│   Marker: "\xAB\xCD\xEF     │  ← Standard MMDB marker (unchanged)
│            MaxMind.com"     │
└─────────────────────────────┘  ← Standard MMDB reader stops here
        ↓                            Everything below is ignored
┌─────────────────────────────┐  ← Extension starts (invisible to standard)
│   Pattern Separator         │     16 bytes: "MMDB_PATTERN\x00\x00\x00"
│   "MMDB_PATTERN\x00\x00\x00"│     (unchanged from current format)
├─────────────────────────────┤
│   Size headers (8 bytes)    │  ← Wrapper for libmaxminddb compat
│   • total_size (4 bytes)    │     (unchanged from current format)
│   • paraglob_size (4 bytes) │
├─────────────────────────────┤
│   .pgb file (Version 2)     │  ⎫
│   ┌─────────────────────────┤  ⎪
│   │ ParaglobHeader          │  ⎪ Standard .pgb v2 format
│   │   magic: "PARAGLOB"     │  ⎪ (same as standalone)
│   │   version: 2            │  ⎪
│   │ AC Nodes                │  ⎪
│   │ AC Edges                │  ⎬ Core pattern matching engine
│   │ Pattern Entries         │  ⎪ (unchanged from v1)
│   │ Pattern Strings         │  ⎪
│   │ Meta-word Mappings      │  ⎪
│   │ Data Section (empty)    │  ⎪ v2 addition: empty in MMDB case
│   │ Pattern→Data Mapping    │  ⎪ v2 addition: maps to MMDB data
│   │   → MMDB data offsets   │  ⎪   (not inline offsets)
│   └─────────────────────────┤  ⎭
└─────────────────────────────┘
```

**Key Design Points**: 
1. **MMDB format unchanged**: Standard readers stop at metadata marker ("\xAB\xCD\xEFMaxMind.com")
2. **Pattern magic unchanged**: .pgb still uses "PARAGLOB" magic, just bumps version to 2
3. **Unified format**: Same .pgb v2 format works standalone OR embedded in MMDB
4. **Backward compatible**: 
   - Standard MMDB readers ignore everything after metadata
   - Old .pgb v1 files still work (no data mapping)
   - Existing libmaxminddb extension files work (treated as v1)
5. **Data deduplication**: IPs and patterns can reference same data in MMDB data section
6. Pattern separator `MMDB_PATTERN\x00\x00\x00` proven not to conflict with MMDB data

---

## Module Structure

### New Modules to Add

```
src/
├── lib.rs                    # Existing - add MMDB exports
├── mmdb/                     # NEW MODULE
│   ├── mod.rs               # Public MMDB API
│   ├── format.rs            # MMDB binary format structures
│   ├── tree.rs              # IP search tree traversal
│   ├── data.rs              # Data section decoder
│   ├── metadata.rs          # Metadata parser
│   ├── types.rs             # MMDB data types (map, array, string, etc.)
│   └── builder.rs           # NEW: Build MMDB files from data
├── unified/                  # NEW MODULE
│   ├── mod.rs               # Unified database API
│   ├── database.rs          # Main Database struct
│   └── format.rs            # Combined format handling
├── ac_offset.rs             # Existing - Aho-Corasick
├── paraglob_offset.rs       # Existing - Pattern matching
├── c_api/                   # Existing - extend for MMDB
│   ├── mod.rs              
│   ├── mmdb.rs              # NEW: MMDB C API
│   └── compat.rs            # NEW: libmaxminddb compatibility
└── cli/                      # NEW MODULE
    ├── main.rs              # CLI entry point
    ├── build.rs             # Build databases
    ├── query.rs             # Query databases
    ├── inspect.rs           # Inspect database contents
    └── combine.rs           # Combine MMDB + patterns

examples/
├── mmdb_lookup.rs           # NEW: IP lookup example
├── combined_db.rs           # NEW: IP + pattern example
└── build_custom_mmdb.rs     # NEW: Building custom databases
```

---

## Detailed Design

### 1. MMDB Core Implementation

#### 1.1 Binary Format Structures

Based on the [MaxMind DB spec](https://maxmind.github.io/MaxMind-DB/), we need:

```rust
// src/mmdb/format.rs

/// MMDB file header (derived from metadata)
pub struct MmdbHeader {
    pub node_count: u32,
    pub record_size: u16,  // 24, 28, or 32 bits
    pub ip_version: u16,   // 4 or 6
}

/// Metadata marker: "\xAB\xCD\xEFMaxMind.com"
pub const METADATA_MARKER: &[u8] = b"\xAB\xCD\xEFMaxMind.com";

/// Search tree record (pointer or data offset)
#[derive(Debug, Clone, Copy)]
pub enum Record {
    /// Points to another node in the tree
    Node(u32),
    /// Empty record (no data)
    Empty,
    /// Points to data section
    Data(u32),
}

/// MMDB data types
#[derive(Debug, Clone)]
pub enum MmdbValue {
    Pointer(u32),
    String(String),
    Double(f64),
    Bytes(Vec<u8>),
    Uint16(u16),
    Uint32(u32),
    Map(Vec<(String, MmdbValue)>),
    Int32(i32),
    Uint64(u64),
    Uint128(u128),
    Array(Vec<MmdbValue>),
    Bool(bool),
    Float(f32),
}
```

#### 1.2 Search Tree Traversal

```rust
// src/mmdb/tree.rs

pub struct SearchTree<'a> {
    data: &'a [u8],
    node_count: u32,
    record_size: u16,
}

impl<'a> SearchTree<'a> {
    /// Lookup an IP address in the search tree
    pub fn lookup(&self, ip: IpAddr) -> Result<Option<u32>, MmdbError> {
        let bits = self.ip_to_bits(ip);
        let mut node = 0u32;
        
        for bit in bits {
            let record = self.read_record(node, bit)?;
            match record {
                Record::Node(next_node) => node = next_node,
                Record::Data(offset) => return Ok(Some(offset)),
                Record::Empty => return Ok(None),
            }
        }
        
        Ok(None)
    }
    
    fn read_record(&self, node: u32, direction: bool) -> Result<Record, MmdbError> {
        // Record size can be 24, 28, or 32 bits
        // Two records per node (left/right)
        // Implementation depends on record_size
        todo!("Read record based on record_size")
    }
}
```

#### 1.3 Data Section Decoder

```rust
// src/mmdb/data.rs

pub struct DataSection<'a> {
    data: &'a [u8],
    base_offset: usize,
}

impl<'a> DataSection<'a> {
    /// Decode a value at the given offset
    pub fn decode(&self, offset: u32) -> Result<MmdbValue, MmdbError> {
        let mut cursor = offset as usize;
        self.decode_at(&mut cursor)
    }
    
    fn decode_at(&self, cursor: &mut usize) -> Result<MmdbValue, MmdbError> {
        let ctrl_byte = self.data[*cursor];
        *cursor += 1;
        
        let type_id = ctrl_byte >> 5;
        let size = ctrl_byte & 0x1f;
        
        match type_id {
            0 => self.decode_extended(cursor, size),  // Extended type
            1 => self.decode_pointer(cursor, size),
            2 => self.decode_string(cursor, size),
            3 => self.decode_double(cursor),
            4 => self.decode_bytes(cursor, size),
            5 => self.decode_uint16(cursor),
            6 => self.decode_uint32(cursor),
            7 => self.decode_map(cursor, size),
            // ... etc
        }
    }
}
```

### 2. Unified Database API

```rust
// src/unified/database.rs

/// Unified database supporting IP lookups and/or pattern matching
pub struct Database {
    /// Memory-mapped file or in-memory buffer
    data: MmapSource,
    
    /// MMDB components (if present)
    mmdb: Option<MmdbDatabase>,
    
    /// Pattern matching components (if present)
    patterns: Option<Paraglob>,
    
    /// Metadata
    metadata: DatabaseMetadata,
}

impl Database {
    /// Open a database file (auto-detects format)
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, DatabaseError> {
        let mmap = unsafe { Mmap::open(path)? };
        Self::from_bytes(mmap.as_slice())
    }
    
    /// Load from bytes (detects format)
    pub fn from_bytes(data: &[u8]) -> Result<Self, DatabaseError> {
        let has_mmdb = Self::detect_mmdb(data);
        let has_patterns = Self::detect_patterns(data);
        
        let mmdb = if has_mmdb {
            Some(MmdbDatabase::parse(data)?)
        } else {
            None
        };
        
        let patterns = if has_patterns {
            Some(Paraglob::from_bytes(Self::extract_pattern_section(data))?)
        } else {
            None
        };
        
        Ok(Self { data, mmdb, patterns, metadata })
    }
    
    /// Lookup an IP address
    pub fn lookup_ip(&self, ip: IpAddr) -> Result<Option<MmdbValue>, DatabaseError> {
        let mmdb = self.mmdb.as_ref()
            .ok_or(DatabaseError::NoIpSupport)?;
        mmdb.lookup(ip)
    }
    
    /// Match patterns against a string
    pub fn match_patterns(&self, query: &str) -> Result<Vec<Match>, DatabaseError> {
        let patterns = self.patterns.as_ref()
            .ok_or(DatabaseError::NoPatternSupport)?;
        patterns.find_all(query)
    }
    
    /// Unified lookup: tries IP first, falls back to pattern matching
    pub fn lookup(&self, query: &str) -> Result<LookupResult, DatabaseError> {
        // Try parsing as IP
        if let Ok(ip) = query.parse::<IpAddr>() {
            if let Some(ref mmdb) = self.mmdb {
                if let Some(value) = mmdb.lookup(ip)? {
                    return Ok(LookupResult::Ip { value, netmask: /* calculate */ });
                }
            }
        }
        
        // Try pattern matching
        if let Some(ref patterns) = self.patterns {
            let matches = patterns.find_all(query)?;
            if !matches.is_empty() {
                return Ok(LookupResult::Pattern { matches });
            }
        }
        
        Ok(LookupResult::NotFound)
    }
}

pub enum LookupResult {
    Ip { value: MmdbValue, netmask: u16 },
    Pattern { matches: Vec<Match> },
    NotFound,
}
```

### 3. C API Design

We'll provide **two C APIs**:

#### 3.1 Native paraglob-rs API (Primary)

```c
// include/paraglob_rs.h (extended)

// MMDB Functions
typedef struct paraglob_database paraglob_database_t;
typedef struct paraglob_lookup_result paraglob_lookup_result_t;

// Open database (auto-detects format)
paraglob_database_t* paraglob_db_open(const char* path);

// Lookup IP or pattern
paraglob_lookup_result_t* paraglob_db_lookup(
    paraglob_database_t* db,
    const char* query
);

// Check what was found
bool paraglob_result_has_ip_data(const paraglob_lookup_result_t* result);
bool paraglob_result_has_pattern_matches(const paraglob_lookup_result_t* result);

// Get IP data
const char* paraglob_result_get_json(const paraglob_lookup_result_t* result);

// Get pattern matches
size_t paraglob_result_pattern_count(const paraglob_lookup_result_t* result);
const char* paraglob_result_pattern_at(const paraglob_lookup_result_t* result, size_t idx);

// Cleanup
void paraglob_result_free(paraglob_lookup_result_t* result);
void paraglob_db_close(paraglob_database_t* db);
```

#### 3.2 libmaxminddb Compatibility API (Optional)

```c
// include/maxminddb_compat.h

// Drop-in replacement for libmaxminddb
typedef struct MMDB_s {
    // ... same fields as original ...
    void* _internal;  // Points to Rust Database
} MMDB_s;

typedef struct MMDB_lookup_result_s {
    bool found_entry;
    MMDB_entry_s entry;
    uint16_t netmask;
} MMDB_lookup_result_s;

// Compatible API
int MMDB_open(const char *filename, uint32_t flags, MMDB_s *mmdb);
MMDB_lookup_result_s MMDB_lookup_string(
    MMDB_s *mmdb,
    const char *ipstr,
    int *gai_error,
    int *mmdb_error
);
int MMDB_get_value(MMDB_entry_s *entry, MMDB_entry_data_s *data, ...);
void MMDB_close(MMDB_s *mmdb);
const char *MMDB_strerror(int error_code);
```

**Implementation Strategy**: The compatibility layer is a **thin wrapper** that translates calls to the native Rust API. This keeps the Rust code clean while providing backward compatibility.

### 4. CLI Tool Design

```bash
# Tool name: "paraglob" or "pgdb"
paraglob --version
paraglob --help

# Query databases
paraglob query mydb.mmdb 8.8.8.8
paraglob query patterns.pgb "*.evil.com"
paraglob query combined.mmdb 1.2.3.4        # IP lookup
paraglob query combined.mmdb "test.com"     # Pattern lookup

# Inspect databases
paraglob inspect mydb.mmdb
paraglob inspect patterns.pgb
paraglob inspect combined.mmdb --show-patterns --show-metadata

# Build pattern databases
paraglob build patterns.txt -o patterns.pgb
paraglob build patterns.json -o patterns.pgb --format json

# Combine MMDB + patterns
paraglob combine \
  --mmdb GeoIP2-Country.mmdb \
  --patterns malicious.txt \
  --output combined.mmdb

# Build custom MMDB from CSV/JSON
paraglob build-mmdb data.csv -o custom.mmdb \
  --ip-column ip_address \
  --data-columns country,asn,org

# Performance testing
paraglob bench mydb.mmdb --queries queries.txt
paraglob bench patterns.pgb --queries patterns.txt
```

---

## Implementation Plan

### Phase 0: Foundation (1-2 days)
- [ ] Create module structure (`mmdb/`, `unified/`, `cli/`)
- [ ] Set up basic MMDB format constants and types
- [ ] Add dependencies: `clap` for CLI, `serde_json` for data handling

### Phase 1: MMDB Reader (3-5 days)
- [ ] Implement search tree traversal (24/28/32-bit records)
- [ ] Implement data section decoder (all MMDB data types)
- [ ] Implement metadata parser
- [ ] Add IPv4-in-IPv6 handling
- [ ] Write unit tests against real MaxMind databases

### Phase 2: Unified Database (2-3 days)
- [ ] Implement `Database` struct with format detection
- [ ] Add IP lookup path
- [ ] Add pattern lookup path
- [ ] Add unified `lookup()` that tries both
- [ ] Test with pure MMDB, pure pattern, and combined files

### Phase 3: Pattern Section Appending (2 days)
- [ ] Implement pattern section writer
- [ ] Add `combine()` function: MMDB + patterns → unified file
- [ ] Verify backward compatibility (plain MMDB readers ignore extra data)
- [ ] Test round-trip: load combined file, verify both sections work

### Phase 4: C API (2-3 days)
- [ ] Extend existing C API with MMDB functions
- [ ] Implement libmaxminddb compatibility layer
- [ ] Write C examples and tests
- [ ] Verify FFI safety

### Phase 5: CLI Tool (3-4 days)
- [ ] Implement `query` subcommand
- [ ] Implement `inspect` subcommand  
- [ ] Implement `combine` subcommand
- [ ] Implement `build` subcommand (patterns from text/JSON)
- [ ] Add nice formatting, colors, JSON output mode

### Phase 6: MMDB Builder (4-5 days) - OPTIONAL/FUTURE
- [ ] Implement IP tree building from data
- [ ] Implement data section writer
- [ ] Implement metadata writer
- [ ] Add CSV/JSON input parsers
- [ ] Write comprehensive tests

### Phase 7: Documentation & Polish (2-3 days)
- [ ] Update README with MMDB features
- [ ] Write usage examples
- [ ] Write migration guide from libmaxminddb
- [ ] Performance benchmarks (compare to libmaxminddb)
- [ ] CI/CD updates

**Total Estimated Time**: 3-4 weeks for full implementation

---

## Migration Path

### For New Projects
```rust
use paraglob_rs::Database;

// Just works!
let db = Database::open("GeoIP2-Country.mmdb")?;
let result = db.lookup_ip("8.8.8.8".parse()?)?;
```

### For Existing libmaxminddb C Code

**Option 1: Relink (zero code changes)**
```bash
# Compile existing code against paraglob-rs
gcc myapp.c -o myapp -lparaglob_rs
# Works because we provide MMDB_* functions
```

**Option 2: Use native API (recommended)**
```c
// Old libmaxminddb code:
MMDB_s mmdb;
MMDB_open("db.mmdb", MMDB_MODE_MMAP, &mmdb);
MMDB_lookup_result_s result = MMDB_lookup_string(&mmdb, "8.8.8.8", ...);

// New paraglob-rs code:
paraglob_database_t* db = paraglob_db_open("db.mmdb");
paraglob_lookup_result_t* result = paraglob_db_lookup(db, "8.8.8.8");
```

---

## Testing Strategy

### Unit Tests
- [ ] MMDB format parsing (all data types)
- [ ] Search tree traversal (24/28/32 bit records)
- [ ] IPv4 and IPv6 lookups
- [ ] Metadata parsing
- [ ] Data section decoding
- [ ] Pattern section appending
- [ ] Combined file format

### Integration Tests
- [ ] Load real MaxMind GeoIP2-Country database
- [ ] Load real MaxMind GeoIP2-City database
- [ ] Load real MaxMind ASN database
- [ ] Create combined MMDB+pattern file, verify both work
- [ ] Verify backward compatibility (standard readers ignore patterns)

### Compatibility Tests
- [ ] Compare results against libmaxminddb for same queries
- [ ] Verify C API compatibility layer works with existing code
- [ ] Test on multiple platforms (macOS, Linux, Windows)

### Performance Tests
- [ ] IP lookup throughput vs libmaxminddb
- [ ] Memory usage comparison
- [ ] Load time comparison
- [ ] Pattern matching performance (already done)

---

## Open Questions & Decisions Needed

### Q1: Combined Format - Data Duplication? ✅ DECIDED

In a combined MMDB+pattern file, pattern matches need to return data. Two options:

**Option A: Reference MMDB data section** ⬅️ **CHOSEN**
- Pattern section stores offsets into main MMDB data section
- Pro: No duplication, single source of truth
- Pro: Same data = same offset (perfect for deduplication)
- Con: Patterns must reference existing data in MMDB

**Option B: Separate pattern data section**
- Pattern section has its own data
- Pro: Patterns independent of IP data
- Con: Potential duplication

**Decision**: **Option A** - Patterns reference main data section. Pattern section stores: `(pattern_id, data_offset_in_main_section)` mapping.

**Rationale**: This enables powerful use cases where the same threat intelligence data can be referenced by both IP addresses and domain patterns. For example:
```rust
// Both point to the same data entry (deduplicated)
let threat_data = MmdbValue::Map(...);

builder.insert("1.2.3.4/32".parse()?, threat_data.clone());  // IP → offset X
builder.add_pattern("malicious.com", threat_data);          // Pattern → offset X

// File stores threat_data only once, both lookups return same entry
db.lookup("1.2.3.4")?;        // Found at offset X
db.lookup("malicious.com")?;  // Found at offset X
```

This is especially valuable for threat intelligence databases where:
- You've resolved domain names to IPs
- Both the IP and domain should return the same threat indicator
- Storage efficiency matters (avoid duplicating large datasets)

### Q2: Builder Complexity ✅ DECIDED

Building MMDB files (the tree structure) is complex. Do we need this initially?

**Options**:
1. **Phase 1**: Reader only (can't build MMDB, only read)
2. **Phase 2**: Add builder early (Phase 4)

**Decision**: **Implement builder early in Phase 4**

**Rationale**: Having the builder early provides several critical benefits:
1. **Test the unified format end-to-end** - Can create combined databases for testing
2. **Build custom threat intelligence databases** - Essential for real-world usage
3. **Enable the IP+pattern deduplication use case** - Can't test this without builder
4. **Experiment with format** - Don't depend on MaxMind databases for development
5. **Better understanding** - Building something is the best way to understand it

The builder will focus on correctness over optimization initially. Performance optimization can come later if needed.

### Q3: API Naming ✅ DECIDED

Should we rename the crate from `paraglob-rs` to something more general like `mmdb-rs` or `geoip-rs`?

**Decision**: **Keep `paraglob-rs`** - The pattern matching is the unique feature. MMDB support is an addition, not a replacement. The name reflects the original purpose while expanding capabilities.

---

### Q4: libmaxminddb Compatibility Layer Priority ✅ DECIDED

Should we implement the libmaxminddb C API compatibility layer?

**Decision**: **Defer to future work (post-Phase 7)**

**Rationale**: The native Rust/C/C++ APIs are more important. The compatibility layer is nice-to-have for drop-in replacement scenarios, but not critical for initial release. Focus on:
1. Native Rust API (idiomatic, primary)
2. Native C API (paraglob-rs style)
3. Native C++ wrapper (RAII)

The compatibility layer can be added later if there's demand from users wanting to migrate existing code.

---

## Success Criteria

This integration is successful when:

✅ Can load and query unmodified MaxMind databases (GeoIP2, ASN)
✅ Can load and query pure pattern databases (.pgb)
✅ Can load and query combined MMDB+pattern databases
✅ Combined files remain backward-compatible with standard MMDB readers
✅ Performance comparable to libmaxminddb for IP lookups
✅ CLI tool provides great UX for common operations
✅ C API compatibility layer allows relinking existing code (optional)
✅ Comprehensive test suite covers all formats
✅ Documentation clear for migration from libmaxminddb

---

## Risks & Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| MMDB format more complex than expected | High | Study spec thoroughly, test with real databases early |
| Performance worse than libmaxminddb | Medium | Profile early, optimize hot paths, use unsafe if needed |
| Compatibility issues with C API | Medium | Extensive testing, clear documentation of differences |
| Combined format breaks standard readers | High | Careful separator placement, test with libmaxminddb |
| Scope creep (too many features) | Medium | Stick to phased plan, defer builder to later phase |

---

## Next Steps

1. **Review this document** - Get feedback, answer open questions
2. **Create detailed task list** - Break down each phase into concrete tasks  
3. **Set up branch** - `feature/mmdb-integration`
4. **Start Phase 0** - Module structure and foundations
5. **Iterate** - Build incrementally, test continuously

---

## Appendix A: MMDB Format Reference

Key details from [MaxMind DB spec](https://maxmind.github.io/MaxMind-DB/):

- **Binary tree**: Each node has 2 records (left/right for 0/1 bit)
- **Record sizes**: 24, 28, or 32 bits per record
- **Node count**: Determines tree size, stored in metadata
- **Data section**: Starts after tree, uses control bytes + type-length-value encoding
- **Metadata marker**: `\xAB\xCD\xEFMaxMind.com` appears 128KB before EOF, followed by metadata map
- **IPv4 in IPv6**: IPv4-compatible-IPv6 tree structure for mixed databases

## Appendix B: References

- [MaxMind DB Spec](https://maxmind.github.io/MaxMind-DB/)
- [libmaxminddb GitHub](https://github.com/maxmind/libmaxminddb)
- [GeoIP2 Documentation](https://dev.maxmind.com/)
- Current paraglob-rs code in `src/`
- Current MMDB extensions in `../libmaxminddb/src/maxminddb-pattern.{c,h}`
