# MMDB Integration - Quick Start Guide

**Status**: Ready to begin implementation
**Branch**: `feature/mmdb-integration`
**Timeline**: 3-4 weeks

---

## Key Decisions Made ✅

1. **Data Deduplication**: Patterns reference main MMDB data section (no duplication)
   - Enables IP + domain pointing to same threat data
   - Example: `1.2.3.4` and `malicious.com` → same data offset

2. **Builder Priority**: Implement early (Phase 4, not deferred)
   - Critical for testing unified format
   - Needed for custom threat intelligence databases

3. **API Focus**: Native APIs first, compatibility layer later
   - Rust API (primary)
   - C API (native paraglob-rs style)
   - C++ wrapper (RAII)
   - libmaxminddb compatibility (deferred to post-Phase 7)

4. **Crate Name**: Keep `paraglob-rs`
   - Pattern matching is the unique feature
   - MMDB is an addition, not replacement

---

## Phase Summary

| Phase | Duration | Description |
|-------|----------|-------------|
| **Phase 0** | 1-2 days | Foundation: modules, dependencies, test setup |
| **Phase 1** | 3-5 days | MMDB Reader: parse format, tree traversal, data decoder |
| **Phase 2** | 2-3 days | Unified API: auto-detect format, handle all three types |
| **Phase 3** | 2 days | Combined format: append patterns, verify compatibility |
| **Phase 4** | 4-5 days | **MMDB Builder: construct databases from CSV/JSON** |
| **Phase 5** | 2 days | C/C++ API: extend FFI for MMDB + builder |
| **Phase 6** | 3-4 days | CLI Tool: query, inspect, combine, build commands |
| **Phase 7** | 2-3 days | Documentation, examples, benchmarks, polish |

**Total**: 19-24 days (3-4 weeks)

---

## Three Database Formats

### 1. Pure MMDB (Backward Compatible)
```
┌─────────────────┐
│ IP Search Tree  │  ← Standard MaxMind format
├─────────────────┤     Works with any MMDB reader
│ Data Section    │
├─────────────────┤
│ Metadata        │
└─────────────────┘
```

### 2. Pattern Files with Data (.pgb v2)
```
┌─────────────────┐
│ Header (v2)     │  ← Enhanced paraglob format
│ magic:PARAGLOB  │     Magic bytes unchanged!
│ version:2       │     Just bumped version number
├─────────────────┤
│ AC Automaton    │  ← Pattern matching engine
├─────────────────┤
│ Pattern Strings │
├─────────────────┤
│ Data (optional) │  ← NEW: Can store inline data
├─────────────────┤     Or reference external data
│ Pattern→Data   │  ← NEW: Maps patterns to data
└─────────────────┘
```

### 3. Combined (New!)
```
┌─────────────────┐
│ IP Search Tree  │  ← Standard MMDB (unchanged)
├─────────────────┤
│ Data Section    │  ← Shared by IP + patterns!
│ (both IP and    │     Deduplicated storage
│  pattern data)  │
├─────────────────┤
│ Metadata marker │  ← "\xAB\xCD\xEFMaxMind.com"
└─────────────────┘  ← Standard MMDB reader stops here
      ↓
┌─────────────────┐  ← Extension (ignored by standard readers)
│ "MMDB_PATTERN"  │     16-byte separator (unchanged)
├─────────────────┤
│ Size wrappers   │     8 bytes (unchanged)
├─────────────────┤
│ .pgb v2 file    │  ← Same as standalone!
│ magic:PARAGLOB  │     Magic bytes unchanged
│ version:2       │     Version bumped to 2
│ AC nodes        │     Pattern matcher
│ Data (empty)    │     Empty - refs MMDB data
│ Pattern→Data   │     Maps to MMDB offsets
└─────────────────┘
```

**Key Points**:
1. **MMDB marker unchanged**: "\xAB\xCD\xEFMaxMind.com" stays the same
2. **.pgb magic unchanged**: "PARAGLOB" stays the same, version 1→2
3. **Same .pgb format** standalone or embedded - unified!
4. **Backward compatible**: Standard MMDB readers ignore extension

---

## Key Use Case: Threat Intelligence

```rust
// Build a database with shared data
let mut builder = MmdbBuilder::new();

let threat_data = MmdbValue::Map(vec![
    ("threat_level".into(), MmdbValue::String("high".into())),
    ("category".into(), MmdbValue::String("malware".into())),
    ("first_seen".into(), MmdbValue::String("2025-01-01".into())),
]);

// IP address resolves to this data
builder.insert("1.2.3.4/32".parse()?, threat_data.clone())?;

// Domain pattern ALSO points to same data (deduplicated!)
builder.add_pattern("*.malicious.com", threat_data)?;

let db = builder.build()?;

// Both queries return the same data entry (stored only once)
assert_eq!(
    db.lookup("1.2.3.4")?,      // IP lookup → offset X
    db.lookup("evil.malicious.com")?  // Pattern match → offset X
);
```

**Benefits**:
- Single source of truth for threat indicators
- Efficient storage (no duplication)
- Easy updates (change data once, affects both IP and pattern)
- Natural fit for resolved domains

---

## API Examples

### Rust API
```rust
use paraglob_rs::Database;

// Auto-detects format (MMDB, pattern, or combined)
let db = Database::open("database.mmdb")?;

// Unified lookup (tries IP first, then patterns)
match db.lookup("1.2.3.4")? {
    LookupResult::Ip { value, netmask } => {
        println!("IP found: {:?} (/{netmask})", value);
    }
    LookupResult::Pattern { matches } => {
        println!("Pattern matches: {:?}", matches);
    }
    LookupResult::NotFound => {
        println!("No match");
    }
}

// Explicit IP lookup
let country = db.lookup_ip("8.8.8.8".parse()?)?;

// Explicit pattern matching
let matches = db.match_patterns("*.evil.com")?;
```

### C API
```c
#include "paraglob_rs.h"

// Open database
paraglob_database_t* db = paraglob_db_open("database.mmdb");

// Lookup
paraglob_lookup_result_t* result = paraglob_db_lookup(db, "1.2.3.4");

if (paraglob_result_has_ip_data(result)) {
    const char* json = paraglob_result_get_json(result);
    printf("Found: %s\n", json);
}

paraglob_result_free(result);
paraglob_db_close(db);
```

### CLI
```bash
# Query databases
paraglob query database.mmdb 1.2.3.4
paraglob query database.mmdb "*.evil.com"

# Inspect database
paraglob inspect database.mmdb --show-patterns

# Build MMDB from CSV
paraglob build-mmdb threats.csv -o threats.mmdb \
  --ip-column ip_address \
  --database-type "Threat-Intel"

# Combine MMDB + patterns
paraglob combine \
  --mmdb GeoIP2.mmdb \
  --patterns malicious-domains.txt \
  --output combined.mmdb

# Build pattern database
paraglob build patterns.txt -o patterns.pgb
```

---

## Getting Started

### 1. Review Documents
- [ ] Read `MMDB_INTEGRATION_DESIGN.md` (architecture, detailed design)
- [ ] Read `MMDB_STAGING_PLAN.md` (actionable tasks, testing)
- [ ] This document (quick reference)

### 2. Prepare Environment
```bash
cd /Users/seth/factual/mmdb_with_strings/paraglob-rs

# Create branch
git checkout -b feature/mmdb-integration

# Verify starting point
cargo test
cargo build --release
```

### 3. Start Phase 0
```bash
# Create module structure
mkdir -p src/mmdb src/unified src/cli

# Update Cargo.toml (see staging plan)
# Add: clap, serde, serde_json, anyhow, thiserror

# Download test database
mkdir -p tests/data
curl -o tests/data/GeoLite2-Country-Test.mmdb \
  https://github.com/maxmind/MaxMind-DB/raw/main/test-data/GeoIP2-Country-Test.mmdb

# Verify setup
cargo check
```

### 4. Work Incrementally
- Complete one phase at a time
- Write tests as you go
- Commit frequently
- Update staging plan with progress

---

## Testing Strategy

### Test with Real Databases
- GeoLite2-Country-Test.mmdb (small, fast)
- GeoIP2-Country.mmdb (real world)
- GeoIP2-City.mmdb (complex)
- ASN database (different structure)

### Compare Against libmaxminddb
```bash
# Your implementation
paraglob query db.mmdb 1.2.3.4

# Reference (libmaxminddb)
mmdblookup --file db.mmdb --ip 1.2.3.4

# Should match!
```

### Backward Compatibility Test
```rust
// Create combined file with patterns
let combined = create_combined_file(mmdb_data, patterns);

// Verify standard MMDB reader still works
std::process::Command::new("mmdblookup")
    .args(&["--file", "combined.mmdb", "--ip", "1.1.1.1"])
    .assert()
    .success();
```

---

## Success Criteria

Before merging to main:
- [ ] Can read unmodified MaxMind databases (GeoIP2, ASN)
- [ ] Can read pure pattern files (.pgb)
- [ ] Can read combined MMDB+pattern files
- [ ] Combined files work with standard MMDB readers (backward compatible)
- [ ] Can build custom MMDB files from CSV/JSON
- [ ] Data deduplication works (IP + pattern → same offset)
- [ ] Performance comparable to libmaxminddb for IP lookups
- [ ] C and C++ APIs work
- [ ] CLI tool has good UX
- [ ] All tests pass (unit, integration, compatibility)
- [ ] Documentation complete
- [ ] Benchmarks run successfully

---

## References

- **Design Doc**: `MMDB_INTEGRATION_DESIGN.md`
- **Staging Plan**: `MMDB_STAGING_PLAN.md`
- **MaxMind DB Spec**: https://maxmind.github.io/MaxMind-DB/
- **libmaxminddb**: https://github.com/maxmind/libmaxminddb
- **Current Code**: `src/` (paraglob-rs implementation)
- **Current Extensions**: `../libmaxminddb/src/maxminddb-pattern.{c,h}`

---

## Daily Workflow

```bash
# Morning: Review progress
less MMDB_STAGING_PLAN.md  # Check current phase

# Work on current task
vim src/mmdb/tree.rs        # Implement

# Test continuously
cargo test
cargo clippy

# Afternoon: Commit progress
git add -A
git commit -m "Phase 1.2: Implement search tree traversal"

# Update tracking
vim MMDB_STAGING_PLAN.md    # Check off completed tasks

# Evening: Push work
git push origin feature/mmdb-integration
```

---

## Questions During Implementation?

1. **Check design doc** for architectural decisions
2. **Check staging plan** for specific tasks and tests
3. **Check MaxMind DB spec** for format details
4. **Compare with libmaxminddb** source code for reference
5. **Test with real databases** early and often

---

**Ready to begin!** 🚀

Start with Phase 0 when you're ready. The plan is comprehensive, but feel free to adjust as you discover new information during implementation.
