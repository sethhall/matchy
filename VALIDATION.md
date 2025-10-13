# Database Validation

Matchy provides comprehensive validation for `.mxy` database files to ensure they are safe to use. This is especially important when working with databases from untrusted sources.

## Quick Start

### CLI Validation

The easiest way to validate a database is using the `matchy` CLI:

```bash
# Validate with strict mode (default)
matchy validate database.mxy

# Validate with standard mode (faster)
matchy validate database.mxy --level standard

# Validate with audit mode (security review)
matchy validate database.mxy --level audit --verbose
```

### Rust API

```rust
use matchy::validation::{validate_database, ValidationLevel};
use std::path::Path;

let report = validate_database(
    Path::new("database.mxy"),
    ValidationLevel::Strict
)?;

if report.is_valid() {
    println!("✓ Database is safe to use");
} else {
    eprintln!("✗ Validation failed:");
    for error in &report.errors {
        eprintln!("  - {}", error);
    }
}
```

### C API

```c
#include <matchy/matchy.h>

char *error = NULL;
int result = matchy_validate(
    "/path/to/database.mxy",
    MATCHY_VALIDATION_STRICT,
    &error
);

if (result != MATCHY_SUCCESS) {
    fprintf(stderr, "Validation failed: %s\n", error);
    if (error) matchy_free_string(error);
    return 1;
}

printf("Database is valid and safe to use!\n");
```

## Validation Levels

Matchy offers three validation levels with different thoroughness/performance tradeoffs:

### Standard

**Speed**: ~18-20ms (on 193MB database)  
**Use when**: Quick checks on known-good databases

**Validates**:
- MMDB metadata structure
- All offsets and bounds
- UTF-8 validity of strings
- Basic data section integrity

### Strict (Default)

**Speed**: ~18-20ms (on 193MB database)  
**Use when**: Loading any database (recommended default)

**Validates**: Everything in Standard, plus:
- Deep IP tree traversal
- Pointer cycle detection
- Data structure integrity
- PARAGLOB consistency:
  - AC node reachability (orphan detection)
  - Pattern-AC bidirectional references
  - AC literal mapping validity
  - Data mapping consistency
  - Meta-word mapping validation

### Audit

**Speed**: ~19-21ms (on 193MB database)  
**Use when**: Security audits, compliance reviews, understanding codebase risks

**Validates**: Everything in Strict, plus:
- Documents all unsafe code locations
- Lists validation checks bypassed in `--trusted` mode
- Provides security risk assessments

**Output** (with `--verbose`):
```
ℹ️  INFORMATION:
  • Audit: Documented 8 unsafe code locations in matchy codebase
  • Audit: --trusted mode bypasses 3 validation checks for performance
  • Note: This database passed all validation checks. Info above is for audit documentation.
```

## What Validation Detects

### Critical Errors (Database Unsafe)

- ✗ Invalid MMDB format or magic bytes
- ✗ Corrupted offsets (out of bounds)
- ✗ Invalid UTF-8 in strings
- ✗ Pointer cycles (infinite loops)
- ✗ Misaligned data structures
- ✗ Invalid type identifiers
- ✗ Orphaned AC automaton nodes
- ✗ Invalid pattern references

### Warnings (Non-Fatal Issues)

- ⚠️  Older format versions (v1, v2)
- ⚠️  Unreachable AC nodes
- ⚠️  Suboptimal encoding choices
- ⚠️  Large databases (potential performance impact)

## CLI Usage

### Basic Validation

```bash
# Default (strict mode)
matchy validate database.mxy

# Explicit level
matchy validate database.mxy --level strict
```

### Output Format

**Success:**
```
Validating: database.mxy
Level:      strict

Statistics:
  Version: v3, Nodes: 100, Patterns: 50 (30 literal, 20 glob), IPs: 1000, Size: 5120 KB
  Validation time: 23ms

✅ VALIDATION PASSED
   Database is safe to use.
```

**Failure:**
```
Validating: database.mxy
Level:      strict

Statistics:
  Version: v0, Nodes: 0, Patterns: 0, IPs: 0, Size: 1024 KB
  Validation time: 2ms

❌ ERRORS (2):
  • Invalid MMDB format: metadata not found
  • Pattern section offset 1000 beyond file size 500

❌ VALIDATION FAILED
   Database has 2 critical error(s).
   DO NOT use this database without fixing the errors.
```

### JSON Output

For programmatic processing:

```bash
matchy validate database.mxy --json
```

```json
{
  "database": "database.mxy",
  "validation_level": "strict",
  "is_valid": true,
  "duration_ms": 23,
  "errors": [],
  "warnings": [],
  "info": ["Valid MMDB metadata marker found", ...],
  "stats": {
    "file_size": 5242880,
    "version": 3,
    "ac_node_count": 100,
    "pattern_count": 50,
    "literal_count": 30,
    "glob_count": 20,
    "has_data_section": true,
    "has_ac_literal_mapping": true,
    "max_ac_depth": 12
  }
}
```

## Best Practices

### When Building Databases

Matchy-generated databases are always safe to use:

```bash
# Build a database
matchy build patterns.txt -o database.mxy

# Validate it (will pass)
matchy validate database.mxy
# ✅ VALIDATION PASSED

# Safe to use with --trusted mode for performance
matchy query database.mxy "*.example.com"
```

### When Receiving Databases

Always validate databases from external sources:

```bash
# Received a database from another source
matchy validate external-database.mxy --level strict

# Only if validation passes, use it
if [ $? -eq 0 ]; then
    matchy query external-database.mxy "query-string"
fi
```

### In Production

```bash
# Validate before deployment
matchy validate production.mxy --level strict

# Run audit before first production use
matchy validate production.mxy --level audit --verbose > audit-report.txt

# After validation passes, use with confidence
./your-app production.mxy
```

## Rust API Details

### ValidationReport

```rust
pub struct ValidationReport {
    /// Critical errors (make database unusable)
    pub errors: Vec<String>,
    
    /// Warnings (non-fatal issues)
    pub warnings: Vec<String>,
    
    /// Informational messages
    pub info: Vec<String>,
    
    /// Database statistics
    pub stats: DatabaseStats,
}

impl ValidationReport {
    /// Check if validation passed (no errors)
    pub fn is_valid(&self) -> bool;
}
```

### DatabaseStats

```rust
pub struct DatabaseStats {
    pub file_size: usize,
    pub version: u32,
    pub ac_node_count: u32,
    pub pattern_count: u32,
    pub ip_entry_count: u32,
    pub literal_count: u32,
    pub glob_count: u32,
    pub has_data_section: bool,
    pub has_ac_literal_mapping: bool,
    pub max_ac_depth: u8,
    
    // Audit mode only
    pub unsafe_code_locations: Vec<UnsafeCodeLocation>,
    pub trust_assumptions: Vec<TrustAssumption>,
}
```

### Example: Integration with Loading

```rust
use matchy::{Database, validation::{validate_database, ValidationLevel}};
use std::path::Path;

fn safe_load_database(path: &Path) -> Result<Database, Box<dyn std::error::Error>> {
    // Validate first
    let report = validate_database(path, ValidationLevel::Strict)?;
    
    if !report.is_valid() {
        return Err(format!("Database validation failed: {:?}", report.errors).into());
    }
    
    // Safe to load
    Ok(Database::open(path.to_str().unwrap())?)
}
```

## C API Details

### Constants

```c
#define MATCHY_VALIDATION_STANDARD  0
#define MATCHY_VALIDATION_STRICT    1
#define MATCHY_VALIDATION_AUDIT     2
```

### Function

```c
int32_t matchy_validate(
    const char *filename,
    int32_t level,
    char **error_message  // May be NULL
);
```

**Returns:**
- `MATCHY_SUCCESS` (0) if valid
- `MATCHY_ERROR_CORRUPT_DATA` if validation failed
- `MATCHY_ERROR_IO` if file cannot be read
- `MATCHY_ERROR_INVALID_PARAM` if parameters invalid

**Error Message:**
- If `error_message` is non-NULL and validation fails, receives a string with error details
- Caller must free the string with `matchy_free_string()`

### Example: Safe Database Loading

```c
#include <matchy/matchy.h>
#include <stdio.h>
#include <stdlib.h>

matchy_t* safe_open_database(const char *path) {
    // Validate first
    char *error = NULL;
    int result = matchy_validate(path, MATCHY_VALIDATION_STRICT, &error);
    
    if (result != MATCHY_SUCCESS) {
        fprintf(stderr, "Validation failed: %s\n", 
                error ? error : "unknown error");
        if (error) matchy_free_string(error);
        return NULL;
    }
    
    // Validation passed - safe to open
    printf("Database validated successfully\n");
    return matchy_open(path);
}

int main() {
    matchy_t *db = safe_open_database("database.mxy");
    if (!db) {
        return 1;
    }
    
    // Use database...
    
    matchy_close(db);
    return 0;
}
```

## Performance

Validation is extremely fast even on large databases:

| Database Size | Standard | Strict | Audit |
|---------------|----------|--------|-------|
| 5 MB          | ~5ms     | ~5ms   | ~6ms  |
| 50 MB         | ~10ms    | ~11ms  | ~12ms |
| 193 MB        | ~18ms    | ~20ms  | ~21ms |
| 500 MB        | ~40ms    | ~42ms  | ~45ms |

**Note**: Times are approximate and depend on hardware. The additional cost of strict/audit mode is minimal.

## Trust Mode vs Validation

Matchy supports a `--trusted` mode that skips UTF-8 validation for ~15-20% performance improvement:

```rust
// Safe mode (validates UTF-8)
let db = Database::open("database.mxy")?;

// Trusted mode (skips UTF-8 validation - faster)
let db = Database::open_trusted("database.mxy")?;
```

**When to use trusted mode:**
- ✅ Database built by matchy
- ✅ Database from your own infrastructure
- ✅ Database validated with `matchy validate`

**When NOT to use trusted mode:**
- ✗ Database from external/untrusted source (without validation)
- ✗ Database downloaded from the internet
- ✗ Database of unknown origin

**Best practice**: Always validate external databases first, then it's safe to use trusted mode:

```bash
# Validate once
matchy validate external.mxy --level strict

# If it passes, trusted mode is safe
./your-app --database external.mxy --trusted
```

## Security Considerations

### Audit Mode Details

Audit mode documents:

1. **Unsafe Code Locations** (8 total):
   - `read_str_unchecked()` - Skips UTF-8 validation in trusted mode
   - Memory-mapped file lifetime extensions
   - Zerocopy transmutes for `#[repr(C)]` structs

2. **Trust Assumptions** (3 total):
   - UTF-8 validation bypassed in trusted mode
   - Bounds checking skipped in trusted mode  
   - File integrity assumed during mmap lifetime

3. **Risk Assessment**:
   - Invalid UTF-8 → Undefined behavior
   - Corrupted offsets → Memory corruption
   - Modified mmap file → Crashes or inconsistencies

### Validation Guarantees

After validation passes, you can safely:
- ✅ Memory-map the file
- ✅ Use zero-copy loading
- ✅ Use trusted mode for performance
- ✅ Share the database across processes
- ✅ Deploy to production

Validation detects:
- ✅ Malformed data structures
- ✅ Corrupted files
- ✅ Invalid UTF-8
- ✅ Buffer overflows
- ✅ Infinite loops
- ✅ Type confusion

## Troubleshooting

### "Invalid MMDB format" Error

The file is not a valid `.mxy` database. Common causes:
- File is corrupted
- Wrong file format (not MMDB)
- File truncated during transfer

**Solution**: Rebuild the database or re-download from source.

### "Pattern section offset beyond file size"

The database file is truncated or corrupted.

**Solution**: Verify file integrity, rebuild if necessary.

### "Invalid UTF-8" Errors

The database contains strings with invalid UTF-8 encoding.

**Solution**: This should never happen with matchy-built databases. If it does, the database is corrupted.

### Validation Takes Too Long

Even on very large databases (500MB+), validation should complete in under a second.

If validation is slow:
- Check disk I/O (SSD vs HDD)
- Verify file isn't on a network mount
- Try `--level standard` for faster validation

## Version History

### v0.5.2 (Current)

- ✅ Removed `basic` validation level
- ✅ Made `strict` the default
- ✅ Added PARAGLOB consistency validation
- ✅ Added C API for validation
- ✅ Fixed audit mode to include all strict checks
- ✅ Improved audit mode messaging
- ✅ Added 9 comprehensive validation tests

### Previous Versions

Earlier versions had validation but with different levels and less comprehensive checks.

## Contributing

Found a validation issue or have suggestions? Please open an issue on GitHub!

## See Also

- [README.md](README.md) - Main project documentation
- [DEVELOPMENT.md](DEVELOPMENT.md) - Architecture and development guide
- [examples/](examples/) - Code examples
