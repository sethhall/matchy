# Validation API

Programmatic database validation for Rust applications.

## Overview

The validation API checks Matchy databases from Rust code before loading them and produces a detailed report. Use `Strict` validation for databases from untrusted sources. `Standard` samples general MMDB data for trusted inputs, but a declared known schema still causes every referenced entry to be schema-validated.

```rust
use matchy::{Database, validation::{validate_database, ValidationLevel}};
use std::path::Path;

let report = validate_database(Path::new("database.mxy"), ValidationLevel::Strict)?;

if report.is_valid() {
    println!("✓ Database passed strict validation");
    // This path must still refer to the same protected bytes that were validated.
    let db = Database::from("database.mxy").open()?;
} else {
    eprintln!("✗ Validation failed:");
    for error in &report.errors {
        eprintln!("  - {}", error);
    }
}
```

Validation applies to the bytes read during that validation call. If the application later reopens a mutable path, another process could replace the file between validation and open. Protect the path from replacement, validate an immutable or atomic snapshot, or bind an application-managed validation record to a content digest and invalidate it whenever the file changes.

## Main Function

### `validate_database`

```rust
pub fn validate_database(
    path: &Path,
    level: ValidationLevel
) -> Result<ValidationReport, MatchyError>
```

Validates a database file and returns a detailed report.

**Parameters:**

- `path` - Path to the `.mxy` database file
- `level` - Validation strictness level

**Returns:** `ValidationReport` with errors, warnings, and statistics

**Example:**

```rust
use matchy::validation::{validate_database, ValidationLevel};
use std::path::Path;

let report = validate_database(
    Path::new("database.mxy"),
    ValidationLevel::Strict
)?;

println!("Validation complete:");
println!("  Errors:   {}", report.errors.len());
println!("  Warnings: {}", report.warnings.len());
println!("  {}", report.stats.summary());
```

## ValidationLevel

```rust
pub enum ValidationLevel {
    Standard,  // Runtime envelopes, sampled MMDB data, exhaustive known schemas
    Strict,    // Exhaustive MMDB tree validation plus deeper component checks
}
```

The `matchy validate` CLI defaults to `Strict`; callers of the Rust API choose a level explicitly.

### Standard

Fast integrity validation that performs:

- The top-level format and section-envelope checks used by the runtime loader
- Header, version, and section-boundary checks
- Sampled structural and value validation of reachable MMDB data from up to 20 tree nodes
- Exhaustive schema validation of referenced entries when `database_type` declares a known schema

Without a known schema, `Standard` does not exhaustively visit every tree record, data value, offset, or string. With a known schema, it still walks all referenced entries for schema conformance, so its running time can be linear in the database size.

```rust
let report = validate_database(path, ValidationLevel::Standard)?;
```

### Strict (Recommended)

Deeper validation that performs:

- All `Standard` checks
- Exhaustive checking of MMDB tree records and the reachable data references they expose
- Deeper consistency checks for extension components, mappings, and automaton structures
- The same exhaustive known-schema checks that also run in `Standard`

Use `Strict` for untrusted input. It substantially increases coverage, but the report still describes the selected checks on the bytes that were read; it is not a promise about a subsequently replaced file.

```rust
let report = validate_database(path, ValidationLevel::Strict)?;
```

## ValidationReport

```rust
pub struct ValidationReport {
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
    pub info: Vec<String>,
    pub stats: DatabaseStats,
}
```

To keep a malformed file from turning diagnostics into a memory sink, a report
retains at most 256 errors, 256 warnings, and 128 informational messages. The
last retained slot becomes a suppression message when additional findings
exist. Suppression never turns an invalid report into a valid one; statistics
continue to use saturating counters where applicable.

### Methods

#### `is_valid()`

```rust
pub fn is_valid(&self) -> bool
```

Returns `true` if the selected validation completed with no reported errors (warnings are allowed). This result applies only to the bytes read and to the coverage of the selected level.

```rust
if report.is_valid() {
    // Open only if `path` still identifies the validated, protected bytes.
    let db = Database::from(path).open()?;
}
```

### Fields

#### `errors`

Critical errors that make the database unusable:

```rust
if !report.errors.is_empty() {
    eprintln!("Critical errors found:");
    for error in &report.errors {
        eprintln!("  ❌ {}", error);
    }
}
```

#### `warnings`

Non-fatal issues that may indicate problems:

```rust
if !report.warnings.is_empty() {
    println!("Warnings:");
    for warning in &report.warnings {
        println!("  ⚠️  {}", warning);
    }
}
```

#### `info`

Informational messages about the validation process:

```rust
for info in &report.info {
    println!("  ℹ️  {}", info);
}
```

## DatabaseStats

```rust
pub struct DatabaseStats {
    pub file_size: usize,
    pub version: u32,
    pub ac_node_count: u32,
    pub pattern_count: u32,
    pub ip_entry_count: u32,
    pub literal_count: u32,
    pub glob_count: u32,
    pub string_data_size: u32,
    pub has_data_section: bool,
    pub has_ac_literal_mapping: bool,
    pub state_encoding_distribution: [u32; 4],
    pub database_type: Option<String>,
    pub schema_validated: bool,
    pub schema_entries_checked: u32,
    pub schema_validation_failures: u32,
}
```

`version` is the PARAGLOB version and is zero for an IP-only database.
`ip_entry_count` comes from MMDB metadata and is zero when that metadata is not
available. `string_data_size` and `has_data_section` describe the embedded
PARAGLOB pattern-string and inline-data sections, not the shared MMDB data
section.

### Methods

#### `summary()`

```rust
pub fn summary(&self) -> String
```

Returns a human-readable summary:

```rust
println!("{}", report.stats.summary());
// Output: "Version: v5, Nodes: 1234, Patterns: 56 (20 literal, 36 glob), IPs: 100, Size: 128 KB"
```

### Example Usage

```rust
let stats = &report.stats;

println!("Database Statistics:");
println!("  File size:    {} KB", stats.file_size / 1024);
println!("  Version:      v{}", stats.version);
println!("  Patterns:     {} ({} literal, {} glob)", 
    stats.pattern_count, stats.literal_count, stats.glob_count);
println!("  IP entries:   {}", stats.ip_entry_count);
println!("  AC nodes:     {}", stats.ac_node_count);
if let Some(database_type) = &stats.database_type {
    println!("  Type:         {}", database_type);
}
println!("  Schema check: {}", stats.schema_validated);
```

## Complete Example

```rust
use matchy::{Database, QueryResult, validation::{validate_database, ValidationLevel}};
use std::path::Path;

fn load_validated_database(path: &Path) -> Result<Database, Box<dyn std::error::Error>> {
    // Validate first
    let report = validate_database(path, ValidationLevel::Strict)?;
    
    // Check for errors
    if !report.is_valid() {
        eprintln!("Database validation failed:");
        for error in &report.errors {
            eprintln!("  ❌ {}", error);
        }
        return Err("Validation failed".into());
    }
    
    // Show warnings if any
    if !report.warnings.is_empty() {
        println!("⚠️  Warnings:");
        for warning in &report.warnings {
            println!("  • {}", warning);
        }
    }
    
    // Display stats
    println!("✓ Validation passed");
    println!("  {}", report.stats.summary());
    
    // The caller must ensure `path` cannot be replaced between validation and open.
    Ok(Database::from(path).open()?)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let db = load_validated_database(Path::new("database.mxy"))?;
    
    // Query the opened database
    if let Some(result @ (QueryResult::Ip { .. } | QueryResult::Pattern { .. })) =
        db.lookup("example.com")?
    {
        println!("Found: {:?}", result);
    }
    
    Ok(())
}
```

## Validation in Production

### Pattern: Validate Once, Use Many Times

```rust
use std::sync::{Arc, RwLock};
use std::collections::HashMap;

struct DatabaseCache {
    databases: Arc<RwLock<HashMap<String, Arc<Database>>>>,
}

impl DatabaseCache {
    fn load(
        &self,
        content_id: &str,
        path: &Path,
    ) -> Result<Arc<Database>, Box<dyn std::error::Error>> {
        // `content_id` is an application-provided digest or immutable identity.
        // Check cache first
        {
            let cache = self.databases.read().unwrap();
            if let Some(db) = cache.get(content_id) {
                return Ok(Arc::clone(db));
            }
        }
        
        // Validate a protected snapshot before loading it.
        let report = validate_database(path, ValidationLevel::Strict)?;
        
        if !report.is_valid() {
            return Err(format!(
                "Database validation failed with {} errors",
                report.errors.len()
            ).into());
        }
        
        // Load and cache only while the path is protected from replacement.
        let db = Arc::new(Database::from(path).open()?);
        
        let mut cache = self.databases.write().unwrap();
        cache.insert(content_id.to_string(), Arc::clone(&db));
        
        Ok(db)
    }
}
```

### Pattern: Background Validation

```rust
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

fn validate_database_async(
    path: String,
) -> Result<mpsc::Receiver<ValidationReport>, Box<dyn std::error::Error>> {
    let (tx, rx) = mpsc::channel();
    
    thread::spawn(move || {
        let report = validate_database(
            Path::new(&path),
            ValidationLevel::Standard
        );
        
        if let Ok(report) = report {
            let _ = tx.send(report);
        }
    });
    
    Ok(rx)
}

// Usage
let rx = validate_database_async("large.mxy".to_string())?;

// Do other work...

// Check result when ready
if let Ok(report) = rx.recv_timeout(Duration::from_secs(5)) {
    if report.is_valid() {
        // Ensure the path still names the bytes checked by the background task.
        let db = Database::from("large.mxy").open()?;
    }
}
```

## Error Handling

Validation errors are separate from database errors:

```rust
use matchy::{MatchyError, validation::{validate_database, ValidationLevel}};

match validate_database(path, ValidationLevel::Strict) {
    Ok(report) if report.is_valid() => {
        // The bytes read passed the selected validation checks.
        println!("✓ Database validation passed");
    }
    Ok(report) => {
        // Validation completed but found errors
        eprintln!("✗ Database has {} errors", report.errors.len());
        for error in &report.errors {
            eprintln!("  - {}", error);
        }
    }
    Err(MatchyError::Io(e)) => {
        eprintln!("I/O error during validation: {}", e);
    }
    Err(MatchyError::Format(e)) => {
        eprintln!("Format error during validation: {}", e);
    }
    Err(e) => {
        eprintln!("Validation error: {}", e);
    }
}
```

## Performance Considerations

**Best Practices:**

1. **Use Strict for untrusted databases** and Standard only when sampled general coverage is appropriate; known-schema checks remain exhaustive
2. **Validate immutable or protected bytes**, so the file cannot change before it is opened
3. **Manage validation caching in the application**, keyed by a digest or immutable identity and invalidated on replacement
4. **Impose file-size and resource limits** appropriate to the deployment before validation
5. **Validate in the background** only when the eventual open is tied to the same bytes

## Security Best Practices

### Always Validate Untrusted Input

```rust
fn load_user_database(user_file: &Path) -> Result<Database, Box<dyn std::error::Error>> {
    // ALWAYS validate user-provided files
    let report = validate_database(user_file, ValidationLevel::Strict)?;
    
    if !report.is_valid() {
        return Err("Untrusted database failed validation".into());
    }
    
    // `user_file` must be an immutable/protected snapshot at this point.
    Database::from(user_file).open().map_err(Into::into)
}
```

The validator's core parsing is implemented in safe Rust and malformed structures fail closed with validation errors. Separately, database open validates top-level envelopes, and query paths perform deliberate bounds checks before accessing nested serialized references. These runtime checks complement explicit validation; they do not turn a stale validation report into a report about replacement bytes.

Validation is not a general resource sandbox: callers should enforce file-size, memory, CPU-time, and concurrency limits suitable for their environment.

### Limit File Size

```rust
fn validate_with_size_limit(
    path: &Path,
    max_size: u64,
) -> Result<ValidationReport, Box<dyn std::error::Error>> {
    let metadata = std::fs::metadata(path)?;
    
    if metadata.len() > max_size {
        return Err(format!(
            "Database too large: {} bytes (max: {})",
            metadata.len(),
            max_size
        ).into());
    }
    
    validate_database(path, ValidationLevel::Strict).map_err(Into::into)
}
```

## See Also

- [matchy validate](../commands/matchy-validate.md) - CLI validation command
- [Error Handling](error-handling-ref.md) - Error types and handling
- [Binary Format](binary-format.md) - What gets validated
- [Database Querying](database-query.md) - Using validated databases
