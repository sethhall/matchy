# Validation API

Programmatic database validation for Rust applications.

## Overview

The validation API allows you to validate Matchy databases from Rust code before loading them. This is essential when working with databases from untrusted sources or when you need detailed validation reports.

```rust
use matchy::validation::{validate_database, ValidationLevel};
use std::path::Path;

let report = validate_database(Path::new("database.mxy"), ValidationLevel::Strict)?;

if report.is_valid() {
    println!("✓ Database is safe to use");
    // Safe to open and use
    let db = Database::from("database.mxy").open()?;
} else {
    eprintln!("✗ Validation failed:");
    for error in &report.errors {
        eprintln!("  - {}", error);
    }
}
```

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
    Standard,  // Basic safety checks
    Strict,    // Deep analysis (default)
}
```

### Standard

Fast validation with essential checks:
- File format structure
- Offset bounds checking
- UTF-8 string validity
- Basic graph structure

```rust
let report = validate_database(path, ValidationLevel::Standard)?;
```

### Strict (Recommended)

Comprehensive validation including:
- All standard checks
- Cycle detection
- Redundancy analysis
- Deep consistency checks
- Pattern reachability

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

### Methods

#### `is_valid()`

```rust
pub fn is_valid(&self) -> bool
```

Returns `true` if there are no errors (warnings are allowed).

```rust
if report.is_valid() {
    // Safe to use
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
use matchy::{Database, validation::{validate_database, ValidationLevel}};
use std::path::Path;

fn load_safe_database(path: &Path) -> Result<Database, Box<dyn std::error::Error>> {
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
    
    // Safe to open
    Ok(Database::from(path).open()?)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let db = load_safe_database(Path::new("database.mxy"))?;
    
    // Use database safely
    if let Some(result) = db.lookup("example.com")? {
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
    fn load(&self, path: &str) -> Result<Arc<Database>, Box<dyn std::error::Error>> {
        // Check cache first
        {
            let cache = self.databases.read().unwrap();
            if let Some(db) = cache.get(path) {
                return Ok(Arc::clone(db));
            }
        }
        
        // Validate before loading
        let report = validate_database(
            Path::new(path),
            ValidationLevel::Strict
        )?;
        
        if !report.is_valid() {
            return Err(format!(
                "Database validation failed with {} errors",
                report.errors.len()
            ).into());
        }
        
        // Load and cache
        let db = Arc::new(Database::from(path).open()?);
        
        let mut cache = self.databases.write().unwrap();
        cache.insert(path.to_string(), Arc::clone(&db));
        
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
        // Database is valid
        println!("✓ Database validated");
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

1. **Validate once per database**, not on every open
2. **Cache validation results** for repeated use
3. **Use Standard level** for trusted databases when you need faster validation
4. **Skip validation** for databases you built yourself
5. **Validate in background** for large databases

## Security Best Practices

### Always Validate Untrusted Input

```rust
fn load_user_database(user_file: &Path) -> Result<Database, Box<dyn std::error::Error>> {
    // ALWAYS validate user-provided files
    let report = validate_database(user_file, ValidationLevel::Strict)?;
    
    if !report.is_valid() {
        return Err("Untrusted database failed validation".into());
    }
    
    Database::from(user_file).open().map_err(Into::into)
}
```

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
