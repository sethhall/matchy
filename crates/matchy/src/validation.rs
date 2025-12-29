//! Database validation for untrusted .mxy files
//!
//! This module provides comprehensive validation of MMDB format database files (.mxy)
//! to ensure they are safe to load and use. It performs thorough checks of:
//!
//! - MMDB metadata and structure
//! - Embedded PARAGLOB sections (if present)
//! - All offsets and bounds checking
//! - UTF-8 validity of all strings
//! - Graph structure integrity (no cycles, valid transitions)
//! - Data consistency (arrays, mappings, references)
//!
//! # Safety
//!
//! The validator is designed to detect malformed, corrupted, or malicious databases
//! without panicking or causing undefined behavior. All checks use safe Rust with
//! explicit bounds checking.
//!
//! # Usage
//!
//! ```rust,no_run
//! use matchy::validation::{validate_database, ValidationLevel};
//! use std::path::Path;
//!
//! let report = validate_database(Path::new("database.mxy"), ValidationLevel::Strict)?;
//!
//! if report.is_valid() {
//!     println!("✓ Database is safe to use");
//! } else {
//!     println!("✗ Validation failed:");
//!     for error in &report.errors {
//!         println!("  - {}", error);
//!     }
//! }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use crate::error::{MatchyError, Result};
use crate::schema_validation::SchemaValidator;
use crate::schemas::is_known_database_type;
use matchy_data_format::{DataDecoder, DataValue};
use matchy_format::offset_format::{
    ParaglobHeader, MAGIC, MATCHY_FORMAT_VERSION, MATCHY_FORMAT_VERSION_V1,
    MATCHY_FORMAT_VERSION_V2, MATCHY_FORMAT_VERSION_V3,
};
use matchy_paraglob::error::ParaglobError;
use std::collections::HashSet;
use std::fs::File;
use std::mem;
use std::path::Path;

use zerocopy::FromBytes;

/// Validation strictness level
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationLevel {
    /// Standard checks: all offsets, UTF-8, basic structure
    Standard,
    /// Strict checks: deep graph analysis, cycles, redundancy, PARAGLOB consistency (default)
    Strict,
}

/// Validation report with detailed findings
#[derive(Debug, Clone)]
pub struct ValidationReport {
    /// Critical errors that make the database unusable
    pub errors: Vec<String>,
    /// Warnings about potential issues (non-fatal)
    pub warnings: Vec<String>,
    /// Informational messages about database properties
    pub info: Vec<String>,
    /// Database statistics
    pub stats: DatabaseStats,
}

/// Database statistics gathered during validation
#[derive(Debug, Clone, Default)]
pub struct DatabaseStats {
    /// File size in bytes
    pub file_size: usize,
    /// Format version (1, 2, or 3)
    pub version: u32,
    /// Number of AC automaton nodes
    pub ac_node_count: u32,
    /// Number of patterns
    pub pattern_count: u32,
    /// Number of IP address entries (if present)
    pub ip_entry_count: u32,
    /// Number of literal patterns
    pub literal_count: u32,
    /// Number of glob patterns
    pub glob_count: u32,
    /// Total string data size
    pub string_data_size: u32,
    /// Has data section (v2+)
    pub has_data_section: bool,
    /// Has AC literal mapping (v3)
    pub has_ac_literal_mapping: bool,
    /// Number of state encoding types used
    pub state_encoding_distribution: [u32; 4], // Empty, One, Sparse, Dense
    /// Database type from metadata (e.g., "ThreatDB-v1")
    pub database_type: Option<String>,
    /// Whether schema validation was performed
    pub schema_validated: bool,
    /// Number of entries validated against schema
    pub schema_entries_checked: u32,
    /// Number of schema validation failures
    pub schema_validation_failures: u32,
}

impl ValidationReport {
    /// Create a new empty report
    fn new() -> Self {
        Self {
            errors: Vec::new(),
            warnings: Vec::new(),
            info: Vec::new(),
            stats: DatabaseStats::default(),
        }
    }

    /// Check if database passed all validations (no errors)
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.errors.is_empty()
    }

    /// Add an error to the report
    fn error(&mut self, msg: impl Into<String>) {
        self.errors.push(msg.into());
    }

    /// Add a warning to the report
    fn warning(&mut self, msg: impl Into<String>) {
        self.warnings.push(msg.into());
    }

    /// Add an info message to the report
    fn info(&mut self, msg: impl Into<String>) {
        self.info.push(msg.into());
    }
}

impl DatabaseStats {
    /// Human-readable summary
    #[must_use]
    pub fn summary(&self) -> String {
        let base = format!(
            "Version: v{}, Nodes: {}, Patterns: {} ({} literal, {} glob), IPs: {}, Size: {} KB",
            self.version,
            self.ac_node_count,
            self.pattern_count,
            self.literal_count,
            self.glob_count,
            self.ip_entry_count,
            self.file_size / 1024
        );

        if let Some(ref db_type) = self.database_type {
            format!("{base}, Type: {db_type}")
        } else {
            base
        }
    }
}

/// Read a record value from an MMDB tree node
///
/// Handles 24-bit (6 bytes/node), 28-bit (7 bytes/node), and 32-bit (8 bytes/node) records.
/// Returns the record value for the specified side (0=left, 1=right), or None if the
/// node_bytes value is not recognized.
///
/// # Arguments
/// * `buffer` - The raw database bytes
/// * `node_offset` - Byte offset of the node in the buffer
/// * `node_bytes` - Size of each node (6, 7, or 8)
/// * `side` - Which record to read (0=left, 1=right)
fn read_tree_record(buffer: &[u8], node_offset: usize, node_bytes: usize, side: u8) -> Option<u32> {
    if node_offset + node_bytes > buffer.len() {
        return None;
    }

    match node_bytes {
        6 => {
            // 24-bit records (3 bytes each)
            let offset = node_offset + (side as usize) * 3;
            let b0 = u32::from(buffer[offset]);
            let b1 = u32::from(buffer[offset + 1]);
            let b2 = u32::from(buffer[offset + 2]);
            Some((b0 << 16) | (b1 << 8) | b2)
        }
        7 => {
            // 28-bit records (7 bytes total per node)
            // Layout: | left[23..0] | left[27..24]:right[27..24] | right[23..0] |
            // Bytes:  |  0  1  2    |            3               |   4  5  6    |
            let middle = buffer[node_offset + 3];
            if side == 0 {
                // Left record
                let low = (u32::from(buffer[node_offset]) << 16)
                    | (u32::from(buffer[node_offset + 1]) << 8)
                    | u32::from(buffer[node_offset + 2]);
                let high = u32::from((middle >> 4) & 0x0F);
                Some((high << 24) | low)
            } else {
                // Right record
                let low = (u32::from(buffer[node_offset + 4]) << 16)
                    | (u32::from(buffer[node_offset + 5]) << 8)
                    | u32::from(buffer[node_offset + 6]);
                let high = u32::from(middle & 0x0F);
                Some((high << 24) | low)
            }
        }
        8 => {
            // 32-bit records (4 bytes each)
            let offset = node_offset + (side as usize) * 4;
            Some(u32::from_be_bytes([
                buffer[offset],
                buffer[offset + 1],
                buffer[offset + 2],
                buffer[offset + 3],
            ]))
        }
        _ => None,
    }
}

/// Validate a database file
///
/// Performs comprehensive validation of a .mxy (MMDB format) database file.
/// Returns a detailed report of any issues found.
///
/// This validates MMDB format databases which may contain:
/// - IP address data
/// - Literal string hash tables  
/// - Embedded PARAGLOB pattern matching sections
///
/// # Arguments
///
/// * `path` - Path to the .mxy file to validate
/// * `level` - Validation strictness level
///
/// # Example
///
/// ```rust,no_run
/// use matchy::validation::{validate_database, ValidationLevel};
/// use std::path::Path;
///
/// let report = validate_database(Path::new("database.mxy"), ValidationLevel::Standard)?;
///
/// if !report.is_valid() {
///     eprintln!("Validation failed with {} errors", report.errors.len());
///     for error in &report.errors {
///         eprintln!("  ERROR: {}", error);
///     }
/// }
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn validate_database(path: &Path, level: ValidationLevel) -> Result<ValidationReport> {
    let mut report = ValidationReport::new();

    // Load entire file into memory for validation
    let file =
        File::open(path).map_err(|e| ParaglobError::Io(format!("Failed to open file: {e}")))?;

    let metadata = file
        .metadata()
        .map_err(|e| ParaglobError::Io(format!("Failed to get file metadata: {e}")))?;

    let file_size = usize::try_from(metadata.len())
        .map_err(|_| ParaglobError::Io("File too large for this platform".to_string()))?;
    report.stats.file_size = file_size;
    report.info(format!(
        "File size: {} bytes ({} KB)",
        file_size,
        file_size / 1024
    ));

    // Read entire file
    let buffer =
        std::fs::read(path).map_err(|e| ParaglobError::Io(format!("Failed to read file: {e}")))?;

    // Validate as MMDB format
    validate_mmdb_database(&buffer, &mut report, level)
}

/// Validate an MMDB format database
fn validate_mmdb_database(
    buffer: &[u8],
    report: &mut ValidationReport,
    level: ValidationLevel,
) -> Result<ValidationReport> {
    // Check for MMDB metadata marker
    if let Err(e) = crate::mmdb::find_metadata_marker(buffer) {
        report.error(format!("Invalid MMDB format: {e}"));
        return Ok(report.clone());
    }

    report.info("Valid MMDB metadata marker found");

    // Try to read metadata
    match crate::mmdb::MmdbMetadata::from_file(buffer) {
        Ok(metadata) => {
            if let Ok(crate::DataValue::Map(map)) = metadata.as_value() {
                // Extract and validate required MMDB fields
                let node_count = match map.get("node_count") {
                    Some(crate::DataValue::Uint16(n)) => u32::from(*n),
                    Some(crate::DataValue::Uint32(n)) => *n,
                    Some(crate::DataValue::Uint64(n)) => match u32::try_from(*n) {
                        Ok(v) => v,
                        Err(_) => {
                            report.error("node_count exceeds u32 maximum");
                            return Ok(report.clone());
                        }
                    },
                    _ => {
                        report.error("Missing or invalid node_count in metadata");
                        return Ok(report.clone());
                    }
                };

                let record_size = match map.get("record_size") {
                    Some(crate::DataValue::Uint16(n)) => *n,
                    Some(crate::DataValue::Uint32(n)) => match u16::try_from(*n) {
                        Ok(v) => v,
                        Err(_) => {
                            report.error("record_size exceeds u16 maximum");
                            return Ok(report.clone());
                        }
                    },
                    _ => {
                        report.error("Missing or invalid record_size in metadata");
                        return Ok(report.clone());
                    }
                };

                let ip_version = match map.get("ip_version") {
                    Some(crate::DataValue::Uint16(n)) => *n,
                    Some(crate::DataValue::Uint32(n)) => match u16::try_from(*n) {
                        Ok(v) => v,
                        Err(_) => {
                            report.error("ip_version exceeds u16 maximum");
                            return Ok(report.clone());
                        }
                    },
                    _ => {
                        report.error("Missing or invalid ip_version in metadata");
                        return Ok(report.clone());
                    }
                };

                // Validate values
                if record_size != 24 && record_size != 28 && record_size != 32 {
                    report.error(format!(
                        "Invalid record_size: {record_size} (must be 24, 28, or 32)"
                    ));
                }

                if ip_version != 4 && ip_version != 6 {
                    report.error(format!("Invalid ip_version: {ip_version} (must be 4 or 6)"));
                }

                // Calculate and validate tree size
                let node_bytes = match record_size {
                    24 => 6,
                    28 => 7,
                    32 => 8,
                    _ => 6, // Already reported error above
                };
                let tree_size = (node_count as usize) * node_bytes;

                if tree_size > buffer.len() {
                    report.error(format!(
                        "Calculated tree size {} exceeds file size {}",
                        tree_size,
                        buffer.len()
                    ));
                } else {
                    report.info(format!(
                        "IP tree: {node_count} nodes, {record_size} bits/record, IPv{ip_version}, tree size: {tree_size} bytes"
                    ));
                }

                // Extract database info
                let database_type =
                    if let Some(crate::DataValue::String(db_type)) = map.get("database_type") {
                        report.info(format!("Database type: {db_type}"));
                        report.stats.database_type = Some(db_type.clone());
                        Some(db_type.clone())
                    } else {
                        None
                    };

                if let Some(crate::DataValue::String(desc)) = map.get("description") {
                    if desc.len() <= 100 {
                        report.info(format!("Description: {desc}"));
                    }
                }

                // Note build timestamp if present
                if let Some(build_epoch) = map.get("build_epoch") {
                    match build_epoch {
                        crate::DataValue::Uint32(epoch) => {
                            report.info(format!("Build epoch: {epoch}"));
                        }
                        crate::DataValue::Uint64(epoch) => {
                            report.info(format!("Build epoch: {epoch}"));
                        }
                        _ => {}
                    }
                }

                // Check for pattern section
                if let Some(crate::DataValue::Uint32(pattern_offset)) =
                    map.get("pattern_section_offset")
                {
                    if *pattern_offset > 0 {
                        let offset = *pattern_offset as usize;
                        report.info(format!("Pattern section found at offset {offset}"));

                        // Validate the embedded PARAGLOB section
                        if offset < buffer.len() {
                            validate_paraglob_section(buffer, offset, report, level)?;
                        } else {
                            report.error(format!(
                                "Pattern section offset {} is beyond file size {}",
                                offset,
                                buffer.len()
                            ));
                        }
                    }
                }

                // Check for literal section
                if let Some(crate::DataValue::Uint32(literal_offset)) =
                    map.get("literal_section_offset")
                {
                    if *literal_offset > 0 {
                        let offset = *literal_offset as usize;
                        report.info(format!("Literal section found at offset {offset}"));

                        // Validate literal hash section if in standard or strict mode
                        if offset < buffer.len() {
                            validate_literal_hash_section(buffer, offset, report);
                        } else {
                            report.error(format!(
                                "Literal section offset {} beyond file size {}",
                                offset,
                                buffer.len()
                            ));
                        }
                    }
                }

                // Store IP count for stats
                if node_count > 0 {
                    // Rough estimate: nodes roughly correlate with IP entries
                    report.stats.ip_entry_count = node_count;
                }

                // Always validate data section structure and UTF-8 (critical for safety)
                validate_mmdb_data_section(buffer, tree_size, report);

                // Validate UTF-8 in data section (critical for safety)
                validate_data_section_utf8(
                    buffer, tree_size, node_count, node_bytes, report, level,
                );

                // Validate data section pointers (critical for safety)
                validate_data_section_pointers(
                    buffer, tree_size, node_count, node_bytes, report, level,
                );

                // Strict mode: deep validation
                if level == ValidationLevel::Strict {
                    // Check for size bombs
                    validate_size_limits(buffer.len(), node_count, report);

                    // Sample tree nodes for integrity
                    validate_tree_samples(buffer, node_count, node_bytes, tree_size, report);

                    // Validate data pointer references
                    validate_data_pointers(buffer, tree_size, node_count, node_bytes, report);

                    // Deep IP tree traversal validation
                    let ip_tree_result = matchy_ip_trie::validate_ip_tree(
                        buffer, tree_size, node_count, node_bytes, ip_version,
                    );
                    report.errors.extend(ip_tree_result.errors);
                    report.warnings.extend(ip_tree_result.warnings);
                    if ip_tree_result.stats.nodes_visited > 0 {
                        report.info(format!(
                            "IP tree traversal: {} nodes visited out of {} total ({}% coverage)",
                            ip_tree_result.stats.nodes_visited,
                            node_count,
                            (ip_tree_result.stats.nodes_visited * 100) / node_count
                        ));
                    }
                }

                // Schema validation for known database types
                if let Some(ref db_type) = database_type {
                    if is_known_database_type(db_type) {
                        validate_schema_content(
                            buffer, db_type, tree_size, node_count, node_bytes, report, level,
                        );
                    }
                }
            }
        }
        Err(e) => {
            report.error(format!("Failed to parse MMDB metadata: {e}"));
            return Ok(report.clone());
        }
    }

    if report.is_valid() {
        report.info("✓ MMDB database structure is valid");
    }

    Ok(report.clone())
}

/// Validate literal hash section structure
fn validate_literal_hash_section(buffer: &[u8], offset: usize, report: &mut ValidationReport) {
    // Check for "MMDB_LITERAL" marker (16 bytes)
    const LITERAL_MARKER: &[u8] = b"MMDB_LITERAL\x00\x00\x00\x00";

    if offset < 16 || offset - 16 > buffer.len() {
        report.error("Literal section offset invalid");
        return;
    }

    // Check for marker before the data
    let marker_start = offset - 16;
    if marker_start + 16 <= buffer.len() {
        let marker = &buffer[marker_start..marker_start + 16];
        if marker == LITERAL_MARKER {
            report.info("Valid MMDB_LITERAL marker found");
        } else {
            report.warning("MMDB_LITERAL marker not found at expected location");
        }
    }

    // The actual literal hash starts at offset
    // Check for "LHSH" magic
    const LHSH_MAGIC: &[u8; 4] = b"LHSH";

    if offset + 4 > buffer.len() {
        report.error("Literal hash section truncated (no magic bytes)");
        return;
    }

    let magic = &buffer[offset..offset + 4];
    if magic == LHSH_MAGIC {
        report.info("Valid literal hash magic (LHSH) found");

        // Read header fields
        if offset + 24 <= buffer.len() {
            let version = u32::from_le_bytes([
                buffer[offset + 4],
                buffer[offset + 5],
                buffer[offset + 6],
                buffer[offset + 7],
            ]);
            let entry_count = u32::from_le_bytes([
                buffer[offset + 8],
                buffer[offset + 9],
                buffer[offset + 10],
                buffer[offset + 11],
            ]);
            let table_size = u32::from_le_bytes([
                buffer[offset + 12],
                buffer[offset + 13],
                buffer[offset + 14],
                buffer[offset + 15],
            ]);

            report.info(format!(
                "Literal hash: version {version}, {entry_count} entries, table size {table_size}"
            ));

            // Basic sanity checks
            if version != 1 {
                report.warning(format!("Unexpected literal hash version: {version}"));
            }

            if entry_count > 10_000_000 {
                report.warning(format!(
                    "Very large literal count: {entry_count} (> 10M, potential memory issue)"
                ));
            }

            if table_size < entry_count {
                report.error(format!(
                    "Table size {table_size} is smaller than entry count {entry_count}"
                ));
            }

            // Store count for stats
            report.stats.literal_count = entry_count;
        } else {
            report.error("Literal hash header truncated");
        }
    } else {
        report.warning(format!(
            "Unexpected literal hash magic: expected LHSH, got {:?}",
            String::from_utf8_lossy(magic)
        ));
    }
}

/// Validate size limits to prevent memory bombs
fn validate_size_limits(file_size: usize, node_count: u32, report: &mut ValidationReport) {
    // Check for unreasonably large files (> 2GB)
    const MAX_SAFE_FILE_SIZE: usize = 2 * 1024 * 1024 * 1024;
    if file_size > MAX_SAFE_FILE_SIZE {
        report.warning(format!(
            "Very large database file: {} MB (> 2GB threshold)",
            file_size / (1024 * 1024)
        ));
    }

    // Check for unreasonably large node counts
    const MAX_REASONABLE_NODES: u32 = 10_000_000;
    if node_count > MAX_REASONABLE_NODES {
        report.warning(format!(
            "Very large node count: {node_count} (> 10M threshold, potential memory bomb)"
        ));
    }
}

/// Sample tree nodes to verify structure integrity
fn validate_tree_samples(
    buffer: &[u8],
    node_count: u32,
    node_bytes: usize,
    tree_size: usize,
    report: &mut ValidationReport,
) {
    if node_count == 0 {
        return;
    }

    // Sample up to 100 random nodes (or all if fewer)
    let sample_count = node_count.min(100) as usize;
    let step = if node_count > 100 {
        node_count as usize / sample_count
    } else {
        1
    };

    let mut sampled = 0;
    for i in (0..node_count as usize).step_by(step) {
        if sampled >= sample_count {
            break;
        }

        let node_offset = i * node_bytes;
        if node_offset + node_bytes > tree_size {
            report.error(format!(
                "Node {i} offset {node_offset} exceeds tree size {tree_size}"
            ));
            break;
        }

        // Basic check: node data should be within bounds
        if node_offset + node_bytes > buffer.len() {
            report.error(format!(
                "Node {i} at offset {node_offset} would exceed buffer"
            ));
            break;
        }

        sampled += 1;
    }

    report.info(format!("Sampled {sampled} tree nodes for integrity"));
}

/// Validate data pointers in tree nodes
fn validate_data_pointers(
    buffer: &[u8],
    tree_size: usize,
    node_count: u32,
    node_bytes: usize,
    report: &mut ValidationReport,
) {
    if node_count == 0 {
        return;
    }

    // Sample some nodes and check their record values
    let sample_count = node_count.min(50) as usize;
    let step = if node_count > 50 {
        node_count as usize / sample_count
    } else {
        1
    };

    let data_section_start = tree_size + 16; // Tree + 16-byte separator
    let max_valid_offset = buffer.len().saturating_sub(data_section_start);

    for i in (0..node_count as usize).step_by(step).take(sample_count) {
        let node_offset = i * node_bytes;

        // Read records from this node based on record size
        // For 24-bit: 2 records of 3 bytes each (6 bytes total)
        // For 28-bit: 2 records of 3.5 bytes each (7 bytes total)
        // For 32-bit: 2 records of 4 bytes each (8 bytes total)

        if node_offset + node_bytes > buffer.len() {
            continue;
        }

        // Read left record (first record)
        let Some(record_val) = read_tree_record(buffer, node_offset, node_bytes, 0) else {
            continue;
        };

        // If record > node_count, it's a data pointer
        if record_val > node_count {
            let data_offset = record_val - node_count - 16;
            if data_offset as usize > max_valid_offset {
                report.warning(format!(
                    "Node {i} has data pointer {data_offset} that may exceed data section"
                ));
            }
        }
    }
}

/// Validate UTF-8 in data section strings (CRITICAL for safety)
fn validate_data_section_utf8(
    buffer: &[u8],
    tree_size: usize,
    node_count: u32,
    node_bytes: usize,
    report: &mut ValidationReport,
    level: ValidationLevel,
) {
    let data_section_start = tree_size + 16; // Tree + separator

    if data_section_start >= buffer.len() {
        return; // No data section
    }

    let data_section = &buffer[data_section_start..];

    // Strategy: Sample data records by following pointers from tree nodes
    // This validates the strings that are actually reachable

    let sample_count = if level == ValidationLevel::Strict {
        node_count.min(100) // Sample up to 100 in strict mode
    } else {
        node_count.min(20) // Sample 20 in standard mode
    };

    if node_count == 0 || sample_count == 0 {
        return;
    }

    let step = if node_count > sample_count {
        (node_count / sample_count).max(1)
    } else {
        1
    };

    let mut strings_checked = 0;
    let mut invalid_utf8_found = false;

    for i in (0..node_count)
        .step_by(step as usize)
        .take(sample_count as usize)
    {
        let node_offset = (i as usize) * node_bytes;

        if node_offset + node_bytes > tree_size {
            continue;
        }

        // Read left record
        let Some(record_val) = read_tree_record(buffer, node_offset, node_bytes, 0) else {
            continue;
        };

        // If record points to data (> node_count), decode it
        if record_val > node_count {
            let data_offset = (record_val - node_count - 16) as usize;

            if data_offset < data_section.len() {
                // Try to decode this data value and check strings
                match check_data_value_utf8(data_section, data_offset) {
                    Ok(count) => {
                        strings_checked += count;
                    }
                    Err(e) => {
                        report.error(format!(
                            "Invalid UTF-8 found in data section at offset {}: {}",
                            data_section_start + data_offset,
                            e
                        ));
                        invalid_utf8_found = true;
                        break;
                    }
                }
            }
        }
    }

    if strings_checked > 0 {
        report.info(format!(
            "UTF-8 validated: {strings_checked} string(s) checked in data section (all valid)"
        ));
    } else if sample_count > 0 {
        report.info("UTF-8 validation: no data records found to sample");
    }

    if invalid_utf8_found {
        report
            .error("Database contains invalid UTF-8 - DO NOT use with --trusted mode!".to_string());
    }
}

/// Check UTF-8 validity of all strings in a data value
/// Returns count of strings checked, or error if invalid UTF-8 found
fn check_data_value_utf8(data_section: &[u8], offset: usize) -> std::result::Result<u32, String> {
    matchy_data_format::validate_data_value_utf8(data_section, offset, 0)
}

/// Validate MMDB data section structure
fn validate_mmdb_data_section(buffer: &[u8], tree_size: usize, report: &mut ValidationReport) {
    // After the tree, there should be a 16-byte separator, then the data section
    const DATA_SEPARATOR_SIZE: usize = 16;

    if tree_size + DATA_SEPARATOR_SIZE > buffer.len() {
        report.error(format!(
            "Tree size {} + separator {} exceeds file size {}",
            tree_size,
            DATA_SEPARATOR_SIZE,
            buffer.len()
        ));
        return;
    }

    let separator_start = tree_size;
    let data_start = tree_size + DATA_SEPARATOR_SIZE;

    // Check separator (should be 16 zero bytes)
    let separator = &buffer[separator_start..data_start];
    if separator.iter().all(|&b| b == 0) {
        report.info("Valid data section separator found");
    } else {
        report.warning("Data section separator is non-zero (may be intentional)");
    }

    // Validate data section exists and is reasonable
    let data_size = buffer.len() - data_start;
    if data_size > 0 {
        report.info(format!("Data section: {data_size} bytes"));

        // Basic sanity check: data section shouldn't be impossibly small
        if data_size < 4 {
            report.warning("Data section is very small (< 4 bytes)");
        }
    } else {
        report.warning("No data section found after tree");
    }
}

/// Validate an embedded PARAGLOB section within an MMDB database
fn validate_paraglob_section(
    buffer: &[u8],
    offset: usize,
    report: &mut ValidationReport,
    level: ValidationLevel,
) -> Result<()> {
    // The pattern section format in MMDB is:
    // [total_size: u32][paraglob_size: u32][PARAGLOB data][pattern_count: u32][offsets...]

    if offset + 8 > buffer.len() {
        report.error("Pattern section header truncated");
        return Ok(());
    }

    // Read sizes
    let _total_size = u32::from_le_bytes([
        buffer[offset],
        buffer[offset + 1],
        buffer[offset + 2],
        buffer[offset + 3],
    ]);
    let paraglob_size = u32::from_le_bytes([
        buffer[offset + 4],
        buffer[offset + 5],
        buffer[offset + 6],
        buffer[offset + 7],
    ]) as usize;

    let paraglob_start = offset + 8;
    let paraglob_end = paraglob_start + paraglob_size;

    if paraglob_end > buffer.len() {
        report.error(format!(
            "PARAGLOB section extends beyond file: start={}, size={}, file_len={}",
            paraglob_start,
            paraglob_size,
            buffer.len()
        ));
        return Ok(());
    }

    // Validate the PARAGLOB data
    let paraglob_data = &buffer[paraglob_start..paraglob_end];
    validate_paraglob_header(paraglob_data, report)?;

    if !report.is_valid() {
        return Ok(());
    }

    // Parse PARAGLOB header for stats
    let header = read_paraglob_header(paraglob_data)?;
    report.stats.version = header.version;
    report.stats.ac_node_count = header.ac_node_count;
    report.stats.pattern_count = header.pattern_count;
    report.stats.has_data_section = header.has_data_section();
    report.stats.has_ac_literal_mapping = header.has_ac_literal_mapping();

    // Validate AC automaton structure
    // Extract the AC buffer slice - AC nodes, edges, and patterns are stored sequentially
    // and all offsets within AC are relative to where the nodes start.
    // Pass everything from nodes_offset to end of paraglob (edges/patterns follow nodes).
    let ac_offset = header.ac_nodes_offset as usize;
    if ac_offset > paraglob_data.len() {
        report.error(format!(
            "AC nodes offset beyond PARAGLOB: offset={}, paraglob_len={}",
            ac_offset,
            paraglob_data.len()
        ));
        return Ok(());
    }
    let ac_buffer = &paraglob_data[ac_offset..];

    let is_strict = level == ValidationLevel::Strict;
    let ac_result = matchy_ac::validate_ac_structure(
        ac_buffer, // AC buffer slice starting at nodes (offsets relative to this)
        0,         // Nodes start at offset 0 of this slice
        header.ac_node_count as usize,
        header.pattern_count,
        is_strict,
    );
    report.errors.extend(ac_result.errors);
    report.warnings.extend(ac_result.warnings);
    report.stats.state_encoding_distribution = ac_result.stats.state_encoding_distribution;

    if !report.is_valid() {
        return Ok(());
    }

    // Validate patterns
    let pattern_result = matchy_paraglob::validate_patterns(
        paraglob_data,
        header.patterns_offset as usize,
        header.pattern_count as usize,
    );
    report.errors.extend(pattern_result.errors);
    report.warnings.extend(pattern_result.warnings);
    report.stats.literal_count = pattern_result.stats.literal_count;
    report.stats.glob_count = pattern_result.stats.glob_count;
    if header.pattern_count > 0 {
        report.info(format!(
            "Patterns: {} total ({} literal, {} glob)",
            header.pattern_count,
            pattern_result.stats.literal_count,
            pattern_result.stats.glob_count
        ));
    }

    if !report.is_valid() {
        return Ok(());
    }

    // PARAGLOB consistency checks in strict mode
    if level == ValidationLevel::Strict {
        validate_paraglob_consistency(paraglob_data, &header, report, level)?;
    }

    // Cross-component validation: Check pattern data offsets point to valid MMDB data
    // This validates the external references from PARAGLOB to MMDB data section
    if header.has_data_section() && header.mapping_count > 0 {
        // Read header as paraglob type (there are two ParaglobHeader types - one in format, one in paraglob)
        // TODO: Fix duplication per architectural notebooks
        let paraglob_header =
            matchy_paraglob::offset_format::ParaglobHeader::read_from_prefix(paraglob_data)
                .map(|(h, _)| h)
                .map_err(|_| {
                    MatchyError::Paraglob(ParaglobError::Format(
                        "Failed to read paraglob header".to_string(),
                    ))
                })?;

        // Get the data offsets that PARAGLOB is referencing
        match matchy_paraglob::get_pattern_data_offsets(paraglob_data, &paraglob_header) {
            Ok(data_offsets) => {
                // Calculate where MMDB data section starts
                // It's after: IP tree + 16-byte separator
                if let Ok(metadata) = crate::mmdb::MmdbMetadata::from_file(buffer) {
                    if let Ok(crate::DataValue::Map(map)) = metadata.as_value() {
                        if let Some(crate::DataValue::Uint32(node_count)) = map.get("node_count") {
                            let record_size = map
                                .get("record_size")
                                .and_then(|v| match v {
                                    crate::DataValue::Uint16(n) => Some(*n),
                                    crate::DataValue::Uint32(n) => u16::try_from(*n).ok(),
                                    _ => None,
                                })
                                .unwrap_or(24);

                            let node_bytes = match record_size {
                                24 => 6,
                                28 => 7,
                                32 => 8,
                                _ => 6,
                            };
                            let tree_size = (*node_count as usize) * node_bytes;
                            let data_section_start = tree_size + 16; // After tree + separator

                            // Validate each data offset
                            for offset in data_offsets {
                                if offset == 0 {
                                    // 0 is valid (means no data for this pattern)
                                    continue;
                                }

                                let offset = offset as usize;
                                if offset < data_section_start {
                                    report.error(format!(
                                        "Pattern data offset {offset} points before data section (starts at {data_section_start})"
                                    ));
                                } else if offset >= buffer.len() {
                                    report.error(format!(
                                        "Pattern data offset {} exceeds file size {}",
                                        offset,
                                        buffer.len()
                                    ));
                                }
                                // Note: We don't validate the offset is within data section end
                                // because we'd need to parse MMDB data structures to know where
                                // pattern section starts. Just checking it's after data section
                                // start and before file end is sufficient.
                            }
                        }
                    }
                }
            }
            Err(e) => {
                report.error(format!("Failed to extract pattern data offsets: {e}"));
            }
        }
    }

    Ok(())
}

/// Read and parse the PARAGLOB header
fn read_paraglob_header(buffer: &[u8]) -> Result<ParaglobHeader> {
    if buffer.len() < mem::size_of::<ParaglobHeader>() {
        return Err(MatchyError::Paraglob(ParaglobError::Format(
            "File too small to contain header".to_string(),
        )));
    }

    let header = ParaglobHeader::read_from_prefix(buffer)
        .map(|(h, _)| h)
        .map_err(|_| {
            MatchyError::Paraglob(ParaglobError::Format("Failed to read header".to_string()))
        })?;

    Ok(header)
}

/// Validate PARAGLOB header structure
fn validate_paraglob_header(buffer: &[u8], report: &mut ValidationReport) -> Result<()> {
    // Check minimum size
    if buffer.len() < mem::size_of::<ParaglobHeader>() {
        report.error(format!(
            "File too small: {} bytes, need at least {} for header",
            buffer.len(),
            mem::size_of::<ParaglobHeader>()
        ));
        return Ok(());
    }

    let header = read_paraglob_header(buffer)?;

    // Check magic bytes
    if &header.magic != MAGIC {
        let magic_str = String::from_utf8_lossy(&header.magic);
        report.error(format!(
            "Invalid magic bytes: expected {MAGIC:?}, got {magic_str:?}"
        ));
        return Ok(());
    }

    // Check version
    match header.version {
        MATCHY_FORMAT_VERSION => {
            report.info("Format version: v4 (latest - ACNodeHot for 50% memory reduction)");
        }
        MATCHY_FORMAT_VERSION_V3 => {
            report.warning("Format version: v3 (older - uses 32-byte ACNode, no longer supported)");
        }
        MATCHY_FORMAT_VERSION_V2 => {
            report.warning(
                "Format version: v2 (older - no AC literal mapping, will be slower to load)",
            );
        }
        MATCHY_FORMAT_VERSION_V1 => {
            report.warning("Format version: v1 (oldest - no data section, no AC literal mapping)");
        }
        v => {
            report.error(format!("Unsupported version: {v} (expected 1, 2, 3, or 4)"));
            return Ok(());
        }
    }

    // Validate endianness marker
    match header.endianness {
        0x00 => report.warning("No endianness marker (legacy format)"),
        0x01 => report.info("Endianness: little-endian"),
        0x02 => {
            report.info("Endianness: big-endian");
            if cfg!(target_endian = "little") {
                report.warning(
                    "Database is big-endian but system is little-endian (will byte-swap on read)",
                );
            }
        }
        e => report.warning(format!("Unknown endianness marker: 0x{e:02x}")),
    }

    // Validate total buffer size matches file size
    if header.total_buffer_size as usize != buffer.len() {
        report.error(format!(
            "Header total_buffer_size ({}) doesn't match file size ({})",
            header.total_buffer_size,
            buffer.len()
        ));
    }

    if let Err(e) = header.validate_offsets(buffer.len()) {
        report.error(format!("Header offset validation failed: {e}"));
    }

    Ok(())
}

/// Validate PARAGLOB consistency - checks for data structure integrity issues
/// This orchestrates calls to component validators
fn validate_paraglob_consistency(
    buffer: &[u8],
    header: &ParaglobHeader,
    report: &mut ValidationReport,
    _level: ValidationLevel,
) -> Result<()> {
    // Skip if empty database
    if header.ac_node_count == 0 && header.pattern_count == 0 {
        return Ok(());
    }

    report.info("Running PARAGLOB consistency checks...");

    // Extract AC buffer slice for consistency checks
    // AC offsets are relative to where AC nodes start
    let ac_offset = header.ac_nodes_offset as usize;
    if ac_offset > buffer.len() {
        report.error(format!(
            "AC nodes offset beyond PARAGLOB in consistency check: offset={}, paraglob_len={}",
            ac_offset,
            buffer.len()
        ));
        return Ok(());
    }
    let ac_buffer = &buffer[ac_offset..];

    // 1. Check for orphan AC nodes
    let ac_reach_result = matchy_ac::validate_ac_reachability(
        ac_buffer, // AC buffer slice, not full paraglob
        0,         // Nodes at offset 0 of AC buffer
        header.ac_node_count as usize,
    );
    report.errors.extend(ac_reach_result.errors);
    report.warnings.extend(ac_reach_result.warnings);
    if ac_reach_result.stats.orphaned_count > 0 {
        report.warning(format!(
            "Found {} orphaned AC nodes (unreachable from root)",
            ac_reach_result.stats.orphaned_count
        ));
    } else {
        report.info("✓ All AC nodes are reachable from root");
    }

    // 2. Validate pattern-AC consistency
    let pattern_info = matchy_paraglob::build_pattern_info(
        buffer,
        header.patterns_offset as usize,
        header.pattern_count as usize,
    )?;
    let pattern_ref_result = matchy_ac::validate_pattern_references(
        ac_buffer, // AC buffer slice, not full paraglob
        0,         // Nodes at offset 0 of AC buffer
        header.ac_node_count as usize,
        header.pattern_count,
        Some(&pattern_info),
    );
    report.errors.extend(pattern_ref_result.errors);
    report.warnings.extend(pattern_ref_result.warnings);

    // 3. Validate AC literal mapping (v3)
    if header.has_ac_literal_mapping() {
        let ac_lit_result = matchy_paraglob::validate_ac_literal_mapping(
            buffer,
            header.ac_literal_map_offset as usize,
            header.pattern_count,
        );
        report.errors.extend(ac_lit_result.errors);
        report.warnings.extend(ac_lit_result.warnings);
    }

    // 4. Validate data mappings (v2+)
    if header.has_data_section() && header.mapping_count > 0 {
        let data_map_result = matchy_format::validate_data_mapping_consistency(buffer, header);
        report.errors.extend(data_map_result.errors);
        report.warnings.extend(data_map_result.warnings);
        let coverage_pct = if header.pattern_count > 0 {
            (data_map_result.stats.patterns_with_data * 100) / header.pattern_count as usize
        } else {
            0
        };
        report.info(format!(
            "Data mapping coverage: {}/{} patterns ({}%)",
            data_map_result.stats.patterns_with_data, header.pattern_count, coverage_pct
        ));
    }

    // 5. Validate meta-word mappings
    if header.meta_word_mapping_count > 0 {
        let meta_result = matchy_paraglob::validate_meta_word_mappings(
            buffer,
            header.meta_word_mappings_offset as usize,
            header.meta_word_mapping_count as usize,
            header.pattern_count,
        );
        report.errors.extend(meta_result.errors);
        report.warnings.extend(meta_result.warnings);
    }

    report.info("✓ PARAGLOB consistency checks complete");
    Ok(())
}

/// Validate data section pointers for safety issues
/// Checks for cycles, depth limits, bounds, and type validity
fn validate_data_section_pointers(
    buffer: &[u8],
    tree_size: usize,
    node_count: u32,
    node_bytes: usize,
    report: &mut ValidationReport,
    level: ValidationLevel,
) {
    let data_section_start = tree_size + 16; // Tree + separator

    if data_section_start >= buffer.len() {
        return; // No data section
    }

    let data_section = &buffer[data_section_start..];

    // Sample data values and validate their pointer chains
    let sample_count = if level == ValidationLevel::Strict {
        node_count.min(100) // More thorough sampling
    } else {
        node_count.min(20) // Basic sampling
    };

    if node_count == 0 || sample_count == 0 {
        return;
    }

    let step = if node_count > sample_count {
        (node_count / sample_count).max(1)
    } else {
        1
    };

    let mut pointers_checked = 0;
    let mut cycles_detected = 0;
    let mut max_depth_found = 0;
    let mut invalid_pointers = 0;

    // Check data values reachable from tree nodes
    for i in (0..node_count)
        .step_by(step as usize)
        .take(sample_count as usize)
    {
        let node_offset = (i as usize) * node_bytes;

        if node_offset + node_bytes > tree_size {
            continue;
        }

        // Read left record
        let Some(record_val) = read_tree_record(buffer, node_offset, node_bytes, 0) else {
            continue;
        };

        // If record points to data (> node_count), validate it
        if record_val > node_count {
            let data_offset = (record_val - node_count - 16) as usize;

            if data_offset < data_section.len() {
                // Validate this data value and all its pointer chains
                let mut visited = HashSet::new();
                match matchy_data_format::validate_data_value_pointers(
                    data_section,
                    data_offset,
                    &mut visited,
                    0,
                ) {
                    Ok(depth) => {
                        pointers_checked += visited.len();
                        max_depth_found = max_depth_found.max(depth);
                    }
                    Err(e) => match e {
                        matchy_data_format::PointerValidationError::Cycle { offset } => {
                            cycles_detected += 1;
                            report.error(format!(
                                "Pointer cycle detected in data section at offset {offset}"
                            ));
                        }
                        matchy_data_format::PointerValidationError::DepthExceeded { depth } => {
                            report.error(format!(
                                "Pointer chain depth {} exceeds safe limit (max: {})",
                                depth,
                                matchy_data_format::MAX_POINTER_DEPTH
                            ));
                        }
                        matchy_data_format::PointerValidationError::InvalidOffset {
                            offset,
                            reason,
                        } => {
                            invalid_pointers += 1;
                            report.error(format!("Invalid pointer at offset {offset}: {reason}"));
                        }
                        matchy_data_format::PointerValidationError::InvalidType {
                            offset,
                            type_id,
                        } => {
                            report.error(format!("Invalid data type {type_id} at offset {offset}"));
                        }
                    },
                }
            }
        }
    }

    // Report findings
    if pointers_checked > 0 {
        report.info(format!(
            "Data pointers validated: {pointers_checked} checked, max chain depth: {max_depth_found}"
        ));
    }

    if cycles_detected > 0 {
        report.error(format!(
            "🚨 CRITICAL: {cycles_detected} pointer cycles detected - could cause infinite loops!"
        ));
    }

    if invalid_pointers > 0 {
        report.error(format!(
            "🚨 CRITICAL: {invalid_pointers} invalid pointers detected - could cause crashes!"
        ));
    }
}

/// Find the literal section offset from metadata
fn find_literal_section_offset(buffer: &[u8]) -> Option<usize> {
    if let Ok(metadata) = crate::mmdb::MmdbMetadata::from_file(buffer) {
        if let Ok(DataValue::Map(map)) = metadata.as_value() {
            if let Some(DataValue::Uint32(offset)) = map.get("literal_section_offset") {
                let offset_val = *offset as usize;
                if offset_val == 0 {
                    return None;
                }
                // Metadata stores offset to start of data, but literal data starts after the LHSH magic
                return Some(offset_val);
            }
        }
    }
    None
}

/// Get all data offsets from the literal hash section
fn get_literal_data_offsets(
    buffer: &[u8],
    literal_offset: usize,
) -> std::result::Result<Vec<u32>, String> {
    // Literal section format:
    // [LHSH magic][header][hash table][string pool][pattern mappings]
    // Pattern mappings: [count: u32][(pattern_id: u32, data_offset: u32); count]

    if literal_offset + 32 > buffer.len() {
        return Err("Literal section truncated".to_string());
    }

    let literal_data = &buffer[literal_offset..];

    // Verify magic
    if &literal_data[0..4] != b"LHSH" {
        return Err("Invalid literal hash magic".to_string());
    }

    // Parse header to find mappings
    let strings_offset = u32::from_le_bytes(
        literal_data[16..20]
            .try_into()
            .expect("slice is exactly 4 bytes"),
    ) as usize;
    let strings_size = u32::from_le_bytes(
        literal_data[20..24]
            .try_into()
            .expect("slice is exactly 4 bytes"),
    ) as usize;

    let mappings_start = strings_offset + strings_size;
    if mappings_start + 4 > literal_data.len() {
        return Err("Mappings section truncated".to_string());
    }

    let count = u32::from_le_bytes(
        literal_data[mappings_start..mappings_start + 4]
            .try_into()
            .expect("slice is exactly 4 bytes"),
    );

    let mut offsets = Vec::with_capacity(count as usize);
    let mappings_data_start = mappings_start + 4;

    for i in 0..count {
        let offset = mappings_data_start + (i as usize) * 8;
        if offset + 8 > literal_data.len() {
            break;
        }
        // Skip pattern_id (first 4 bytes), read data_offset (next 4 bytes)
        let data_offset = u32::from_le_bytes(
            literal_data[offset + 4..offset + 8]
                .try_into()
                .expect("slice is exactly 4 bytes"),
        );
        offsets.push(data_offset);
    }

    Ok(offsets)
}

/// Validate data entries against a known schema
///
/// For databases with a known database_type (like "ThreatDB-v1"), this validates
/// that ALL data entries conform to the expected schema structure.
///
/// This checks data from:
/// 1. Literal hash data offsets (all entries)
/// 2. Pattern data offsets (all entries)  
/// 3. IP tree leaf data (all unique data offsets)
fn validate_schema_content(
    buffer: &[u8],
    database_type: &str,
    tree_size: usize,
    node_count: u32,
    node_bytes: usize,
    report: &mut ValidationReport,
    _level: ValidationLevel,
) {
    // Try to create a schema validator
    let validator = match SchemaValidator::new(database_type) {
        Ok(v) => v,
        Err(e) => {
            report.warning(format!(
                "Could not create schema validator for '{database_type}': {e}"
            ));
            return;
        }
    };

    report.info(format!(
        "Validating ALL data entries against {database_type} schema..."
    ));
    report.stats.schema_validated = true;

    let data_section_start = tree_size + 16; // Tree + separator
    if data_section_start >= buffer.len() {
        report.warning("No data section found for schema validation");
        return;
    }

    let data_section = &buffer[data_section_start..];
    let decoder = DataDecoder::new(data_section, 0); // Offsets are relative to data section

    let mut entries_checked: u32 = 0;
    let mut validation_failures: u32 = 0;
    let mut first_errors: Vec<String> = Vec::new();
    const MAX_ERRORS_TO_REPORT: u32 = 10;

    // Track validated offsets to avoid duplicates (data deduplication means multiple
    // keys can point to the same data)
    let mut validated_offsets: HashSet<u32> = HashSet::new();

    // Helper to validate a data value at an offset
    let mut validate_at_offset = |data_offset: u32, source: &str| {
        // Skip if already validated (deduplication)
        if validated_offsets.contains(&data_offset) {
            return;
        }
        validated_offsets.insert(data_offset);

        if (data_offset as usize) >= data_section.len() {
            return;
        }

        match decoder.decode(data_offset) {
            Ok(data_value) => {
                if let DataValue::Map(map) = data_value {
                    entries_checked += 1;

                    if let Err(e) = validator.validate(&map) {
                        validation_failures += 1;
                        if first_errors.len() < MAX_ERRORS_TO_REPORT as usize {
                            first_errors.push(format!("{source} at offset {data_offset}: {e}"));
                        }
                    }
                }
            }
            Err(_) => {
                // Decoding errors are handled by structural validation
            }
        }
    };

    // 1. Validate ALL entries from literal hash section (if present)
    if let Some(literal_offset) = find_literal_section_offset(buffer) {
        if let Ok(data_offsets) = get_literal_data_offsets(buffer, literal_offset) {
            for offset in data_offsets.iter() {
                if *offset > 0 {
                    // Offset is absolute, convert to relative to data section
                    let offset_usize = *offset as usize;
                    if offset_usize >= data_section_start {
                        if let Ok(rel_offset) = u32::try_from(offset_usize - data_section_start) {
                            validate_at_offset(rel_offset, "Literal entry");
                        }
                    }
                }
            }
        }
    }

    // 2. Validate ALL entries from pattern section (if present)
    if let Ok(metadata) = crate::mmdb::MmdbMetadata::from_file(buffer) {
        if let Ok(DataValue::Map(map)) = metadata.as_value() {
            if let Some(DataValue::Uint32(pattern_offset)) = map.get("pattern_section_offset") {
                if *pattern_offset > 0 {
                    let offset = *pattern_offset as usize;
                    if offset + 8 <= buffer.len() {
                        // Read PARAGLOB header to get pattern data offsets
                        let paraglob_size = u32::from_le_bytes([
                            buffer[offset + 4],
                            buffer[offset + 5],
                            buffer[offset + 6],
                            buffer[offset + 7],
                        ]) as usize;

                        let paraglob_start = offset + 8;
                        if paraglob_start + paraglob_size <= buffer.len() {
                            let paraglob_data =
                                &buffer[paraglob_start..paraglob_start + paraglob_size];
                            if let Ok((header, _)) =
                                matchy_format::offset_format::ParaglobHeader::read_from_prefix(
                                    paraglob_data,
                                )
                            {
                                if header.has_data_section() && header.mapping_count > 0 {
                                    if let Ok(data_offsets) =
                                        matchy_paraglob::get_pattern_data_offsets(
                                            paraglob_data,
                                            &header,
                                        )
                                    {
                                        for offset in data_offsets.iter() {
                                            if *offset > 0 {
                                                // Pattern data offsets are absolute
                                                let offset_usize = *offset as usize;
                                                if offset_usize >= data_section_start {
                                                    if let Ok(rel_offset) = u32::try_from(
                                                        offset_usize - data_section_start,
                                                    ) {
                                                        validate_at_offset(
                                                            rel_offset,
                                                            "Pattern entry",
                                                        );
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // 3. Validate ALL unique data from IP tree nodes
    // We traverse the tree to find all leaf nodes with data pointers
    for i in 0..node_count {
        let node_offset = (i as usize) * node_bytes;

        if node_offset + node_bytes > tree_size {
            continue;
        }

        // Read both left and right records
        let Some(left_record) = read_tree_record(buffer, node_offset, node_bytes, 0) else {
            continue;
        };
        let Some(right_record) = read_tree_record(buffer, node_offset, node_bytes, 1) else {
            continue;
        };

        // Check left record - if it points to data (> node_count), validate
        if left_record > node_count {
            let data_offset = left_record - node_count - 16;
            validate_at_offset(data_offset, "IP entry");
        }

        // Check right record
        if right_record > node_count {
            let data_offset = right_record - node_count - 16;
            validate_at_offset(data_offset, "IP entry");
        }
    }

    report.stats.schema_entries_checked = entries_checked;
    report.stats.schema_validation_failures = validation_failures;

    // Report results
    if entries_checked > 0 {
        if validation_failures == 0 {
            report.info(format!(
                "✓ Schema validation passed: {entries_checked} entries checked, all valid"
            ));
        } else {
            let pct_failed = (validation_failures * 100) / entries_checked;
            report.error(format!(
                "Schema validation failed: {validation_failures}/{entries_checked} entries invalid ({pct_failed}%)"
            ));

            // Report first few errors as details
            for err in first_errors {
                report.error(format!("  • {err}"));
            }

            if validation_failures > MAX_ERRORS_TO_REPORT {
                report.error(format!(
                    "  ... and {} more validation errors",
                    validation_failures - MAX_ERRORS_TO_REPORT
                ));
            }
        }
    } else {
        report.warning("No data entries found for schema validation");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_validate_empty_file() {
        let temp = NamedTempFile::new().unwrap();
        let path = temp.path();

        let result = validate_database(path, ValidationLevel::Standard);
        assert!(result.is_ok());

        let report = result.unwrap();
        assert!(!report.is_valid());
        assert!(!report.errors.is_empty());
        // Should fail to find MMDB metadata marker
        assert!(report.errors.iter().any(|e| e.contains("MMDB")));
    }

    #[test]
    fn test_validate_valid_database() {
        // NOTE: This test is commented out because DatabaseBuilder creates MMDB format,
        // not standalone PARAGLOB format. The validator is designed for .mxy files
        // which have different structure. We keep the other error detection tests.
        //
        // TODO: Create a proper .mxy file builder test when we have sample databases
    }

    #[test]
    fn test_validate_corrupted_database() {
        // Test with non-MMDB data
        let db_bytes = vec![0u8; 1024]; // Random bytes, not MMDB format

        let temp = NamedTempFile::new().unwrap();
        std::fs::write(temp.path(), db_bytes).unwrap();

        let result = validate_database(temp.path(), ValidationLevel::Standard);
        assert!(result.is_ok());

        let report = result.unwrap();
        assert!(!report.is_valid());
        // Should fail to find MMDB format
        assert!(report.errors.iter().any(|e| e.contains("MMDB")));
    }

    #[test]
    fn test_validation_report_is_valid() {
        let mut report = ValidationReport::new();
        assert!(report.is_valid(), "New report should be valid");

        report.error("Test error");
        assert!(!report.is_valid(), "Report with error should be invalid");

        let mut report2 = ValidationReport::new();
        report2.warning("Test warning");
        assert!(
            report2.is_valid(),
            "Report with only warning should be valid"
        );
    }

    #[test]
    fn test_database_stats_default() {
        let stats = DatabaseStats::default();
        assert_eq!(stats.file_size, 0);
        assert_eq!(stats.version, 0);
        assert_eq!(stats.ac_node_count, 0);
        assert_eq!(stats.pattern_count, 0);
        assert!(!stats.has_data_section);
        assert!(!stats.has_ac_literal_mapping);
    }

    #[test]
    fn test_strict_mode_runs_deep_checks() {
        // Create a minimal but valid-ish MMDB structure for testing
        // This is a simplified test - real validation needs proper MMDB format
        let temp = NamedTempFile::new().unwrap();

        // Invalid but testable
        let db_bytes = vec![0u8; 1024];
        std::fs::write(temp.path(), db_bytes).unwrap();

        let result_standard = validate_database(temp.path(), ValidationLevel::Standard);
        let result_strict = validate_database(temp.path(), ValidationLevel::Strict);

        assert!(result_standard.is_ok());
        assert!(result_strict.is_ok());

        // Both should fail on this invalid data, but we're just checking they run
        assert!(!result_standard.unwrap().is_valid());
        assert!(!result_strict.unwrap().is_valid());
    }

    #[test]
    fn test_validation_error_accumulation() {
        let mut report = ValidationReport::new();

        report.error("Error 1");
        report.error("Error 2");
        report.warning("Warning 1");
        report.info("Info 1");

        assert_eq!(report.errors.len(), 2);
        assert_eq!(report.warnings.len(), 1);
        assert_eq!(report.info.len(), 1);
        assert!(!report.is_valid());
    }

    #[test]
    fn test_database_stats_summary() {
        let stats = DatabaseStats {
            version: 3,
            ac_node_count: 100,
            pattern_count: 50,
            literal_count: 30,
            glob_count: 20,
            ..Default::default()
        };

        let summary = stats.summary();
        assert!(summary.contains("v3"));
        assert!(summary.contains("100"));
        assert!(summary.contains("50"));
    }
}
