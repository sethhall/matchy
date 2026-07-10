//! Database validation for untrusted .mxy files
//!
//! This module validates MMDB format database files (`.mxy`). Strict mode
//! exhaustively walks tree-reachable data; standard mode performs the same
//! load-time envelope checks with sampled deep data inspection. When a known
//! database schema is declared, both levels additionally validate every
//! referenced entry against that schema. Checks include:
//!
//! - MMDB metadata and structure
//! - Embedded PARAGLOB sections (if present)
//! - Offset and bounds checking
//! - UTF-8 validity in inspected data values
//! - Graph structure integrity (no cycles, valid transitions)
//! - Data consistency (arrays, mappings, references)
//!
//! # Safety
//!
//! Validation is implemented in safe Rust with explicit bounds checks. A passing
//! report describes the bytes read for this validation run; it is not a guarantee
//! that a path still names the same bytes when the database is opened later.
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
//!     println!("✓ The bytes read passed strict validation");
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
use matchy_format::offset_format::{ParaglobHeader, MAGIC, MATCHY_FORMAT_VERSION};
use matchy_paraglob::error::ParaglobError;
use std::collections::HashSet;
use std::mem;
use std::path::Path;

use zerocopy::FromBytes;

const MAX_VALIDATION_ERRORS: usize = 256;
const MAX_VALIDATION_WARNINGS: usize = 256;
const MAX_VALIDATION_INFO: usize = 128;
const ERRORS_SUPPRESSED: &str =
    "Additional validation errors suppressed after reaching the limit of 256";
const WARNINGS_SUPPRESSED: &str =
    "Additional validation warnings suppressed after reaching the limit of 256";
const INFO_SUPPRESSED: &str =
    "Additional validation information suppressed after reaching the limit of 128";

fn push_capped(messages: &mut Vec<String>, message: String, limit: usize, sentinel: &str) {
    let already_has_sentinel = messages.iter().any(|existing| existing == sentinel);
    if message == sentinel && already_has_sentinel {
        return;
    }
    if messages.len() < limit {
        messages.push(message);
    } else if !already_has_sentinel {
        messages[limit - 1] = sentinel.to_string();
    }
}

/// Validation strictness level
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationLevel {
    /// Runtime-equivalent header/envelope checks plus sampled reachable data.
    /// Known-schema validation still checks every referenced entry.
    Standard,
    /// Exhaustive tree-reachable data and deep graph/component consistency checks.
    Strict,
}

/// Validation report with detailed findings
#[derive(Debug, Clone)]
pub struct ValidationReport {
    /// Critical errors, capped at 256 retained messages including a suppression sentinel.
    pub errors: Vec<String>,
    /// Non-fatal warnings, capped at 256 retained messages including a suppression sentinel.
    pub warnings: Vec<String>,
    /// Informational messages, capped at 128 entries including a suppression sentinel.
    pub info: Vec<String>,
    /// Database statistics
    pub stats: DatabaseStats,
}

/// Database statistics gathered during validation
#[derive(Debug, Clone, Default)]
pub struct DatabaseStats {
    /// File size in bytes
    pub file_size: usize,
    /// Paraglob format version (current: v5; zero for IP-only databases)
    pub version: u32,
    /// Number of AC automaton nodes
    pub ac_node_count: u32,
    /// Number of patterns
    pub pattern_count: u32,
    /// Number of IP entries recorded in metadata (zero when unavailable)
    pub ip_entry_count: u32,
    /// Number of literal patterns
    pub literal_count: u32,
    /// Number of glob patterns
    pub glob_count: u32,
    /// Paraglob pattern-string section size (zero when unavailable)
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
        push_capped(
            &mut self.errors,
            msg.into(),
            MAX_VALIDATION_ERRORS,
            ERRORS_SUPPRESSED,
        );
    }

    /// Add a warning to the report
    fn warning(&mut self, msg: impl Into<String>) {
        push_capped(
            &mut self.warnings,
            msg.into(),
            MAX_VALIDATION_WARNINGS,
            WARNINGS_SUPPRESSED,
        );
    }

    /// Add an info message to the report
    fn info(&mut self, msg: impl Into<String>) {
        push_capped(
            &mut self.info,
            msg.into(),
            MAX_VALIDATION_INFO,
            INFO_SUPPRESSED,
        );
    }

    fn extend_errors(&mut self, errors: impl IntoIterator<Item = String>) {
        for error in errors {
            self.error(error);
        }
    }

    fn extend_warnings(&mut self, warnings: impl IntoIterator<Item = String>) {
        for warning in warnings {
            self.warning(warning);
        }
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
    if side > 1 {
        return None;
    }
    let node_end = node_offset.checked_add(node_bytes)?;
    let node = buffer.get(node_offset..node_end)?;

    match node_bytes {
        6 => {
            // 24-bit records (3 bytes each)
            let offset = usize::from(side) * 3;
            let record = node.get(offset..offset + 3)?;
            let b0 = u32::from(record[0]);
            let b1 = u32::from(record[1]);
            let b2 = u32::from(record[2]);
            Some((b0 << 16) | (b1 << 8) | b2)
        }
        7 => {
            // 28-bit records (7 bytes total per node)
            // Layout: | left[23..0] | left[27..24]:right[27..24] | right[23..0] |
            // Bytes:  |  0  1  2    |            3               |   4  5  6    |
            let middle = node[3];
            if side == 0 {
                // Left record
                let low =
                    (u32::from(node[0]) << 16) | (u32::from(node[1]) << 8) | u32::from(node[2]);
                let high = u32::from((middle >> 4) & 0x0F);
                Some((high << 24) | low)
            } else {
                // Right record
                let low =
                    (u32::from(node[4]) << 16) | (u32::from(node[5]) << 8) | u32::from(node[6]);
                let high = u32::from(middle & 0x0F);
                Some((high << 24) | low)
            }
        }
        8 => {
            // 32-bit records (4 bytes each)
            let offset = usize::from(side) * 4;
            let record = node.get(offset..offset + 4)?;
            Some(u32::from_be_bytes([
                record[0], record[1], record[2], record[3],
            ]))
        }
        _ => None,
    }
}

fn record_data_offset(
    record: u32,
    node_count: u32,
) -> std::result::Result<Option<usize>, &'static str> {
    if record <= node_count {
        return Ok(None);
    }

    let encoded_offset = record
        .checked_sub(node_count)
        .ok_or("record is below node count")?;
    let data_offset = encoded_offset
        .checked_sub(16)
        .ok_or("record points into the reserved data separator")?;
    usize::try_from(data_offset)
        .map(Some)
        .map_err(|_| "data offset is not addressable")
}

fn mmdb_data_section(buffer: &[u8], tree_size: usize) -> Option<(usize, &[u8])> {
    let start = tree_size.checked_add(16)?;
    let metadata_start = crate::mmdb::find_metadata_marker(buffer).ok()?;
    let sections = crate::Database::locate_embedded_sections(buffer, metadata_start).ok()?;
    let data_end = sections.data_section_end()?;
    if start > data_end {
        return None;
    }
    Some((start, buffer.get(start..data_end)?))
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

    // Read the path once, then derive every reported property from this snapshot.
    // This avoids mixing metadata from one file state with bytes from another.
    let buffer =
        std::fs::read(path).map_err(|e| ParaglobError::Io(format!("Failed to read file: {e}")))?;
    let file_size = buffer.len();
    report.stats.file_size = file_size;
    report.info(format!(
        "File size: {} bytes ({} KB)",
        file_size,
        file_size / 1024
    ));

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
    let metadata_offset = match crate::mmdb::find_metadata_marker(buffer) {
        Ok(offset) => offset,
        Err(error) => {
            report.error(format!("Invalid MMDB format: {error}"));
            return Ok(report.clone());
        }
    };

    report.info("Valid MMDB metadata marker found");

    // Use the same fail-closed header parser as runtime loading before running
    // the more descriptive validation passes below. This catches malformed
    // metadata, impossible tree envelopes, and invalid separators up front.
    let parsed_header = match crate::mmdb::MmdbHeader::from_file(buffer) {
        Ok(header) => header,
        Err(error) => {
            report.error(format!("Invalid MMDB header: {error}"));
            return Ok(report.clone());
        }
    };
    let embedded_sections = match crate::Database::locate_embedded_sections(buffer, metadata_offset)
    {
        Ok(sections) => sections,
        Err(error) => {
            report.error(format!("Invalid embedded section layout: {error}"));
            return Ok(report.clone());
        }
    };

    // Try to read metadata
    match crate::mmdb::MmdbMetadata::from_file(buffer) {
        Ok(metadata) => {
            let metadata_value = match metadata.as_value() {
                Ok(value) => value,
                Err(error) => {
                    report.error(format!("Failed to decode MMDB metadata: {error}"));
                    return Ok(report.clone());
                }
            };
            let crate::DataValue::Map(map) = metadata_value else {
                report.error("MMDB metadata is not a map");
                return Ok(report.clone());
            };

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
            let tree_size = parsed_header.tree_size;

            if node_count != parsed_header.node_count {
                report.error("Metadata node_count changed between parser passes");
                return Ok(report.clone());
            }

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

            // Validate the same resolved extension locations runtime loading uses.
            if let Some(offset) = embedded_sections.pattern_data_offset() {
                report.info(format!("Pattern section found at offset {offset}"));
                validate_paraglob_section(buffer, offset, report, level)?;
            }

            if let Some(offset) = embedded_sections.literal_data_offset() {
                report.info(format!("Literal section found at offset {offset}"));
                validate_literal_hash_section(buffer, offset, report);
            }

            // Store the exact entry count when Matchy metadata provides it.
            // Search-tree node count is not an entry count and is therefore
            // reported separately in the informational tree summary above.
            report.stats.ip_entry_count = map
                .get("ip_entry_count")
                .and_then(|value| match value {
                    crate::DataValue::Uint16(value) => Some(u32::from(*value)),
                    crate::DataValue::Uint32(value) => Some(*value),
                    crate::DataValue::Uint64(value) => u32::try_from(*value).ok(),
                    _ => None,
                })
                .unwrap_or(0);

            // Always validate data section structure and UTF-8 (critical for safety)
            validate_mmdb_data_section(buffer, tree_size, report);

            // Validate UTF-8 in data section (critical for safety)
            validate_data_section_utf8(buffer, tree_size, node_count, node_bytes, report, level);

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
                report.extend_errors(ip_tree_result.errors);
                report.extend_warnings(ip_tree_result.warnings);
                if ip_tree_result.stats.nodes_visited > 0 && node_count > 0 {
                    let coverage_pct = (u128::from(ip_tree_result.stats.nodes_visited) * 100)
                        / u128::from(node_count);
                    report.info(format!(
                        "IP tree traversal: {} nodes visited out of {} total ({}% coverage)",
                        ip_tree_result.stats.nodes_visited, node_count, coverage_pct
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
            report.error("MMDB_LITERAL marker not found at expected location");
        }
    }

    let metadata_offset = match crate::mmdb::find_metadata_marker(buffer) {
        Ok(offset) => offset,
        Err(error) => {
            report.error(format!("Cannot bound literal section: {error}"));
            return;
        }
    };
    let Some(bounded_buffer) = buffer.get(..metadata_offset) else {
        report.error("Literal section metadata boundary is invalid");
        return;
    };

    let validation = matchy_literal_hash::validate_literal_hash(bounded_buffer, offset);
    report.info(format!(
        "Literal hash: version {}, {} entries, table size {}",
        validation.stats.version, validation.stats.entry_count, validation.stats.table_size
    ));
    report.stats.literal_count = validation.stats.entry_count;
    report.extend_errors(validation.errors);
    report.extend_warnings(validation.warnings);
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

        let Some(node_offset) = i.checked_mul(node_bytes) else {
            report.error(format!("Node {i} offset overflow"));
            break;
        };
        let Some(node_end) = node_offset.checked_add(node_bytes) else {
            report.error(format!("Node {i} end overflow"));
            break;
        };
        if node_end > tree_size {
            report.error(format!(
                "Node {i} offset {node_offset} exceeds tree size {tree_size}"
            ));
            break;
        }

        // Basic check: node data should be within bounds
        if node_end > buffer.len() {
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

    let Some((_, data_section)) = mmdb_data_section(buffer, tree_size) else {
        report.error("Could not determine bounded MMDB data section");
        return;
    };

    let node_count_usize = usize::try_from(node_count).unwrap_or(usize::MAX);
    let mut data_records = 0usize;
    for i in 0..node_count_usize {
        let Some(node_offset) = i.checked_mul(node_bytes) else {
            report.error(format!("Node {i} offset overflow"));
            break;
        };

        for side in 0..=1 {
            let Some(record) = read_tree_record(buffer, node_offset, node_bytes, side) else {
                report.error(format!("Could not read node {i} side {side}"));
                continue;
            };

            match record_data_offset(record, node_count) {
                Ok(Some(data_offset)) => {
                    data_records += 1;
                    if data_offset >= data_section.len() {
                        report.error(format!(
                            "Node {i} side {side} data offset {data_offset} exceeds bounded data section ({} bytes)",
                            data_section.len()
                        ));
                    }
                }
                Ok(None) => {}
                Err(reason) => {
                    report.error(format!(
                        "Node {i} side {side} contains invalid record {record}: {reason}"
                    ));
                }
            }
        }
    }

    report.info(format!(
        "Data pointer envelopes validated exhaustively: {data_records} data record(s)"
    ));
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
    let Some((data_section_start, data_section)) = mmdb_data_section(buffer, tree_size) else {
        report.error("Could not determine bounded MMDB data section");
        return;
    };

    let nodes_to_check = if node_count == 0 {
        0
    } else if level == ValidationLevel::Strict {
        node_count
    } else {
        node_count.min(20)
    };
    let step = node_count.checked_div(nodes_to_check).unwrap_or(1).max(1);

    let mut strings_checked = 0u64;
    let mut values_checked = 0usize;
    let mut checked_offsets = HashSet::new();

    for i in (0..node_count)
        .step_by(step as usize)
        .take(nodes_to_check as usize)
    {
        let Some(node_offset) = usize::try_from(i)
            .ok()
            .and_then(|index| index.checked_mul(node_bytes))
        else {
            report.error(format!("Node {i} offset overflow during data validation"));
            continue;
        };

        for side in 0..=1 {
            let Some(record) = read_tree_record(buffer, node_offset, node_bytes, side) else {
                report.error(format!(
                    "Could not read node {i} side {side} during data validation"
                ));
                continue;
            };

            match record_data_offset(record, node_count) {
                Ok(Some(data_offset)) if data_offset >= data_section.len() => {
                    report.error(format!(
                        "Node {i} side {side} data offset {data_offset} exceeds bounded data section ({} bytes)",
                        data_section.len()
                    ));
                }
                Ok(Some(data_offset)) => {
                    if checked_offsets.contains(&data_offset) {
                        continue;
                    }
                    if checked_offsets.try_reserve(1).is_err() {
                        report.error("Could not allocate data-validation offset set");
                        return;
                    }
                    checked_offsets.insert(data_offset);
                    values_checked += 1;

                    match check_data_value_utf8(data_section, data_offset) {
                        Ok(count) => {
                            strings_checked = strings_checked.saturating_add(u64::from(count));
                        }
                        Err(error) => {
                            report.error(format!(
                                "Invalid data value at file offset {}: {error}",
                                data_section_start + data_offset
                            ));
                        }
                    }
                }
                Ok(None) => {}
                Err(reason) => report.error(format!(
                    "Node {i} side {side} contains invalid record {record}: {reason}"
                )),
            }
        }
    }

    match get_embedded_data_offsets(buffer) {
        Ok(offsets) => {
            for offset in offsets {
                let Ok(data_offset) = usize::try_from(offset) else {
                    report.error(format!("Embedded data offset {offset} is not addressable"));
                    continue;
                };
                if data_offset >= data_section.len() {
                    report.error(format!(
                        "Embedded data offset {data_offset} exceeds bounded data section ({} bytes)",
                        data_section.len()
                    ));
                    continue;
                }
                if checked_offsets.contains(&data_offset) {
                    continue;
                }
                if checked_offsets.try_reserve(1).is_err() {
                    report.error("Could not allocate data-validation offset set");
                    return;
                }
                checked_offsets.insert(data_offset);
                values_checked += 1;

                match check_data_value_utf8(data_section, data_offset) {
                    Ok(count) => {
                        strings_checked = strings_checked.saturating_add(u64::from(count));
                    }
                    Err(error) => report.error(format!(
                        "Invalid embedded data value at file offset {}: {error}",
                        data_section_start + data_offset
                    )),
                }
            }
        }
        Err(error) => report.error(format!(
            "Could not validate embedded data mappings: {error}"
        )),
    }

    let coverage = if level == ValidationLevel::Strict {
        "exhaustive"
    } else {
        "sampled"
    };
    report.info(format!(
        "Data decoding and UTF-8 validation ({coverage}): {values_checked} unique value(s), {strings_checked} string(s)"
    ));
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

    let Some(data_start) = tree_size.checked_add(DATA_SEPARATOR_SIZE) else {
        report.error("Tree plus separator size overflow");
        return;
    };
    if data_start > buffer.len() {
        report.error(format!(
            "Tree size {} + separator {} exceeds file size {}",
            tree_size,
            DATA_SEPARATOR_SIZE,
            buffer.len()
        ));
        return;
    }

    let separator_start = tree_size;

    // Check separator (should be 16 zero bytes)
    let Some(separator) = buffer.get(separator_start..data_start) else {
        report.error("Data separator range is invalid");
        return;
    };
    if separator.iter().all(|&b| b == 0) {
        report.info("Valid data section separator found");
    } else {
        report.warning("Data section separator is non-zero (may be intentional)");
    }

    // Validate only the MMDB data region; extension sections and metadata are
    // bounded separately by the same locator used by runtime loading.
    let Some((_, data_section)) = mmdb_data_section(buffer, tree_size) else {
        report.error("Could not determine bounded MMDB data section");
        return;
    };
    let data_size = data_section.len();
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
    if let Err(error) = get_combined_pattern_data_offsets(buffer, offset) {
        report.error(format!("Invalid combined pattern section: {error}"));
        return Ok(());
    }

    let Some(header_end) = offset.checked_add(2 * std::mem::size_of::<u32>()) else {
        report.error("Pattern section header range overflow");
        return Ok(());
    };
    let Some(section_header) = buffer.get(offset..header_end) else {
        report.error("Pattern section header truncated");
        return Ok(());
    };
    let paraglob_size = usize::try_from(u32::from_le_bytes(
        section_header[4..]
            .try_into()
            .expect("fixed paraglob size field"),
    ))
    .unwrap_or(usize::MAX);
    let Some(paraglob_end) = header_end.checked_add(paraglob_size) else {
        report.error("PARAGLOB section range overflow");
        return Ok(());
    };

    // Validate the PARAGLOB data
    let Some(paraglob_data) = buffer.get(header_end..paraglob_end) else {
        report.error("PARAGLOB section range is out of bounds");
        return Ok(());
    };
    validate_paraglob_header(paraglob_data, report)?;

    if !report.is_valid() {
        return Ok(());
    }

    // Parse PARAGLOB header for stats
    let header = read_paraglob_header(paraglob_data)?;
    report.stats.version = header.version;
    report.stats.ac_node_count = header.ac_node_count;
    report.stats.pattern_count = header.pattern_count;
    report.stats.string_data_size = header.pattern_strings_size;
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
    report.extend_errors(ac_result.errors);
    report.extend_warnings(ac_result.warnings);
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
    report.extend_errors(pattern_result.errors);
    report.extend_warnings(pattern_result.warnings);
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

    // Runtime loading supports only the current header layout. Older versions
    // have different sizes/semantics and must not be parsed as v5.
    if header.version != MATCHY_FORMAT_VERSION {
        report.error(format!(
            "Unsupported Paraglob version: {} (expected {MATCHY_FORMAT_VERSION})",
            header.version
        ));
        return Ok(());
    }
    report.info(format!("Paraglob format version: v{MATCHY_FORMAT_VERSION}"));

    // Validate endianness marker
    match header.endianness {
        0x00 => report.warning("No endianness marker (legacy format)"),
        0x01 => report.info("Endianness: little-endian"),
        0x02 => report.warning(
            "Big-endian marker is reserved; current readers do not implement byte swapping",
        ),
        e => report.warning(format!("Unknown/reserved endianness marker: 0x{e:02x}")),
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
    report.extend_errors(ac_reach_result.errors);
    report.extend_warnings(ac_reach_result.warnings);
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
    report.extend_errors(pattern_ref_result.errors);
    report.extend_warnings(pattern_ref_result.warnings);

    // 3. Validate AC literal mapping (v3)
    if header.has_ac_literal_mapping() {
        let ac_lit_result = matchy_paraglob::validate_ac_literal_mapping(
            buffer,
            header.ac_literal_map_offset as usize,
            header.pattern_count,
        );
        report.extend_errors(ac_lit_result.errors);
        report.extend_warnings(ac_lit_result.warnings);
    }

    // 4. Validate data mappings (v2+)
    if header.has_data_section() && header.mapping_count > 0 {
        let data_map_result = matchy_format::validate_data_mapping_consistency(buffer, header);
        report.extend_errors(data_map_result.errors);
        report.extend_warnings(data_map_result.warnings);
        let coverage_pct = if header.pattern_count > 0 {
            ((data_map_result.stats.patterns_with_data as u128) * 100)
                / u128::from(header.pattern_count)
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
        report.extend_errors(meta_result.errors);
        report.extend_warnings(meta_result.warnings);
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
    let Some((_, data_section)) = mmdb_data_section(buffer, tree_size) else {
        report.error("Could not determine bounded MMDB data section");
        return;
    };

    let nodes_to_check = if node_count == 0 {
        0
    } else if level == ValidationLevel::Strict {
        node_count
    } else {
        node_count.min(20)
    };
    let step = node_count.checked_div(nodes_to_check).unwrap_or(1).max(1);

    let mut values_checked = 0usize;
    let mut cycles_detected = 0;
    let mut max_depth_found = 0;
    let mut invalid_pointers = 0;
    let mut checked_offsets = HashSet::new();

    // Check data values reachable from tree nodes
    for i in (0..node_count)
        .step_by(step as usize)
        .take(nodes_to_check as usize)
    {
        let Some(node_offset) = usize::try_from(i)
            .ok()
            .and_then(|index| index.checked_mul(node_bytes))
        else {
            report.error(format!(
                "Node {i} offset overflow during pointer validation"
            ));
            continue;
        };

        for side in 0..=1 {
            let Some(record) = read_tree_record(buffer, node_offset, node_bytes, side) else {
                report.error(format!(
                    "Could not read node {i} side {side} during pointer validation"
                ));
                continue;
            };
            let data_offset = match record_data_offset(record, node_count) {
                Ok(Some(offset)) if offset < data_section.len() => offset,
                Ok(Some(offset)) => {
                    invalid_pointers += 1;
                    report.error(format!(
                        "Node {i} side {side} data offset {offset} exceeds bounded data section ({} bytes)",
                        data_section.len()
                    ));
                    continue;
                }
                Ok(None) => continue,
                Err(reason) => {
                    invalid_pointers += 1;
                    report.error(format!(
                        "Node {i} side {side} contains invalid record {record}: {reason}"
                    ));
                    continue;
                }
            };

            if checked_offsets.contains(&data_offset) {
                continue;
            }
            if checked_offsets.try_reserve(1).is_err() {
                report.error("Could not allocate pointer-validation offset set");
                return;
            }
            checked_offsets.insert(data_offset);
            values_checked += 1;

            let mut path = HashSet::new();
            match matchy_data_format::validate_data_value_pointers(
                data_section,
                data_offset,
                &mut path,
                0,
            ) {
                Ok(depth) => max_depth_found = max_depth_found.max(depth),
                Err(matchy_data_format::PointerValidationError::Cycle { offset }) => {
                    cycles_detected += 1;
                    report.error(format!(
                        "Pointer cycle detected in data section at offset {offset}"
                    ));
                }
                Err(matchy_data_format::PointerValidationError::DepthExceeded { depth }) => {
                    report.error(format!(
                        "Data pointer/nesting depth {depth} exceeds a safe limit"
                    ));
                }
                Err(matchy_data_format::PointerValidationError::InvalidOffset {
                    offset,
                    reason,
                }) => {
                    invalid_pointers += 1;
                    report.error(format!("Invalid data at offset {offset}: {reason}"));
                }
                Err(matchy_data_format::PointerValidationError::InvalidType {
                    offset,
                    type_id,
                }) => {
                    report.error(format!("Invalid data type {type_id} at offset {offset}"));
                }
            }
        }
    }

    match get_embedded_data_offsets(buffer) {
        Ok(offsets) => {
            for offset in offsets {
                let Ok(data_offset) = usize::try_from(offset) else {
                    invalid_pointers += 1;
                    report.error(format!("Embedded data offset {offset} is not addressable"));
                    continue;
                };
                if data_offset >= data_section.len() {
                    invalid_pointers += 1;
                    report.error(format!(
                        "Embedded data offset {data_offset} exceeds bounded data section ({} bytes)",
                        data_section.len()
                    ));
                    continue;
                }
                if checked_offsets.contains(&data_offset) {
                    continue;
                }
                if checked_offsets.try_reserve(1).is_err() {
                    report.error("Could not allocate pointer-validation offset set");
                    return;
                }
                checked_offsets.insert(data_offset);
                values_checked += 1;

                let mut path = HashSet::new();
                match matchy_data_format::validate_data_value_pointers(
                    data_section,
                    data_offset,
                    &mut path,
                    0,
                ) {
                    Ok(depth) => max_depth_found = max_depth_found.max(depth),
                    Err(matchy_data_format::PointerValidationError::Cycle { offset }) => {
                        cycles_detected += 1;
                        report.error(format!(
                            "Pointer cycle detected in embedded data at offset {offset}"
                        ));
                    }
                    Err(matchy_data_format::PointerValidationError::DepthExceeded { depth }) => {
                        report.error(format!(
                            "Embedded data pointer/nesting depth {depth} exceeds a safe limit"
                        ));
                    }
                    Err(matchy_data_format::PointerValidationError::InvalidOffset {
                        offset,
                        reason,
                    }) => {
                        invalid_pointers += 1;
                        report.error(format!(
                            "Invalid embedded data at offset {offset}: {reason}"
                        ));
                    }
                    Err(matchy_data_format::PointerValidationError::InvalidType {
                        offset,
                        type_id,
                    }) => report.error(format!(
                        "Invalid embedded data type {type_id} at offset {offset}"
                    )),
                }
            }
        }
        Err(error) => report.error(format!(
            "Could not validate embedded data mappings: {error}"
        )),
    }

    let coverage = if level == ValidationLevel::Strict {
        "exhaustive"
    } else {
        "sampled"
    };
    report.info(format!(
        "Data structure validation ({coverage}): {values_checked} unique value(s), max pointer depth {max_depth_found}"
    ));

    if cycles_detected > 0 {
        report.error(format!("{cycles_detected} pointer cycle(s) detected"));
    }

    if invalid_pointers > 0 {
        report.error(format!(
            "{invalid_pointers} invalid data pointer/offset record(s) detected"
        ));
    }
}

/// Get all data offsets from the literal hash section
fn get_literal_data_offsets(
    buffer: &[u8],
    literal_offset: usize,
) -> std::result::Result<Vec<u32>, String> {
    let metadata_offset = crate::mmdb::find_metadata_marker(buffer).map_err(|error| {
        format!("Could not bound literal mappings before MMDB metadata: {error}")
    })?;
    let literal_data = buffer
        .get(literal_offset..metadata_offset)
        .ok_or_else(|| "Literal section range is invalid".to_string())?;
    let literal_hash = matchy_literal_hash::LiteralHash::from_buffer(
        literal_data,
        crate::MatchMode::CaseSensitive,
    )
    .map_err(|error| format!("Invalid literal hash: {error}"))?;

    Ok(literal_hash
        .data_mappings()
        .map(|(_, data_offset)| data_offset)
        .collect())
}

fn get_combined_pattern_data_offsets(
    buffer: &[u8],
    pattern_offset: usize,
) -> std::result::Result<Vec<u32>, String> {
    let metadata_offset = crate::mmdb::find_metadata_marker(buffer).map_err(|error| {
        format!("Could not bound pattern mappings before MMDB metadata: {error}")
    })?;
    let header_end = pattern_offset
        .checked_add(2 * std::mem::size_of::<u32>())
        .ok_or_else(|| "Pattern section header range overflow".to_string())?;
    let header = buffer
        .get(pattern_offset..header_end)
        .filter(|_| header_end <= metadata_offset)
        .ok_or_else(|| "Pattern section header is truncated".to_string())?;
    let total_size = usize::try_from(u32::from_le_bytes(
        header[..4].try_into().expect("fixed pattern size field"),
    ))
    .map_err(|_| "Pattern section size is not addressable".to_string())?;
    let paraglob_size = usize::try_from(u32::from_le_bytes(
        header[4..].try_into().expect("fixed paraglob size field"),
    ))
    .map_err(|_| "Paraglob size is not addressable".to_string())?;

    let section_end = pattern_offset
        .checked_add(total_size)
        .ok_or_else(|| "Pattern section range overflow".to_string())?;
    if section_end > metadata_offset || section_end < header_end {
        return Err("Pattern section exceeds its containing MMDB region".to_string());
    }
    let paraglob_end = header_end
        .checked_add(paraglob_size)
        .ok_or_else(|| "Paraglob range overflow".to_string())?;
    let paraglob_data = buffer
        .get(header_end..paraglob_end)
        .filter(|_| paraglob_end <= section_end)
        .ok_or_else(|| "Paraglob section exceeds the declared pattern section".to_string())?;
    let paraglob_header = read_paraglob_header(paraglob_data)
        .map_err(|error| format!("Could not read embedded Paraglob header: {error}"))?;
    let count_end = paraglob_end
        .checked_add(std::mem::size_of::<u32>())
        .ok_or_else(|| "Pattern mapping count range overflow".to_string())?;
    let count_bytes = buffer
        .get(paraglob_end..count_end)
        .filter(|_| count_end <= section_end)
        .ok_or_else(|| "Pattern mapping count is truncated".to_string())?;
    let count = usize::try_from(u32::from_le_bytes(
        count_bytes
            .try_into()
            .expect("fixed pattern mapping count field"),
    ))
    .map_err(|_| "Pattern mapping count is not addressable".to_string())?;
    let inner_pattern_count = usize::try_from(paraglob_header.pattern_count)
        .map_err(|_| "Embedded Paraglob pattern count is not addressable".to_string())?;
    if count < inner_pattern_count {
        return Err(format!(
            "Pattern mapping count {count} is smaller than embedded Paraglob pattern count {inner_pattern_count}"
        ));
    }
    let mapping_bytes = count
        .checked_mul(std::mem::size_of::<u32>())
        .ok_or_else(|| "Pattern mapping table size overflow".to_string())?;
    let mappings_end = count_end
        .checked_add(mapping_bytes)
        .ok_or_else(|| "Pattern mapping table range overflow".to_string())?;
    if mappings_end != section_end {
        return Err(format!(
            "Pattern mapping table ends at {mappings_end}, declared section ends at {section_end}"
        ));
    }

    let mappings = buffer
        .get(count_end..mappings_end)
        .ok_or_else(|| "Pattern mapping table is out of bounds".to_string())?;
    let mut offsets = Vec::new();
    offsets
        .try_reserve_exact(count)
        .map_err(|_| "Could not allocate pattern mapping offsets".to_string())?;
    for bytes in mappings.chunks_exact(std::mem::size_of::<u32>()) {
        offsets.push(u32::from_le_bytes(
            bytes.try_into().expect("mapping chunks are four bytes"),
        ));
    }
    Ok(offsets)
}

fn get_embedded_data_offsets(buffer: &[u8]) -> std::result::Result<Vec<u32>, String> {
    let metadata_offset = crate::mmdb::find_metadata_marker(buffer)
        .map_err(|error| format!("Could not locate MMDB metadata: {error}"))?;
    let sections = crate::Database::locate_embedded_sections(buffer, metadata_offset)?;
    let mut offsets = Vec::new();

    if let Some(literal_offset) = sections.literal_data_offset() {
        offsets.extend(get_literal_data_offsets(buffer, literal_offset)?);
    }
    if let Some(pattern_offset) = sections.pattern_data_offset() {
        offsets.extend(get_combined_pattern_data_offsets(buffer, pattern_offset)?);
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

    let Some((_, data_section)) = mmdb_data_section(buffer, tree_size) else {
        report.warning("No data section found for schema validation");
        return;
    };
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
        entries_checked = entries_checked.saturating_add(1);

        let Ok(data_offset_usize) = usize::try_from(data_offset) else {
            validation_failures += 1;
            if first_errors.len() < MAX_ERRORS_TO_REPORT as usize {
                first_errors.push(format!("{source} offset {data_offset} is not addressable"));
            }
            return;
        };
        if data_offset_usize >= data_section.len() {
            validation_failures += 1;
            if first_errors.len() < MAX_ERRORS_TO_REPORT as usize {
                first_errors.push(format!(
                    "{source} offset {data_offset} exceeds bounded data section ({} bytes)",
                    data_section.len()
                ));
            }
            return;
        }

        match decoder.decode(data_offset) {
            Ok(DataValue::Map(map)) => {
                if let Err(e) = validator.validate(&map) {
                    validation_failures += 1;
                    if first_errors.len() < MAX_ERRORS_TO_REPORT as usize {
                        first_errors.push(format!("{source} at offset {data_offset}: {e}"));
                    }
                }
            }
            Ok(_) => {
                validation_failures += 1;
                if first_errors.len() < MAX_ERRORS_TO_REPORT as usize {
                    first_errors.push(format!("{source} at offset {data_offset} is not a map"));
                }
            }
            Err(error) => {
                validation_failures += 1;
                if first_errors.len() < MAX_ERRORS_TO_REPORT as usize {
                    first_errors.push(format!(
                        "{source} at offset {data_offset} does not decode: {error}"
                    ));
                }
            }
        }
    };

    // Validate all entries referenced by literal and combined-pattern mappings.
    match get_embedded_data_offsets(buffer) {
        Ok(data_offsets) => {
            for data_offset in data_offsets {
                validate_at_offset(data_offset, "String entry");
            }
        }
        Err(error) => report.error(format!("Could not validate embedded mappings: {error}")),
    }

    // Validate all unique data from IP tree nodes.
    // We traverse the tree to find all leaf nodes with data pointers
    for i in 0..node_count {
        let Some(node_offset) = usize::try_from(i)
            .ok()
            .and_then(|index| index.checked_mul(node_bytes))
        else {
            continue;
        };
        let Some(node_end) = node_offset.checked_add(node_bytes) else {
            continue;
        };

        if node_end > tree_size {
            continue;
        }

        // Read both left and right records
        let Some(left_record) = read_tree_record(buffer, node_offset, node_bytes, 0) else {
            continue;
        };
        let Some(right_record) = read_tree_record(buffer, node_offset, node_bytes, 1) else {
            continue;
        };

        for record in [left_record, right_record] {
            if let Ok(Some(data_offset)) = record_data_offset(record, node_count) {
                if let Ok(offset) = u32::try_from(data_offset) {
                    validate_at_offset(offset, "IP entry");
                }
            }
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
            let pct_failed = (u128::from(validation_failures) * 100) / u128::from(entries_checked);
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
    use matchy_data_format::DataEncoder;
    use std::collections::HashMap;
    use tempfile::NamedTempFile;

    const TEST_METADATA_MARKER: &[u8] = b"\xAB\xCD\xEFMaxMind.com";

    fn synthetic_mmdb(node_count: u32, tree: &[u8], data_section: &[u8]) -> Vec<u8> {
        let mut metadata = HashMap::new();
        metadata.insert("node_count".to_string(), DataValue::Uint32(node_count));
        metadata.insert("record_size".to_string(), DataValue::Uint16(24));
        metadata.insert("ip_version".to_string(), DataValue::Uint16(4));

        let mut encoder = DataEncoder::new();
        encoder.encode(&DataValue::Map(metadata));

        let mut bytes = tree.to_vec();
        bytes.extend_from_slice(&[0; 16]);
        bytes.extend_from_slice(data_section);
        bytes.extend_from_slice(TEST_METADATA_MARKER);
        bytes.extend_from_slice(&encoder.into_bytes());
        bytes
    }

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
        let mut builder = matchy_format::DatabaseBuilder::new(crate::MatchMode::CaseSensitive);
        for key in ["192.0.2.1", "literal.example", "*.malware.test"] {
            let mut data = HashMap::new();
            data.insert("source".to_string(), DataValue::String("test".to_string()));
            builder.add_entry(key, data).unwrap();
        }
        let bytes = builder.build().unwrap();

        for level in [ValidationLevel::Standard, ValidationLevel::Strict] {
            let mut report = ValidationReport::new();
            let report = validate_mmdb_database(&bytes, &mut report, level).unwrap();
            assert!(
                report.is_valid(),
                "{level:?} rejected builder output: {:?}",
                report.errors
            );
            assert!(report.stats.ip_entry_count > 0);
            assert!(report.stats.literal_count > 0);
            assert!(report.stats.glob_count > 0);
        }
    }

    #[test]
    fn validator_rejects_too_few_outer_pattern_mappings() {
        let mut builder = matchy_format::DatabaseBuilder::new(crate::MatchMode::CaseSensitive);
        for key in ["*.one.test", "*.two.test"] {
            let mut data = HashMap::new();
            data.insert("source".to_string(), DataValue::String("test".to_string()));
            builder.add_entry(key, data).unwrap();
        }
        let mut bytes = builder.build().unwrap();

        let metadata_offset = crate::mmdb::find_metadata_marker(&bytes).unwrap();
        let sections = crate::Database::locate_embedded_sections(&bytes, metadata_offset).unwrap();
        let pattern_offset = sections.pattern_data_offset().unwrap();
        let total_size = usize::try_from(u32::from_le_bytes(
            bytes[pattern_offset..pattern_offset + 4]
                .try_into()
                .unwrap(),
        ))
        .unwrap();
        let paraglob_size = usize::try_from(u32::from_le_bytes(
            bytes[pattern_offset + 4..pattern_offset + 8]
                .try_into()
                .unwrap(),
        ))
        .unwrap();
        let count_offset = pattern_offset + 8 + paraglob_size;
        assert_eq!(
            u32::from_le_bytes(bytes[count_offset..count_offset + 4].try_into().unwrap()),
            2
        );

        // Keep the outer envelope internally consistent while dropping one
        // mapping. The embedded Paraglob still declares both patterns.
        bytes[pattern_offset..pattern_offset + 4]
            .copy_from_slice(&u32::try_from(total_size - 4).unwrap().to_le_bytes());
        bytes[count_offset..count_offset + 4].copy_from_slice(&1u32.to_le_bytes());
        let section_end = pattern_offset + total_size;
        bytes.drain(section_end - 4..section_end);

        let mut report = ValidationReport::new();
        let report = validate_mmdb_database(&bytes, &mut report, ValidationLevel::Standard)
            .expect("validation should return a report");

        assert!(!report.is_valid());
        assert!(report.errors.iter().any(|error| error.contains(
            "Pattern mapping count 1 is smaller than embedded Paraglob pattern count 2"
        )));
    }

    #[test]
    fn test_validate_corrupted_database() {
        // Test with non-MMDB data
        let db_bytes = vec![0u8; 1024]; // Random bytes, not MMDB format
        let expected_size = db_bytes.len();

        let temp = NamedTempFile::new().unwrap();
        std::fs::write(temp.path(), db_bytes).unwrap();

        let result = validate_database(temp.path(), ValidationLevel::Standard);
        assert!(result.is_ok());

        let report = result.unwrap();
        assert_eq!(report.stats.file_size, expected_size);
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
    fn validation_report_caps_retained_findings() {
        let mut report = ValidationReport::new();
        report.extend_errors((0..MAX_VALIDATION_ERRORS + 10).map(|i| format!("merged error {i}")));
        report.extend_warnings(
            (0..MAX_VALIDATION_WARNINGS + 10).map(|i| format!("merged warning {i}")),
        );
        // Component validators use the same sentinel. Merging their capped
        // output must not create duplicate suppression messages.
        report.extend_errors([ERRORS_SUPPRESSED.to_string()]);
        report.extend_warnings([WARNINGS_SUPPRESSED.to_string()]);
        for i in 0..MAX_VALIDATION_INFO + 10 {
            report.info(format!("info {i}"));
        }

        assert_eq!(report.errors.len(), MAX_VALIDATION_ERRORS);
        assert_eq!(report.warnings.len(), MAX_VALIDATION_WARNINGS);
        assert_eq!(report.info.len(), MAX_VALIDATION_INFO);
        assert_eq!(
            report
                .errors
                .iter()
                .filter(|message| message.as_str() == ERRORS_SUPPRESSED)
                .count(),
            1
        );
        assert_eq!(
            report
                .warnings
                .iter()
                .filter(|message| message.as_str() == WARNINGS_SUPPRESSED)
                .count(),
            1
        );
        assert_eq!(
            report
                .info
                .iter()
                .filter(|message| message.as_str() == INFO_SUPPRESSED)
                .count(),
            1
        );
        assert!(!report.is_valid());
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

    #[test]
    fn tree_record_helpers_fail_closed() {
        let node = [0, 0, 1, 0, 0, 17];
        assert_eq!(read_tree_record(&node, 0, 6, 0), Some(1));
        assert_eq!(read_tree_record(&node, 0, 6, 1), Some(17));
        assert_eq!(read_tree_record(&node, 0, 6, 2), None);
        assert_eq!(read_tree_record(&node[..5], 0, 6, 0), None);
        assert_eq!(read_tree_record(&node, usize::MAX, 6, 0), None);

        assert_eq!(record_data_offset(100, 100), Ok(None));
        assert!(record_data_offset(101, 100).is_err());
        assert!(record_data_offset(115, 100).is_err());
        assert_eq!(record_data_offset(116, 100), Ok(Some(0)));
    }

    #[test]
    fn validator_rejects_claimed_tree_outside_file() {
        let bytes = synthetic_mmdb(1, &[], &[]);
        let mut report = ValidationReport::new();
        let report = validate_mmdb_database(&bytes, &mut report, ValidationLevel::Standard)
            .expect("validation should return a report");

        assert!(!report.is_valid());
        assert!(report
            .errors
            .iter()
            .any(|error| error.contains("Invalid MMDB header")));
    }

    #[test]
    fn strict_validation_checks_right_side_data_records() {
        // One 24-bit node: left is the not-found sentinel, right points to data
        // offset zero. That value is a self-pointer and must be rejected.
        let bytes = synthetic_mmdb(1, &[0, 0, 1, 0, 0, 17], &[0x20, 0x00]);
        let mut report = ValidationReport::new();
        let report = validate_mmdb_database(&bytes, &mut report, ValidationLevel::Strict)
            .expect("validation should return a report");

        assert!(!report.is_valid());
        assert!(report.errors.iter().any(|error| {
            error.contains("Pointer cycle") || error.contains("Invalid data value")
        }));
    }
}
