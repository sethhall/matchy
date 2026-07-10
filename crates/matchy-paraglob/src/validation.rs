//! Paraglob validation for untrusted binary data
//!
//! This module checks paraglob pattern structures and their relationships before
//! runtime loading. It validates pattern entries, AC literal mappings, meta-word
//! mappings, and cross-references between patterns and AC nodes.

use crate::offset_format::{MetaWordMapping, PatternEntry};
use std::collections::HashSet;
use std::mem;
use zerocopy::FromBytes;

const MAX_VALIDATION_ERRORS: usize = 256;
const MAX_VALIDATION_WARNINGS: usize = 256;
const ERRORS_SUPPRESSED: &str =
    "Additional validation errors suppressed after reaching the limit of 256";
const WARNINGS_SUPPRESSED: &str =
    "Additional validation warnings suppressed after reaching the limit of 256";

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

/// Validation result for paraglob structures
#[derive(Debug, Clone)]
pub struct ParaglobValidationResult {
    /// Critical errors, capped at 256 retained messages including a suppression sentinel.
    pub errors: Vec<String>,
    /// Non-fatal warnings, capped at 256 retained messages including a suppression sentinel.
    pub warnings: Vec<String>,
    /// Statistics gathered during validation
    pub stats: ParaglobStats,
}

/// Statistics gathered during paraglob validation
#[derive(Debug, Clone, Default)]
pub struct ParaglobStats {
    /// Number of patterns
    pub pattern_count: u32,
    /// Number of literal patterns
    pub literal_count: u32,
    /// Number of glob patterns
    pub glob_count: u32,
    /// Number of AC literal mapping entries validated
    pub ac_literal_map_entries: u32,
    /// Number of meta-word mappings
    pub meta_word_count: u32,
    /// Number of unreferenced literal patterns
    pub unreferenced_literals: u32,
}

impl ParaglobValidationResult {
    fn new() -> Self {
        Self {
            errors: Vec::new(),
            warnings: Vec::new(),
            stats: ParaglobStats::default(),
        }
    }

    /// Check if validation passed (no errors)
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.errors.is_empty()
    }

    fn error(&mut self, message: impl Into<String>) {
        push_capped(
            &mut self.errors,
            message.into(),
            MAX_VALIDATION_ERRORS,
            ERRORS_SUPPRESSED,
        );
    }

    fn warning(&mut self, message: impl Into<String>) {
        push_capped(
            &mut self.warnings,
            message.into(),
            MAX_VALIDATION_WARNINGS,
            WARNINGS_SUPPRESSED,
        );
    }
}

/// Validate pattern entries
///
/// Validates:
/// - Pattern entry bounds
/// - Pattern type validity (literal vs glob)
/// - Pattern ID consistency
///
/// # Arguments
///
/// * `buffer` - The buffer containing paraglob data
/// * `patterns_offset` - Offset to the pattern entries array
/// * `pattern_count` - Number of patterns
///
/// # Returns
///
/// A `ParaglobValidationResult` with errors, warnings, and statistics
#[must_use]
pub fn validate_patterns(
    buffer: &[u8],
    patterns_offset: usize,
    pattern_count: usize,
) -> ParaglobValidationResult {
    let mut result = ParaglobValidationResult::new();
    result.stats.pattern_count = u32::try_from(pattern_count).unwrap_or(u32::MAX);

    if pattern_count == 0 {
        return result;
    }

    let mut literal_count = 0;
    let mut glob_count = 0;

    for i in 0..pattern_count {
        let entry_offset = patterns_offset + i * mem::size_of::<PatternEntry>();

        if entry_offset + mem::size_of::<PatternEntry>() > buffer.len() {
            result.error(format!("Pattern entry {i} out of bounds"));
            continue;
        }

        let entry = match PatternEntry::read_from_prefix(&buffer[entry_offset..]) {
            Ok((e, _)) => e,
            Err(_) => {
                result.error(format!("Failed to read pattern entry {i}"));
                continue;
            }
        };

        // Validate pattern type
        match entry.pattern_type {
            0 => literal_count += 1, // Literal
            1 => glob_count += 1,    // Glob
            t => result.error(format!("Pattern {i} has invalid type: {t}")),
        }

        // Pattern ID should match index (typically)
        if let Ok(expected_id) = u32::try_from(i) {
            if entry.pattern_id != expected_id {
                result.warning(format!(
                    "Pattern {} has mismatched ID: {} (expected {})",
                    i, entry.pattern_id, i
                ));
            }
        }
    }

    result.stats.literal_count = literal_count;
    result.stats.glob_count = glob_count;

    result
}

/// Build pattern info list for cross-validation with AC
///
/// Creates a list of (pattern_id, pattern_type) tuples that can be passed
/// to matchy_ac::validate_pattern_references for cross-validation.
/// This avoids matchy-paraglob needing to read AC node structures.
///
/// # Arguments
///
/// * `buffer` - The buffer containing paraglob data
/// * `patterns_offset` - Offset to the pattern entries array
/// * `pattern_count` - Number of patterns
///
/// # Returns
///
/// A vector of (pattern_id, pattern_type) tuples, or an error
pub fn build_pattern_info(
    buffer: &[u8],
    patterns_offset: usize,
    pattern_count: usize,
) -> Result<Vec<(u32, u8)>, String> {
    let mut pattern_info = Vec::with_capacity(pattern_count);

    for i in 0..pattern_count {
        let entry_offset = patterns_offset + i * mem::size_of::<PatternEntry>();
        if entry_offset + mem::size_of::<PatternEntry>() > buffer.len() {
            return Err(format!("Pattern entry {i} out of bounds"));
        }

        let entry = match PatternEntry::read_from_prefix(&buffer[entry_offset..]) {
            Ok((e, _)) => e,
            Err(_) => return Err(format!("Failed to read pattern entry {i}")),
        };

        pattern_info.push((entry.pattern_id, entry.pattern_type));
    }

    Ok(pattern_info)
}

/// Validate AC literal mapping consistency
///
/// Validates the AC literal mapping structure (v3+ format - hash table).
/// Checks entry counts, pattern ID references, and structure integrity.
///
/// # Arguments
///
/// * `buffer` - The buffer containing paraglob data
/// * `map_offset` - Offset to the AC literal mapping
/// * `pattern_count` - Total number of patterns (for validating pattern IDs)
///
/// # Returns
///
/// A `ParaglobValidationResult` with errors, warnings, and statistics
#[must_use]
pub fn validate_ac_literal_mapping(
    buffer: &[u8],
    map_offset: usize,
    pattern_count: u32,
) -> ParaglobValidationResult {
    let mut result = ParaglobValidationResult::new();

    // Load the hash table and validate it
    let hash_buffer = &buffer[map_offset..];
    if let Err(e) = crate::literal_hash::ACLiteralHash::from_buffer(hash_buffer) {
        result.error(format!("Failed to load AC literal hash table: {e}"));
        return result;
    }

    // Validate all pattern IDs in the hash table
    // We need to walk through the hash table entries and check pattern lists
    let header_size = mem::size_of::<crate::literal_hash::ACLiteralHashHeader>();
    let table_start = map_offset + header_size;
    let entry_size = mem::size_of::<crate::literal_hash::ACHashEntry>();

    // Read header to get table size
    if hash_buffer.len() < header_size {
        result.error("AC literal hash header truncated");
        return result;
    }

    let table_size = u32::from_le_bytes([
        hash_buffer[12],
        hash_buffer[13],
        hash_buffer[14],
        hash_buffer[15],
    ]) as usize;

    let patterns_start_in_hash = u32::from_le_bytes([
        hash_buffer[16],
        hash_buffer[17],
        hash_buffer[18],
        hash_buffer[19],
    ]) as usize;

    let mut referenced_patterns = HashSet::new();
    let mut entries_validated = 0;

    // Walk through hash table entries
    for i in 0..table_size {
        let entry_offset = table_start - map_offset + i * entry_size;
        if entry_offset + entry_size > hash_buffer.len() {
            result.error(format!("Hash table entry {i} out of bounds"));
            break;
        }

        let literal_id = u32::from_le_bytes([
            hash_buffer[entry_offset],
            hash_buffer[entry_offset + 1],
            hash_buffer[entry_offset + 2],
            hash_buffer[entry_offset + 3],
        ]);

        // Skip empty slots
        if literal_id == 0xFFFFFFFF {
            continue;
        }

        let patterns_offset = u32::from_le_bytes([
            hash_buffer[entry_offset + 4],
            hash_buffer[entry_offset + 5],
            hash_buffer[entry_offset + 6],
            hash_buffer[entry_offset + 7],
        ]) as usize;

        let pattern_count_entry = u32::from_le_bytes([
            hash_buffer[entry_offset + 8],
            hash_buffer[entry_offset + 9],
            hash_buffer[entry_offset + 10],
            hash_buffer[entry_offset + 11],
        ]) as usize;

        // Validate pattern IDs
        let abs_patterns_offset = patterns_start_in_hash + patterns_offset;
        for j in 0..pattern_count_entry {
            let pid_offset = abs_patterns_offset + j * 4;
            if pid_offset + 4 > hash_buffer.len() {
                result.error(format!(
                    "Pattern list for literal {literal_id} truncated at pattern {j}"
                ));
                break;
            }

            let pattern_id = u32::from_le_bytes([
                hash_buffer[pid_offset],
                hash_buffer[pid_offset + 1],
                hash_buffer[pid_offset + 2],
                hash_buffer[pid_offset + 3],
            ]);

            if pattern_id >= pattern_count {
                result.error(format!(
                    "AC literal mapping entry {i} references invalid pattern ID: {pattern_id}"
                ));
            } else {
                referenced_patterns.insert(pattern_id);
            }
        }

        entries_validated += 1;
    }

    result.stats.ac_literal_map_entries = entries_validated;

    result
}

/// Validate meta-word mappings
///
/// Validates meta-word mapping structures.
/// Checks string offsets, pattern ID arrays, and reference validity.
///
/// # Arguments
///
/// * `buffer` - The buffer containing paraglob data
/// * `mapping_offset` - Offset to the meta-word mappings array
/// * `mapping_count` - Number of meta-word mappings
/// * `pattern_count` - Total number of patterns (for validating pattern IDs)
///
/// # Returns
///
/// A `ParaglobValidationResult` with errors, warnings, and statistics
#[must_use]
pub fn validate_meta_word_mappings(
    buffer: &[u8],
    mapping_offset: usize,
    mapping_count: usize,
    pattern_count: u32,
) -> ParaglobValidationResult {
    let mut result = ParaglobValidationResult::new();
    result.stats.meta_word_count = u32::try_from(mapping_count).unwrap_or(u32::MAX);

    let mut referenced_patterns = HashSet::new();
    let mut invalid_references = 0;

    for i in 0..mapping_count {
        let entry_offset = mapping_offset + i * mem::size_of::<MetaWordMapping>();
        if entry_offset + mem::size_of::<MetaWordMapping>() > buffer.len() {
            result.error(format!("Meta-word mapping {i} out of bounds"));
            continue;
        }

        let mapping = match MetaWordMapping::read_from_prefix(&buffer[entry_offset..]) {
            Ok((m, _)) => m,
            Err(_) => {
                result.error(format!("Failed to read meta-word mapping {i}"));
                continue;
            }
        };

        // Validate meta-word string offset
        if mapping.meta_word_offset as usize >= buffer.len() {
            invalid_references += 1;
        }

        // Validate pattern IDs array offset and count
        if mapping.pattern_count > 0 {
            let pattern_ids_size = (mapping.pattern_count as usize) * mem::size_of::<u32>();
            let pattern_ids_offset = mapping.pattern_ids_offset as usize;

            if pattern_ids_offset + pattern_ids_size <= buffer.len() {
                // Read and validate each pattern ID
                for j in 0..mapping.pattern_count {
                    let pid_offset = pattern_ids_offset + (j as usize) * mem::size_of::<u32>();
                    if pid_offset + 4 <= buffer.len() {
                        let pattern_id = u32::from_le_bytes([
                            buffer[pid_offset],
                            buffer[pid_offset + 1],
                            buffer[pid_offset + 2],
                            buffer[pid_offset + 3],
                        ]);

                        if pattern_id >= pattern_count {
                            invalid_references += 1;
                        } else {
                            referenced_patterns.insert(pattern_id);
                        }
                    }
                }
            } else {
                invalid_references += 1;
            }
        }
    }

    if invalid_references > 0 {
        result.error(format!(
            "Meta-word mappings contain {invalid_references} invalid references"
        ));
    }

    result
}

/// Get pattern data offsets for cross-component validation
///
/// Extracts all data_offset values from PatternDataMapping entries.
/// These offsets are relative to this Paraglob's inline data section. They are
/// not the separate MMDB-relative offsets stored by a combined Matchy database.
///
/// # Arguments
///
/// * `buffer` - The PARAGLOB section buffer (starting at PARAGLOB magic)
/// * `header` - Already-parsed ParaglobHeader
///
/// # Returns
///
/// Vector of inline-data-relative offsets, empty if no data mappings exist.
///
/// # Example
///
/// ```rust,ignore
/// let offsets = get_pattern_data_offsets(paraglob_buffer, &header)?;
/// for offset in offsets {
///     validate_offset_in_inline_data(offset, &header)?;
/// }
/// ```
pub fn get_pattern_data_offsets(
    buffer: &[u8],
    header: &crate::offset_format::ParaglobHeader,
) -> Result<Vec<u32>, String> {
    // Check if this PARAGLOB section has data mappings
    if !header.has_data_section() || header.mapping_count == 0 {
        return Ok(Vec::new());
    }

    let mappings_offset = usize::try_from(header.mapping_table_offset)
        .map_err(|_| "Pattern mapping offset is not addressable".to_string())?;
    let mapping_count = usize::try_from(header.mapping_count)
        .map_err(|_| "Pattern mapping count is not addressable".to_string())?;
    let mapping_size = mem::size_of::<crate::offset_format::PatternDataMapping>();

    // Validate mappings are within buffer
    let mappings_size = mapping_count
        .checked_mul(mapping_size)
        .ok_or_else(|| "Pattern mapping table size overflow".to_string())?;
    let mappings_end = mappings_offset
        .checked_add(mappings_size)
        .ok_or_else(|| "Pattern mapping table range overflow".to_string())?;
    if mappings_end > buffer.len() {
        return Err("Pattern data mappings extend beyond buffer".to_string());
    }

    let mut offsets = Vec::new();
    offsets
        .try_reserve_exact(mapping_count)
        .map_err(|_| "Could not allocate pattern data offsets".to_string())?;

    // Read each PatternDataMapping and extract data_offset
    for i in 0..mapping_count {
        let mapping_offset = mappings_offset + i * mapping_size;
        let mapping_end = mapping_offset + mapping_size;
        let mapping_bytes = &buffer[mapping_offset..mapping_end];

        let (mapping, _) = crate::offset_format::PatternDataMapping::read_from_prefix(
            mapping_bytes,
        )
        .map_err(|_| format!("Failed to read PatternDataMapping at offset {mapping_offset}"))?;

        // Extract just the data_offset field (the yield value)
        offsets.push(mapping.data_offset);
    }

    Ok(offsets)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation_result_caps_retained_findings() {
        let mut result = ParaglobValidationResult::new();
        for i in 0..MAX_VALIDATION_ERRORS + 10 {
            result.error(format!("error {i}"));
        }
        for i in 0..MAX_VALIDATION_WARNINGS + 10 {
            result.warning(format!("warning {i}"));
        }

        assert_eq!(result.errors.len(), MAX_VALIDATION_ERRORS);
        assert_eq!(result.warnings.len(), MAX_VALIDATION_WARNINGS);
        assert_eq!(
            result
                .errors
                .iter()
                .filter(|message| message.as_str() == ERRORS_SUPPRESSED)
                .count(),
            1
        );
        assert_eq!(
            result
                .warnings
                .iter()
                .filter(|message| message.as_str() == WARNINGS_SUPPRESSED)
                .count(),
            1
        );
        assert!(!result.is_valid());
    }

    #[test]
    fn test_empty_patterns() {
        let buffer = vec![0u8; 100];
        let result = validate_patterns(&buffer, 0, 0);
        assert!(result.is_valid());
        assert_eq!(result.stats.pattern_count, 0);
    }

    #[test]
    fn test_validate_patterns_out_of_bounds() {
        let buffer = vec![0u8; 10]; // Too small
        let result = validate_patterns(&buffer, 0, 1);
        assert!(!result.is_valid());
        assert!(!result.errors.is_empty());
    }

    #[test]
    fn test_get_pattern_data_offsets_no_mappings() {
        // Create a minimal valid header with no data section
        let mut buffer = vec![0u8; mem::size_of::<crate::offset_format::ParaglobHeader>()];
        let magic = b"PARAGLOB";
        buffer[..8].copy_from_slice(magic);

        let header = crate::offset_format::ParaglobHeader::read_from_prefix(&buffer)
            .unwrap()
            .0;
        let result = get_pattern_data_offsets(&buffer, &header);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 0);
    }
}
