//! Validation for matchy format file structure
//!
//! Provides validation of pattern-to-data mappings and other format-level
//! consistency checks.

use crate::{ParaglobHeader, PatternDataMapping};
use matchy_data_format::{DataDecoder, DataValue};
use std::collections::{HashMap, HashSet};
use std::error::Error;
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

/// Trait for validating entry data before insertion into a database
///
/// Implement this trait to provide custom validation logic for entries
/// being added to a [`DatabaseBuilder`](crate::DatabaseBuilder).
///
/// # Example
///
/// ```rust,ignore
/// use matchy_format::{DatabaseBuilder, EntryValidator};
/// use matchy_data_format::DataValue;
/// use std::collections::HashMap;
/// use std::error::Error;
///
/// struct RequiredFieldValidator {
///     required_fields: Vec<String>,
/// }
///
/// impl EntryValidator for RequiredFieldValidator {
///     fn validate(
///         &self,
///         key: &str,
///         data: &HashMap<String, DataValue>,
///     ) -> Result<(), Box<dyn Error + Send + Sync>> {
///         for field in &self.required_fields {
///             if !data.contains_key(field) {
///                 return Err(format!(
///                     "Entry '{}': missing required field '{}'",
///                     key, field
///                 ).into());
///             }
///         }
///         Ok(())
///     }
/// }
///
/// let validator = RequiredFieldValidator {
///     required_fields: vec!["threat_level".to_string(), "source".to_string()],
/// };
///
/// let mut builder = DatabaseBuilder::new(MatchMode::CaseSensitive)
///     .with_validator(Box::new(validator));
///
/// // This will fail validation
/// builder.add_entry("1.2.3.4", HashMap::new())?;
/// ```
pub trait EntryValidator: Send + Sync {
    /// Validate entry data before insertion
    ///
    /// # Arguments
    /// * `key` - The entry key (IP, domain, pattern, etc.)
    /// * `data` - The data map to be associated with this entry
    ///
    /// # Returns
    /// * `Ok(())` if validation passes
    /// * `Err(...)` with a descriptive error message if validation fails
    fn validate(
        &self,
        key: &str,
        data: &HashMap<String, DataValue>,
    ) -> Result<(), Box<dyn Error + Send + Sync>>;
}

/// Validation result for format-level checks
#[derive(Debug, Clone)]
pub struct FormatValidationResult {
    /// Errors, capped at 256 retained messages including a suppression sentinel.
    pub errors: Vec<String>,
    /// Warnings, capped at 256 retained messages including a suppression sentinel.
    pub warnings: Vec<String>,
    /// Validation statistics
    pub stats: FormatStats,
}

impl FormatValidationResult {
    /// Create a new empty validation result
    #[must_use]
    pub fn new() -> Self {
        Self {
            errors: Vec::new(),
            warnings: Vec::new(),
            stats: FormatStats::default(),
        }
    }

    /// Check if validation passed (no errors)
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.errors.is_empty()
    }

    /// Add an error
    pub fn error(&mut self, msg: String) {
        push_capped(
            &mut self.errors,
            msg,
            MAX_VALIDATION_ERRORS,
            ERRORS_SUPPRESSED,
        );
    }

    /// Add a warning
    pub fn warning(&mut self, msg: String) {
        push_capped(
            &mut self.warnings,
            msg,
            MAX_VALIDATION_WARNINGS,
            WARNINGS_SUPPRESSED,
        );
    }
}

impl Default for FormatValidationResult {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics from format validation
#[derive(Debug, Clone, Default)]
pub struct FormatStats {
    /// Number of mappings validated
    pub mappings_validated: usize,
    /// Number of patterns with data
    pub patterns_with_data: usize,
    /// Number of duplicate mappings found
    pub duplicate_mappings: usize,
}

/// Validate data section mapping consistency (v2+ format)
///
/// This function validates the pattern→data mapping table to ensure:
/// - All pattern IDs are valid (< pattern_count)
/// - No duplicate pattern IDs in mapping table
/// - Data offsets and sizes are within bounds
///
/// # Arguments
/// * `buffer` - Full file buffer
/// * `header` - Parsed ParaglobHeader
///
/// # Returns
/// Validation result with errors, warnings, and coverage statistics
#[must_use]
pub fn validate_data_mapping_consistency(
    buffer: &[u8],
    header: &ParaglobHeader,
) -> FormatValidationResult {
    let mut result = FormatValidationResult::new();

    let Some(mapping_offset) = usize::try_from(header.mapping_table_offset).ok() else {
        result.error("Mapping table offset is not addressable".to_string());
        return result;
    };
    let Some(mapping_count) = usize::try_from(header.mapping_count).ok() else {
        result.error("Mapping count is not addressable".to_string());
        return result;
    };
    let Some(data_offset) = usize::try_from(header.data_section_offset).ok() else {
        result.error("Data section offset is not addressable".to_string());
        return result;
    };
    let Some(data_size) = usize::try_from(header.data_section_size).ok() else {
        result.error("Data section size is not addressable".to_string());
        return result;
    };

    if mapping_count == 0 {
        // No mappings is valid (not all patterns need data)
        return result;
    }

    if mapping_offset == 0 {
        result.error("Mapping table offset is 0 but mapping_count > 0".to_string());
        return result;
    }
    if !header.has_data_section() {
        result.error("Mapping table is present without a data section".to_string());
        return result;
    }

    let mapping_entry_size = std::mem::size_of::<PatternDataMapping>();
    let Some(mapping_bytes) = mapping_count.checked_mul(mapping_entry_size) else {
        result.error("Mapping table size overflows address space".to_string());
        return result;
    };
    let Some(mapping_end) = mapping_offset.checked_add(mapping_bytes) else {
        result.error("Mapping table range overflows address space".to_string());
        return result;
    };
    if mapping_end > buffer.len() {
        result.error(format!(
            "Mapping table range [{mapping_offset}, {mapping_end}) exceeds buffer size {}",
            buffer.len()
        ));
        return result;
    }

    let Some(data_end) = data_offset.checked_add(data_size) else {
        result.error("Data section range overflows address space".to_string());
        return result;
    };
    if data_end > buffer.len() {
        result.error(format!(
            "Data section range [{data_offset}, {data_end}) exceeds buffer size {}",
            buffer.len()
        ));
        return result;
    }
    if !header.has_inline_data() {
        result.warning(
            "Data section is present without the inline-data flag; current runtime still treats it as inline"
                .to_string(),
        );
    }
    let data_section = &buffer[data_offset..data_end];
    let decoder = DataDecoder::new(data_section, 0);

    let mut patterns_with_data = HashSet::new();
    let mut duplicate_mappings = 0;
    let mut previous_pattern_id = None;

    for i in 0..mapping_count {
        let entry_offset = mapping_offset + i * mapping_entry_size;
        let entry_end = entry_offset + mapping_entry_size;

        let mapping = match PatternDataMapping::read_from_prefix(&buffer[entry_offset..entry_end]) {
            Ok((m, _)) => m,
            Err(_) => {
                result.error(format!(
                    "Failed to read PatternDataMapping at offset {entry_offset}"
                ));
                continue;
            }
        };

        // Check for duplicate pattern IDs in mapping table
        if !patterns_with_data.insert(mapping.pattern_id) {
            duplicate_mappings += 1;
        }

        if previous_pattern_id.is_some_and(|previous| mapping.pattern_id < previous) {
            result.error(format!(
                "Mapping table is not sorted: entry {i} pattern ID {} follows a larger ID",
                mapping.pattern_id
            ));
        }
        previous_pattern_id = Some(mapping.pattern_id);

        // Validate pattern ID is valid
        if mapping.pattern_id >= header.pattern_count {
            if header.pattern_count == 0 {
                result.error(format!(
                    "Mapping entry {i} references pattern ID {} but pattern_count is zero",
                    mapping.pattern_id
                ));
            } else {
                result.error(format!(
                    "Mapping entry {} references invalid pattern ID {} (max: {})",
                    i,
                    mapping.pattern_id,
                    header.pattern_count - 1
                ));
            }
            continue;
        }

        // Mapping offsets are relative to the start of the data section.
        let relative_start = usize::try_from(mapping.data_offset).unwrap_or(usize::MAX);
        let mapping_size = usize::try_from(mapping.data_size).unwrap_or(usize::MAX);
        let relative_end = relative_start.checked_add(mapping_size);
        if relative_start >= data_size {
            result.error(format!(
                "Mapping entry {i} relative data offset {relative_start} is outside data section size {data_size}"
            ));
        } else if mapping_size != 0 && relative_end.is_none_or(|end| end > data_size) {
            result.error(format!(
                "Mapping entry {i} relative data range [{relative_start}, {}) exceeds data section size {data_size}",
                relative_end.map_or_else(|| "overflow".to_string(), |end| end.to_string())
            ));
        } else if let Err(error) = decoder.decode(mapping.data_offset) {
            result.error(format!(
                "Mapping entry {i} data at relative offset {} does not decode: {error}",
                mapping.data_offset
            ));
        }

        result.stats.mappings_validated += 1;
    }

    result.stats.patterns_with_data = patterns_with_data.len();
    result.stats.duplicate_mappings = duplicate_mappings;

    if duplicate_mappings > 0 {
        result.error(format!(
            "Found {duplicate_mappings} duplicate pattern IDs in data mapping table"
        ));
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation_result_caps_retained_findings() {
        let mut result = FormatValidationResult::new();
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

    fn create_test_header(pattern_count: u32, mapping_count: u32) -> ParaglobHeader {
        let mut header = ParaglobHeader::new();
        header.pattern_count = pattern_count;
        header.mapping_count = mapping_count;
        header.mapping_table_offset = 1000; // Arbitrary offset
        header.data_section_offset = 5000;
        header.data_section_size = 1000;
        header.data_flags = 0x01; // Inline data
        header
    }

    fn encode_mapping(pattern_id: u32, data_offset: u32, data_size: u32) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&pattern_id.to_le_bytes());
        buf.extend_from_slice(&data_offset.to_le_bytes());
        buf.extend_from_slice(&data_size.to_le_bytes());
        buf
    }

    fn mark_empty_strings(buffer: &mut [u8], relative_offsets: &[usize]) {
        for &offset in relative_offsets {
            buffer[5000 + offset] = 0x40;
        }
    }

    #[test]
    fn test_validate_no_mappings() {
        let header = create_test_header(10, 0);
        let buffer = vec![0u8; 6000];

        let result = validate_data_mapping_consistency(&buffer, &header);
        assert!(result.is_valid());
        assert_eq!(result.stats.mappings_validated, 0);
    }

    #[test]
    fn test_validate_valid_mappings() {
        let header = create_test_header(10, 3);
        let mut buffer = vec![0u8; 6000];

        // Write three valid mappings at offset 1000
        let mappings = vec![
            encode_mapping(0, 100, 50),
            encode_mapping(1, 200, 50),
            encode_mapping(2, 300, 50),
        ];

        let mut offset = 1000;
        for mapping_bytes in mappings {
            buffer[offset..offset + mapping_bytes.len()].copy_from_slice(&mapping_bytes);
            offset += mapping_bytes.len();
        }
        mark_empty_strings(&mut buffer, &[100, 200, 300]);

        let result = validate_data_mapping_consistency(&buffer, &header);
        assert!(result.is_valid());
        assert_eq!(result.stats.mappings_validated, 3);
        assert_eq!(result.stats.patterns_with_data, 3);
        assert_eq!(result.stats.duplicate_mappings, 0);
    }

    #[test]
    fn test_validate_duplicate_pattern_ids() {
        let header = create_test_header(10, 3);
        let mut buffer = vec![0u8; 6000];

        // Write mappings with duplicate pattern IDs
        let mappings = vec![
            encode_mapping(0, 100, 50),
            encode_mapping(0, 200, 50), // Duplicate!
            encode_mapping(1, 300, 50),
        ];

        let mut offset = 1000;
        for mapping_bytes in mappings {
            buffer[offset..offset + mapping_bytes.len()].copy_from_slice(&mapping_bytes);
            offset += mapping_bytes.len();
        }
        mark_empty_strings(&mut buffer, &[100, 200, 300]);

        let result = validate_data_mapping_consistency(&buffer, &header);
        assert!(!result.is_valid());
        assert_eq!(result.errors.len(), 1);
        assert_eq!(result.stats.duplicate_mappings, 1);
        assert_eq!(result.stats.patterns_with_data, 2); // Only 2 unique patterns
    }

    #[test]
    fn test_validate_invalid_pattern_id() {
        let header = create_test_header(10, 2);
        let mut buffer = vec![0u8; 6000];

        // Write mappings, one with invalid pattern ID
        let mappings = vec![
            encode_mapping(5, 100, 50),
            encode_mapping(99, 200, 50), // Invalid! >= pattern_count
        ];

        let mut offset = 1000;
        for mapping_bytes in mappings {
            buffer[offset..offset + mapping_bytes.len()].copy_from_slice(&mapping_bytes);
            offset += mapping_bytes.len();
        }
        mark_empty_strings(&mut buffer, &[100, 200]);

        let result = validate_data_mapping_consistency(&buffer, &header);
        assert!(!result.is_valid());
        assert_eq!(result.errors.len(), 1);
        assert!(result.errors[0].contains("invalid pattern ID 99"));
    }

    #[test]
    fn test_validate_data_bounds() {
        let header = create_test_header(10, 2);
        let mut buffer = vec![0u8; 6000];

        // Write mappings with out-of-bounds data
        let mappings = vec![
            encode_mapping(0, 100, 50),  // Valid relative range
            encode_mapping(1, 900, 200), // Exceeds 1000-byte data section
        ];

        let mut offset = 1000;
        for mapping_bytes in mappings {
            buffer[offset..offset + mapping_bytes.len()].copy_from_slice(&mapping_bytes);
            offset += mapping_bytes.len();
        }
        mark_empty_strings(&mut buffer, &[100]);

        let result = validate_data_mapping_consistency(&buffer, &header);
        assert!(!result.is_valid());
        assert_eq!(result.errors.len(), 1);
        assert!(result.errors[0].contains("exceeds data section"));
    }

    #[test]
    fn test_validate_truncated_mapping_table() {
        let header = create_test_header(10, 3);
        let buffer = vec![0u8; 1020]; // Too small to hold all 3 mappings

        let result = validate_data_mapping_consistency(&buffer, &header);
        assert!(!result.is_valid());
        assert!(result.errors.iter().any(|e| e.contains("exceeds buffer")));
    }

    #[test]
    fn test_validate_zero_pattern_count_without_underflow() {
        let header = create_test_header(0, 1);
        let mut buffer = vec![0u8; 6000];
        let mapping = encode_mapping(0, 0, 1);
        buffer[1000..1000 + mapping.len()].copy_from_slice(&mapping);

        let result = validate_data_mapping_consistency(&buffer, &header);
        assert!(!result.is_valid());
        assert!(result
            .errors
            .iter()
            .any(|error| error.contains("pattern_count is zero")));
    }

    #[test]
    fn test_validate_rejects_unsorted_mapping_table() {
        let header = create_test_header(10, 2);
        let mut buffer = vec![0u8; 6000];
        let mappings = [encode_mapping(2, 100, 1), encode_mapping(1, 200, 1)];
        let mut offset = 1000;
        for mapping in mappings {
            buffer[offset..offset + mapping.len()].copy_from_slice(&mapping);
            offset += mapping.len();
        }
        mark_empty_strings(&mut buffer, &[100, 200]);

        let result = validate_data_mapping_consistency(&buffer, &header);
        assert!(!result.is_valid());
        assert!(result
            .errors
            .iter()
            .any(|error| error.contains("not sorted")));
    }

    #[test]
    fn test_validate_accepts_legacy_implicit_sized_mapping() {
        let header = create_test_header(1, 1);
        let mut buffer = vec![0u8; 6000];
        let mapping = encode_mapping(0, 100, 0);
        buffer[1000..1000 + mapping.len()].copy_from_slice(&mapping);
        mark_empty_strings(&mut buffer, &[100]);

        let result = validate_data_mapping_consistency(&buffer, &header);
        assert!(result.is_valid(), "{:?}", result.errors);
    }
}
