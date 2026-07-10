use crate::{LiteralHash, LITERAL_HASH_MAGIC, MATCHY_LITERAL_HASH_VERSION};
use matchy_match_mode::MatchMode;

const HEADER_SIZE: usize = 32;
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

#[derive(Debug, Clone)]
pub struct LiteralHashValidationResult {
    /// Errors, capped at 256 retained messages including a suppression sentinel.
    pub errors: Vec<String>,
    /// Warnings, capped at 256 retained messages including a suppression sentinel.
    pub warnings: Vec<String>,
    /// Statistics gathered during validation.
    pub stats: LiteralHashStats,
}

#[derive(Debug, Clone, Default)]
pub struct LiteralHashStats {
    /// Number of literal entries declared by the header.
    pub entry_count: u32,
    /// Number of hash table slots declared by the header.
    pub table_size: u32,
    /// Literal hash format version.
    pub version: u32,
}

impl LiteralHashValidationResult {
    fn new() -> Self {
        Self {
            errors: Vec::new(),
            warnings: Vec::new(),
            stats: LiteralHashStats::default(),
        }
    }

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

#[must_use]
pub fn validate_literal_hash(buffer: &[u8], offset: usize) -> LiteralHashValidationResult {
    let mut result = LiteralHashValidationResult::new();

    let Some(literal_data) = buffer.get(offset..) else {
        result.error("Buffer too small for literal hash magic");
        return result;
    };

    let Some(magic) = literal_data.get(..4) else {
        result.error("Buffer too small for literal hash magic");
        return result;
    };
    if magic != LITERAL_HASH_MAGIC {
        result.error(format!(
            "Invalid literal hash magic: expected {LITERAL_HASH_MAGIC:?}, got {magic:?}"
        ));
        return result;
    }

    let Some(header) = literal_data.get(..HEADER_SIZE) else {
        result.error("Literal hash header truncated");
        return result;
    };

    let version = u32::from_le_bytes(header[4..8].try_into().expect("fixed header field"));
    let entry_count = u32::from_le_bytes(header[8..12].try_into().expect("fixed header field"));
    let table_size = u32::from_le_bytes(header[12..16].try_into().expect("fixed header field"));

    result.stats.version = version;
    result.stats.entry_count = entry_count;
    result.stats.table_size = table_size;

    if version != MATCHY_LITERAL_HASH_VERSION {
        result.error(format!(
            "Unexpected literal hash version: {version} (expected {MATCHY_LITERAL_HASH_VERSION})"
        ));
        return result;
    }

    if entry_count > 10_000_000 {
        result.warning(format!(
            "Very large literal count: {entry_count} (> 10M, potential memory issue)"
        ));
    }

    if let Err(error) = LiteralHash::from_buffer(literal_data, MatchMode::CaseSensitive) {
        result.error(error.to_string());
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::LiteralHashBuilder;

    #[test]
    fn validation_result_caps_retained_findings() {
        let mut result = LiteralHashValidationResult::new();
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

    fn valid_literal_hash() -> Vec<u8> {
        let mut builder = LiteralHashBuilder::new(MatchMode::CaseSensitive);
        builder.add_pattern("example.test", 0);
        builder.build(&[(0, 7)]).unwrap()
    }

    #[test]
    fn test_validate_literal_hash_truncated() {
        let buffer = vec![0u8; 10];
        let result = validate_literal_hash(&buffer, 0);
        assert!(!result.is_valid());
        assert!(!result.errors.is_empty());
    }

    #[test]
    fn test_validate_literal_hash_bad_magic() {
        let mut buffer = vec![0u8; 64];
        buffer[0..4].copy_from_slice(b"XXXX");
        let result = validate_literal_hash(&buffer, 0);
        assert!(!result.is_valid());
        assert!(result.errors.iter().any(|e| e.contains("magic")));
    }

    #[test]
    fn test_validate_literal_hash_valid() {
        let buffer = valid_literal_hash();

        let result = validate_literal_hash(&buffer, 0);
        assert!(result.is_valid(), "errors: {:?}", result.errors);
        assert_eq!(result.stats.version, MATCHY_LITERAL_HASH_VERSION);
        assert_eq!(result.stats.entry_count, 1);
        assert!(result.stats.table_size >= 1);
    }

    #[test]
    fn test_validate_literal_hash_table_too_small() {
        let mut buffer = valid_literal_hash();
        let table_size = u32::from_le_bytes(buffer[12..16].try_into().unwrap());
        buffer[8..12].copy_from_slice(&(table_size + 1).to_le_bytes());

        let result = validate_literal_hash(&buffer, 0);
        assert!(!result.is_valid());
        assert!(result
            .errors
            .iter()
            .any(|e| e.contains("exceeds table_size")));
    }

    #[test]
    fn test_validate_literal_hash_misaligned_table_offset() {
        let mut buffer = valid_literal_hash();
        let table_offset = u32::from_le_bytes(buffer[28..32].try_into().unwrap());
        buffer[28..32].copy_from_slice(&(table_offset + 1).to_le_bytes());

        let result = validate_literal_hash(&buffer, 0);
        assert!(!result.is_valid());
        assert!(result
            .errors
            .iter()
            .any(|e| e.contains("not 8-byte aligned")));
    }

    #[test]
    fn test_validate_literal_hash_table_offset_too_small() {
        let mut buffer = valid_literal_hash();
        buffer[28..32].copy_from_slice(&32u32.to_le_bytes());

        let result = validate_literal_hash(&buffer, 0);
        assert!(!result.is_valid());
        assert!(result
            .errors
            .iter()
            .any(|e| e.contains("overlaps shard offset table")));
    }
}
