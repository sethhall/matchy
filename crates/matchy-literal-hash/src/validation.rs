use crate::{LITERAL_HASH_MAGIC, MATCHY_LITERAL_HASH_VERSION};

const HEADER_SIZE: usize = 32;

#[derive(Debug, Clone)]
pub struct LiteralHashValidationResult {
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
    pub stats: LiteralHashStats,
}

#[derive(Debug, Clone, Default)]
pub struct LiteralHashStats {
    pub entry_count: u32,
    pub table_size: u32,
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
}

#[must_use]
pub fn validate_literal_hash(buffer: &[u8], offset: usize) -> LiteralHashValidationResult {
    let mut result = LiteralHashValidationResult::new();

    const LITERAL_MARKER: &[u8] = b"MMDB_LITERAL\x00\x00\x00\x00";

    if offset >= 16 && offset - 16 <= buffer.len() {
        let marker_start = offset - 16;
        if marker_start + 16 <= buffer.len() {
            let potential_marker = &buffer[marker_start..marker_start + 16];
            if potential_marker == LITERAL_MARKER {
                result
                    .warnings
                    .push("Found MMDB_LITERAL marker before hash data".to_string());
            }
        }
    }

    if offset + 4 > buffer.len() {
        result
            .errors
            .push("Buffer too small for literal hash magic".to_string());
        return result;
    }

    let magic = &buffer[offset..offset + 4];
    if magic != LITERAL_HASH_MAGIC {
        result.errors.push(format!(
            "Invalid literal hash magic: expected {LITERAL_HASH_MAGIC:?}, got {magic:?}"
        ));
        return result;
    }

    if offset + HEADER_SIZE > buffer.len() {
        result
            .errors
            .push("Literal hash header truncated".to_string());
        return result;
    }

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
    let num_shards = u32::from_le_bytes([
        buffer[offset + 16],
        buffer[offset + 17],
        buffer[offset + 18],
        buffer[offset + 19],
    ]);
    let table_offset = u32::from_le_bytes([
        buffer[offset + 28],
        buffer[offset + 29],
        buffer[offset + 30],
        buffer[offset + 31],
    ]);

    result.stats.version = version;
    result.stats.entry_count = entry_count;
    result.stats.table_size = table_size;

    if version != MATCHY_LITERAL_HASH_VERSION {
        result.warnings.push(format!(
            "Unexpected literal hash version: {version} (expected {MATCHY_LITERAL_HASH_VERSION})"
        ));
    }

    if entry_count > 10_000_000 {
        result.warnings.push(format!(
            "Very large literal count: {entry_count} (> 10M, potential memory issue)"
        ));
    }

    if table_size < entry_count {
        result.errors.push(format!(
            "Table size {table_size} is smaller than entry count {entry_count}"
        ));
    }

    if !table_offset.is_multiple_of(8) {
        result
            .errors
            .push(format!("Table offset {table_offset} is not 8-byte aligned"));
    }

    let min_table_offset = HEADER_SIZE + (num_shards as usize + 1) * 4;
    if (table_offset as usize) < min_table_offset {
        result.errors.push(format!(
            "Table offset {table_offset} is before end of shard table (minimum {min_table_offset})"
        ));
    }

    let table_end = table_offset as usize + table_size as usize * 16;
    if offset + table_end > buffer.len() {
        result.errors.push(format!(
            "Hash table extends beyond buffer (offset {table_offset} + {} entries * 16 bytes = {table_end}, buffer len {})",
            table_size,
            buffer.len() - offset
        ));
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

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
    #[allow(clippy::cast_possible_truncation)]
    fn test_validate_literal_hash_valid() {
        let num_shards: u32 = 16;
        let shard_table_size = (num_shards as usize + 1) * 4;
        let table_offset: u32 = ((HEADER_SIZE + shard_table_size + 7) & !7) as u32;
        let table_size: u32 = 128;
        let table_bytes = table_size as usize * 16;
        let total_size = table_offset as usize + table_bytes;

        let mut buffer = vec![0u8; total_size];
        buffer[0..4].copy_from_slice(b"LHSH");
        buffer[4..8].copy_from_slice(&3u32.to_le_bytes());
        buffer[8..12].copy_from_slice(&100u32.to_le_bytes());
        buffer[12..16].copy_from_slice(&table_size.to_le_bytes());
        buffer[16..20].copy_from_slice(&num_shards.to_le_bytes());
        buffer[28..32].copy_from_slice(&table_offset.to_le_bytes());

        let result = validate_literal_hash(&buffer, 0);
        assert!(result.is_valid(), "errors: {:?}", result.errors);
        assert_eq!(result.stats.version, 3);
        assert_eq!(result.stats.entry_count, 100);
        assert_eq!(result.stats.table_size, 128);
    }

    #[test]
    fn test_validate_literal_hash_table_too_small() {
        let mut buffer = vec![0u8; 64];
        buffer[0..4].copy_from_slice(b"LHSH");
        buffer[4..8].copy_from_slice(&3u32.to_le_bytes());
        buffer[8..12].copy_from_slice(&100u32.to_le_bytes());
        buffer[12..16].copy_from_slice(&50u32.to_le_bytes());

        let result = validate_literal_hash(&buffer, 0);
        assert!(!result.is_valid());
        assert!(result.errors.iter().any(|e| e.contains("smaller")));
    }

    #[test]
    fn test_validate_literal_hash_misaligned_table_offset() {
        let mut buffer = vec![0u8; 256];
        buffer[0..4].copy_from_slice(b"LHSH");
        buffer[4..8].copy_from_slice(&3u32.to_le_bytes());
        buffer[8..12].copy_from_slice(&1u32.to_le_bytes());
        buffer[12..16].copy_from_slice(&16u32.to_le_bytes());
        buffer[16..20].copy_from_slice(&1u32.to_le_bytes());
        buffer[28..32].copy_from_slice(&41u32.to_le_bytes());

        let result = validate_literal_hash(&buffer, 0);
        assert!(!result.is_valid());
        assert!(result
            .errors
            .iter()
            .any(|e| e.contains("not 8-byte aligned")));
    }

    #[test]
    fn test_validate_literal_hash_table_offset_too_small() {
        let mut buffer = vec![0u8; 256];
        buffer[0..4].copy_from_slice(b"LHSH");
        buffer[4..8].copy_from_slice(&3u32.to_le_bytes());
        buffer[8..12].copy_from_slice(&1u32.to_le_bytes());
        buffer[12..16].copy_from_slice(&16u32.to_le_bytes());
        buffer[16..20].copy_from_slice(&16u32.to_le_bytes());
        buffer[28..32].copy_from_slice(&32u32.to_le_bytes());

        let result = validate_literal_hash(&buffer, 0);
        assert!(!result.is_valid());
        assert!(result
            .errors
            .iter()
            .any(|e| e.contains("before end of shard table")));
    }
}
