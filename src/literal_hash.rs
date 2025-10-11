//! Literal String Hash Table for O(1) Lookups
//!
//! This module provides a memory-mapped hash table optimized for exact string matching.
//! Unlike Aho-Corasick which is designed for pattern matching, this provides O(1) lookups
//! for literal strings using FxHash with linear probing.
//!
//! # Format
//!
//! The hash table is stored in a memory-mappable binary format:
//!
//! ```text
//! [Header]
//!   magic: [u8; 4]           // "LHSH"
//!   version: u32              // 1
//!   entry_count: u32          // Number of literal patterns
//!   table_size: u32           // Hash table size (entry_count * 1.25)
//!   strings_offset: u32       // Offset to string pool
//!   strings_size: u32         // Size of string pool
//!
//! [Hash Table]
//!   entries: [HashEntry; table_size]
//!     hash: u64               // Full hash for verification
//!     string_offset: u32      // Offset into string pool (or 0xFFFFFFFF if empty)
//!     pattern_id: u32         // Pattern ID for data lookup
//!
//! [String Pool]
//!   Strings stored as: [length: u16][bytes...][null terminator]
//!
//! [Pattern Mappings]
//!   count: u32
//!   mappings: [(pattern_id: u32, data_offset: u32); count]
//! ```

use crate::error::ParaglobError;
use rustc_hash::FxHasher;
use std::hash::{Hash, Hasher};
use std::mem;

/// Magic bytes for literal hash section
pub const LITERAL_HASH_MAGIC: &[u8; 4] = b"LHSH";

/// Current version of the literal hash format
pub const LITERAL_HASH_VERSION: u32 = 1;

/// Empty slot marker
const EMPTY_SLOT: u32 = 0xFFFFFFFF;

/// Hash table header
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct LiteralHashHeader {
    /// Magic bytes "LHSH"
    pub magic: [u8; 4],
    /// Format version
    pub version: u32,
    /// Number of literal patterns
    pub entry_count: u32,
    /// Hash table size
    pub table_size: u32,
    /// Offset to string pool
    pub strings_offset: u32,
    /// Size of string pool
    pub strings_size: u32,
}

/// Single hash table entry
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct HashEntry {
    /// Full hash for verification
    pub hash: u64,
    /// Offset into string pool
    pub string_offset: u32,
    /// Pattern ID for data lookup
    pub pattern_id: u32,
}

impl HashEntry {
    fn empty() -> Self {
        Self {
            hash: 0,
            string_offset: EMPTY_SLOT,
            pattern_id: 0,
        }
    }

    fn is_empty(&self) -> bool {
        self.string_offset == EMPTY_SLOT
    }
}

/// Pattern ID to data offset mapping
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct PatternMapping {
    /// Pattern identifier
    pub pattern_id: u32,
    /// Offset to data section
    pub data_offset: u32,
}

/// Builder for literal hash table
pub struct LiteralHashBuilder {
    patterns: Vec<(String, u32)>, // (pattern, pattern_id)
}

impl LiteralHashBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            patterns: Vec::new(),
        }
    }

    /// Add a literal pattern
    pub fn add_pattern(&mut self, pattern: String, pattern_id: u32) {
        self.patterns.push((pattern, pattern_id));
    }

    /// Build the hash table
    ///
    /// Returns (hash_table_bytes, pattern_id_to_data_offset_map)
    pub fn build(
        self,
        pattern_data_offsets: &[(u32, u32)], // (pattern_id, data_offset)
    ) -> Result<Vec<u8>, ParaglobError> {
        if self.patterns.is_empty() {
            return Ok(Vec::new());
        }

        // Calculate table size (125% of entries for ~0.8 load factor)
        let table_size = (self.patterns.len() * 5).div_ceil(4).max(16);

        // Build string pool
        let mut string_pool = Vec::new();
        let mut string_offsets = Vec::new();

        for (pattern, _) in &self.patterns {
            string_offsets.push(string_pool.len());
            // Store as: [length: u16][bytes][null]
            let len = pattern.len() as u16;
            string_pool.extend_from_slice(&len.to_le_bytes());
            string_pool.extend_from_slice(pattern.as_bytes());
            string_pool.push(0); // null terminator
        }

        // Build hash table with linear probing
        let mut table = vec![HashEntry::empty(); table_size];

        for (idx, (pattern, pattern_id)) in self.patterns.iter().enumerate() {
            let hash = compute_hash(pattern);
            let mut slot = (hash as usize) % table_size;

            // Linear probing to find empty slot
            loop {
                if table[slot].is_empty() {
                    table[slot] = HashEntry {
                        hash,
                        string_offset: string_offsets[idx] as u32,
                        pattern_id: *pattern_id,
                    };
                    break;
                }
                slot = (slot + 1) % table_size;
            }
        }

        // Calculate offsets
        let header_size = mem::size_of::<LiteralHashHeader>();
        let table_bytes_size = table_size * mem::size_of::<HashEntry>();
        let strings_offset = header_size + table_bytes_size;
        let strings_size = string_pool.len();

        // Serialize everything
        let mut buffer = Vec::new();

        // Header
        let header = LiteralHashHeader {
            magic: *LITERAL_HASH_MAGIC,
            version: LITERAL_HASH_VERSION,
            entry_count: self.patterns.len() as u32,
            table_size: table_size as u32,
            strings_offset: strings_offset as u32,
            strings_size: strings_size as u32,
        };

        buffer.extend_from_slice(&header.magic);
        buffer.extend_from_slice(&header.version.to_le_bytes());
        buffer.extend_from_slice(&header.entry_count.to_le_bytes());
        buffer.extend_from_slice(&header.table_size.to_le_bytes());
        buffer.extend_from_slice(&header.strings_offset.to_le_bytes());
        buffer.extend_from_slice(&header.strings_size.to_le_bytes());

        // Hash table entries
        for entry in &table {
            buffer.extend_from_slice(&entry.hash.to_le_bytes());
            buffer.extend_from_slice(&entry.string_offset.to_le_bytes());
            buffer.extend_from_slice(&entry.pattern_id.to_le_bytes());
        }

        // String pool
        buffer.extend_from_slice(&string_pool);

        // Pattern mappings
        buffer.extend_from_slice(&(pattern_data_offsets.len() as u32).to_le_bytes());
        for (pattern_id, data_offset) in pattern_data_offsets {
            buffer.extend_from_slice(&pattern_id.to_le_bytes());
            buffer.extend_from_slice(&data_offset.to_le_bytes());
        }

        Ok(buffer)
    }

    /// Get number of patterns
    pub fn pattern_count(&self) -> usize {
        self.patterns.len()
    }
}

impl Default for LiteralHashBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Memory-mapped literal hash table for lookups
pub struct LiteralHash<'a> {
    buffer: &'a [u8],
    header: LiteralHashHeader,
    table_start: usize,
    strings_start: usize,
    mappings_start: usize,
}

impl<'a> LiteralHash<'a> {
    /// Load from memory-mapped buffer
    pub fn from_buffer(buffer: &'a [u8]) -> Result<Self, ParaglobError> {
        if buffer.len() < mem::size_of::<LiteralHashHeader>() {
            return Err(ParaglobError::InvalidPattern(
                "Buffer too small for literal hash header".to_string(),
            ));
        }

        // Parse header
        let magic = &buffer[0..4];
        if magic != LITERAL_HASH_MAGIC {
            return Err(ParaglobError::InvalidPattern(format!(
                "Invalid literal hash magic: expected {:?}, got {:?}",
                LITERAL_HASH_MAGIC, magic
            )));
        }

        let version = u32::from_le_bytes(buffer[4..8].try_into().unwrap());
        if version != LITERAL_HASH_VERSION {
            return Err(ParaglobError::InvalidPattern(format!(
                "Unsupported literal hash version: {}",
                version
            )));
        }

        let entry_count = u32::from_le_bytes(buffer[8..12].try_into().unwrap());
        let table_size = u32::from_le_bytes(buffer[12..16].try_into().unwrap());
        let strings_offset = u32::from_le_bytes(buffer[16..20].try_into().unwrap());
        let strings_size = u32::from_le_bytes(buffer[20..24].try_into().unwrap());

        let header = LiteralHashHeader {
            magic: *LITERAL_HASH_MAGIC,
            version,
            entry_count,
            table_size,
            strings_offset,
            strings_size,
        };

        let table_start = mem::size_of::<LiteralHashHeader>();
        let strings_start = strings_offset as usize;
        let mappings_start = strings_start + strings_size as usize;

        Ok(Self {
            buffer,
            header,
            table_start,
            strings_start,
            mappings_start,
        })
    }

    /// Lookup a literal string
    ///
    /// Returns the pattern ID if found, None otherwise
    pub fn lookup(&self, query: &str) -> Option<u32> {
        let hash = compute_hash(query);
        let table_size = self.header.table_size as usize;
        let mut slot = (hash as usize) % table_size;

        let entry_size = mem::size_of::<HashEntry>();

        // Linear probing search
        for _ in 0..table_size {
            let entry_offset = self.table_start + slot * entry_size;
            if entry_offset + entry_size > self.buffer.len() {
                return None;
            }

            let entry_bytes = &self.buffer[entry_offset..entry_offset + entry_size];
            let entry_hash = u64::from_le_bytes(entry_bytes[0..8].try_into().unwrap());
            let string_offset = u32::from_le_bytes(entry_bytes[8..12].try_into().unwrap());
            let pattern_id = u32::from_le_bytes(entry_bytes[12..16].try_into().unwrap());

            // Empty slot - not found
            if string_offset == EMPTY_SLOT {
                return None;
            }

            // Hash matches - verify string
            if entry_hash == hash {
                if let Some(stored_string) = self.read_string(string_offset as usize) {
                    if stored_string == query {
                        return Some(pattern_id);
                    }
                }
            }

            slot = (slot + 1) % table_size;
        }

        None
    }

    /// Read a string from the string pool
    fn read_string(&self, offset: usize) -> Option<&str> {
        let abs_offset = self.strings_start + offset;
        if abs_offset + 2 > self.buffer.len() {
            return None;
        }

        let len = u16::from_le_bytes(self.buffer[abs_offset..abs_offset + 2].try_into().ok()?);
        let str_start = abs_offset + 2;
        let str_end = str_start + len as usize;

        if str_end > self.buffer.len() {
            return None;
        }

        std::str::from_utf8(&self.buffer[str_start..str_end]).ok()
    }

    /// Get data offset for a pattern ID
    pub fn get_data_offset(&self, pattern_id: u32) -> Option<u32> {
        if self.mappings_start + 4 > self.buffer.len() {
            return None;
        }

        let count = u32::from_le_bytes(
            self.buffer[self.mappings_start..self.mappings_start + 4]
                .try_into()
                .ok()?,
        );

        let mappings_data_start = self.mappings_start + 4;
        let mapping_size = 8; // pattern_id: u32 + data_offset: u32

        for i in 0..count {
            let offset = mappings_data_start + (i as usize) * mapping_size;
            if offset + mapping_size > self.buffer.len() {
                return None;
            }

            let pid = u32::from_le_bytes(self.buffer[offset..offset + 4].try_into().ok()?);
            if pid == pattern_id {
                let data_offset =
                    u32::from_le_bytes(self.buffer[offset + 4..offset + 8].try_into().ok()?);
                return Some(data_offset);
            }
        }

        None
    }

    /// Get statistics
    pub fn entry_count(&self) -> u32 {
        self.header.entry_count
    }

    /// Get table size
    pub fn table_size(&self) -> u32 {
        self.header.table_size
    }
}

/// Compute FxHash of a string
fn compute_hash(s: &str) -> u64 {
    let mut hasher = FxHasher::default();
    s.hash(&mut hasher);
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_hash_table() {
        let mut builder = LiteralHashBuilder::new();
        builder.add_pattern("test1".to_string(), 0);
        builder.add_pattern("test2".to_string(), 1);
        builder.add_pattern("test3".to_string(), 2);

        let pattern_data = vec![(0, 100), (1, 200), (2, 300)];
        let bytes = builder.build(&pattern_data).unwrap();

        let hash = LiteralHash::from_buffer(&bytes).unwrap();
        assert_eq!(hash.lookup("test1"), Some(0));
        assert_eq!(hash.lookup("test2"), Some(1));
        assert_eq!(hash.lookup("test3"), Some(2));
        assert_eq!(hash.lookup("test4"), None);

        assert_eq!(hash.get_data_offset(0), Some(100));
        assert_eq!(hash.get_data_offset(1), Some(200));
        assert_eq!(hash.get_data_offset(2), Some(300));
    }

    #[test]
    fn test_hash_collisions() {
        let mut builder = LiteralHashBuilder::new();
        // Add many patterns to force collisions
        for i in 0..100 {
            builder.add_pattern(format!("pattern_{}", i), i);
        }

        let pattern_data: Vec<_> = (0..100).map(|i| (i, i * 10)).collect();
        let bytes = builder.build(&pattern_data).unwrap();

        let hash = LiteralHash::from_buffer(&bytes).unwrap();
        for i in 0..100 {
            assert_eq!(hash.lookup(&format!("pattern_{}", i)), Some(i));
        }
    }
}
