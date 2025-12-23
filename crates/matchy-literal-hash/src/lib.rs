//! Literal String Hash Table for O(1) Lookups
//!
//! This module provides a memory-mapped hash table optimized for exact string matching.
//! Unlike Aho-Corasick which is designed for pattern matching, this provides O(1) lookups
//! for literal strings using 96-bit truncated XXH3 hashes with sharded parallel construction.
//!
//! # Format (Version 2)
//!
//! The hash table is stored in a memory-mappable binary format:
//!
//! ```text
//! [Header - 32 bytes]
//!   magic: [u8; 4]           // "LHSH"
//!   version: u32              // 2
//!   entry_count: u32          // Number of literal patterns
//!   table_size: u32           // Hash table size (entry_count * 1.25)
//!   reserved1: u32            // Reserved (was strings_offset, now 0)
//!   reserved2: u32            // Reserved (was strings_size, now 0)
//!   num_shards: u32           // Number of shards (power of 2)
//!   shard_bits: u32           // Bits used for sharding (log2(num_shards))
//!
//! [Shard Offset Table]
//!   offsets: [u32; num_shards + 1]
//!
//! [Hash Table]
//!   entries: [HashEntry; table_size]
//!     hash: [u8; 12]          // 96-bit truncated XXH3_128
//!     pattern_id: u32         // Pattern ID for data lookup
//!
//! [Pattern Mappings]
//!   count: u32
//!   mappings: [(pattern_id: u32, data_offset: u32); count]
//! ```
//!
//! Note: Version 2 removes the string pool entirely. String verification is replaced
//! by 96-bit hash comparison, which provides negligible collision probability
//! (false positive rate < 10^-24 per query for 100K entries).
//!
use matchy_match_mode::MatchMode;
use rayon::prelude::*;
use rustc_hash::FxHashMap;
use std::mem;
use xxhash_rust::xxh3::xxh3_128;

// Validation module for literal hash structures
pub mod validation;

// Re-export validation types for convenience
pub use validation::{validate_literal_hash, LiteralHashStats, LiteralHashValidationResult};

/// Errors that can occur in literal hash operations
#[derive(Debug, Clone)]
pub enum LiteralHashError {
    /// Invalid format or corrupted data
    InvalidFormat(String),
}

impl std::fmt::Display for LiteralHashError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidFormat(msg) => {
                write!(f, "Invalid literal hash format: {msg}")
            }
        }
    }
}

impl std::error::Error for LiteralHashError {}

/// Magic bytes for literal hash section
pub const LITERAL_HASH_MAGIC: &[u8; 4] = b"LHSH";

/// Current version of the literal hash format
pub const MATCHY_LITERAL_HASH_VERSION: u32 = 2;

/// Empty slot marker - all 0xFF bytes indicate an empty hash entry
const EMPTY_HASH: [u8; 12] = [0xFF; 12];

/// Hash table header (32 bytes)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct LiteralHashHeader {
    /// Magic bytes "LHSH"
    pub magic: [u8; 4],
    /// Format version (2 for 96-bit hash format)
    pub version: u32,
    /// Number of literal patterns
    pub entry_count: u32,
    /// Hash table size
    pub table_size: u32,
    /// Reserved (was strings_offset in v1)
    pub reserved1: u32,
    /// Reserved (was strings_size in v1)
    pub reserved2: u32,
    /// Number of shards (power of 2)
    pub num_shards: u32,
    /// Bits used for sharding (log2(num_shards))
    pub shard_bits: u32,
}

/// Single hash table entry (16 bytes)
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HashEntry {
    /// 96-bit truncated XXH3_128 hash
    pub hash: [u8; 12],
    /// Pattern ID for data lookup
    pub pattern_id: u32,
}

impl HashEntry {
    fn empty() -> Self {
        Self {
            hash: EMPTY_HASH,
            pattern_id: 0,
        }
    }

    fn is_empty(&self) -> bool {
        self.hash == EMPTY_HASH
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

/// Single shard of the hash table
struct Shard {
    table: Vec<HashEntry>,
    shard_id: usize,
}

/// Builder for literal hash table
pub struct LiteralHashBuilder {
    patterns: Vec<([u8; 12], u32)>, // (hash, pattern_id)
    mode: MatchMode,
}

impl LiteralHashBuilder {
    /// Create a new builder
    #[must_use]
    pub fn new(mode: MatchMode) -> Self {
        Self {
            patterns: Vec::new(),
            mode,
        }
    }

    /// Add a literal pattern
    pub fn add_pattern(&mut self, pattern: &str, pattern_id: u32) {
        let normalized = match self.mode {
            MatchMode::CaseSensitive => pattern.to_string(),
            MatchMode::CaseInsensitive => pattern.to_lowercase(),
        };
        let hash = compute_hash(&normalized);
        self.patterns.push((hash, pattern_id));
    }

    /// Build the hash table with parallel sharding
    pub fn build(self, pattern_data_offsets: &[(u32, u32)]) -> Result<Vec<u8>, LiteralHashError> {
        if self.patterns.is_empty() {
            return Ok(Vec::new());
        }

        let shard_bits = if self.patterns.len() < 10_000 {
            4
        } else if self.patterns.len() < 100_000 {
            5
        } else {
            6
        };
        let num_shards = 1 << shard_bits;

        let mut shard_buckets: Vec<Vec<([u8; 12], u32)>> =
            (0..num_shards).map(|_| Vec::new()).collect();

        for (hash, pattern_id) in self.patterns {
            let shard_id = hash_to_shard(&hash, num_shards);
            shard_buckets[shard_id].push((hash, pattern_id));
        }

        let parallelism = std::thread::available_parallelism()
            .map(std::num::NonZero::get)
            .unwrap_or(8);
        let batch_size = parallelism.min(num_shards).max(1);
        let mut shards = Vec::with_capacity(num_shards);

        for chunk_start in (0..num_shards).step_by(batch_size) {
            let chunk_end = (chunk_start + batch_size).min(num_shards);

            let mut chunk: Vec<Shard> = shard_buckets[chunk_start..chunk_end]
                .par_iter_mut()
                .enumerate()
                .map(|(i, entries)| {
                    let shard_id = chunk_start + i;
                    let entries_vec = std::mem::take(entries);
                    build_shard(shard_id, &entries_vec)
                })
                .collect();

            shards.append(&mut chunk);
        }

        let table_size: usize = shards.iter().map(|s| s.table.len()).sum();
        let mut final_table = Vec::with_capacity(table_size);

        let mut shard_offsets = vec![0u32; num_shards + 1];
        let mut table_offset = 0u32;

        for shard in &shards {
            shard_offsets[shard.shard_id] = table_offset;
            table_offset += u32::try_from(shard.table.len()).map_err(|_| {
                LiteralHashError::InvalidFormat("Shard table size exceeds u32::MAX".into())
            })?;
        }
        shard_offsets[num_shards] = table_offset;

        for shard in shards {
            final_table.extend(shard.table);
        }

        let header_size = 32;
        let shard_table_size = (num_shards + 1) * 4;
        let table_bytes_size = table_size * mem::size_of::<HashEntry>();

        let total_size = header_size
            + shard_table_size
            + table_bytes_size
            + 4
            + (pattern_data_offsets.len() * 8);
        let mut buffer = Vec::with_capacity(total_size);

        let entry_count = final_table.iter().filter(|e| !e.is_empty()).count();
        let header = LiteralHashHeader {
            magic: *LITERAL_HASH_MAGIC,
            version: MATCHY_LITERAL_HASH_VERSION,
            entry_count: u32::try_from(entry_count).map_err(|_| {
                LiteralHashError::InvalidFormat("Entry count exceeds u32::MAX".into())
            })?,
            table_size: u32::try_from(table_size).map_err(|_| {
                LiteralHashError::InvalidFormat("Table size exceeds u32::MAX".into())
            })?,
            reserved1: 0,
            reserved2: 0,
            num_shards: u32::try_from(num_shards).map_err(|_| {
                LiteralHashError::InvalidFormat("Shard count exceeds u32::MAX".into())
            })?,
            shard_bits,
        };

        buffer.extend_from_slice(&header.magic);
        buffer.extend_from_slice(&header.version.to_le_bytes());
        buffer.extend_from_slice(&header.entry_count.to_le_bytes());
        buffer.extend_from_slice(&header.table_size.to_le_bytes());
        buffer.extend_from_slice(&header.reserved1.to_le_bytes());
        buffer.extend_from_slice(&header.reserved2.to_le_bytes());
        buffer.extend_from_slice(&header.num_shards.to_le_bytes());
        buffer.extend_from_slice(&header.shard_bits.to_le_bytes());

        for offset in &shard_offsets {
            buffer.extend_from_slice(&offset.to_le_bytes());
        }

        buffer.reserve(table_bytes_size);
        for entry in final_table.iter() {
            buffer.extend_from_slice(&entry.hash);
            buffer.extend_from_slice(&entry.pattern_id.to_le_bytes());
        }

        let pattern_count = u32::try_from(pattern_data_offsets.len()).map_err(|_| {
            LiteralHashError::InvalidFormat("Pattern count exceeds u32::MAX".into())
        })?;
        buffer.extend_from_slice(&pattern_count.to_le_bytes());
        for (pattern_id, data_offset) in pattern_data_offsets.iter() {
            buffer.extend_from_slice(&pattern_id.to_le_bytes());
            buffer.extend_from_slice(&data_offset.to_le_bytes());
        }

        Ok(buffer)
    }

    /// Get number of patterns
    #[must_use]
    pub fn pattern_count(&self) -> usize {
        self.patterns.len()
    }
}

impl Default for LiteralHashBuilder {
    fn default() -> Self {
        Self::new(MatchMode::CaseSensitive)
    }
}

/// Memory-mapped literal hash table for lookups
#[derive(Clone)]
pub struct LiteralHash<'a> {
    buffer: &'a [u8],
    header: LiteralHashHeader,
    table_start: usize,
    mappings_start: usize,
    shard_offsets: Vec<u32>,
    mode: MatchMode,
}

impl<'a> LiteralHash<'a> {
    /// Load from memory-mapped buffer
    pub fn from_buffer(buffer: &'a [u8], mode: MatchMode) -> Result<Self, LiteralHashError> {
        const HEADER_SIZE: usize = 32;
        if buffer.len() < HEADER_SIZE {
            return Err(LiteralHashError::InvalidFormat(
                "Buffer too small for literal hash header".to_string(),
            ));
        }

        let magic = &buffer[0..4];
        if magic != LITERAL_HASH_MAGIC {
            return Err(LiteralHashError::InvalidFormat(format!(
                "Invalid literal hash magic: expected {LITERAL_HASH_MAGIC:?}, got {magic:?}"
            )));
        }

        let version = u32::from_le_bytes(buffer[4..8].try_into().unwrap());
        if version != MATCHY_LITERAL_HASH_VERSION {
            return Err(LiteralHashError::InvalidFormat(format!(
                "Unsupported literal hash version: {version} (expected {MATCHY_LITERAL_HASH_VERSION})"
            )));
        }

        let entry_count = u32::from_le_bytes(buffer[8..12].try_into().unwrap());
        let table_size = u32::from_le_bytes(buffer[12..16].try_into().unwrap());
        let reserved1 = u32::from_le_bytes(buffer[16..20].try_into().unwrap());
        let reserved2 = u32::from_le_bytes(buffer[20..24].try_into().unwrap());
        let num_shards = u32::from_le_bytes(buffer[24..28].try_into().unwrap());
        let shard_bits = u32::from_le_bytes(buffer[28..32].try_into().unwrap());

        let header = LiteralHashHeader {
            magic: *LITERAL_HASH_MAGIC,
            version,
            entry_count,
            table_size,
            reserved1,
            reserved2,
            num_shards,
            shard_bits,
        };

        let header_size = 32;
        let shard_table_start = header_size;
        let shard_table_size = (num_shards as usize + 1) * 4;
        let mut shard_offsets = Vec::with_capacity(num_shards as usize + 1);

        for i in 0..=num_shards as usize {
            let offset_pos = shard_table_start + i * 4;
            if offset_pos + 4 > buffer.len() {
                return Err(LiteralHashError::InvalidFormat(
                    "Shard offset table truncated".to_string(),
                ));
            }
            let offset = u32::from_le_bytes(buffer[offset_pos..offset_pos + 4].try_into().unwrap());
            shard_offsets.push(offset);
        }

        let table_start = shard_table_start + shard_table_size;
        let table_bytes = table_size as usize * mem::size_of::<HashEntry>();
        let mappings_start = table_start + table_bytes;

        Ok(Self {
            buffer,
            header,
            table_start,
            mappings_start,
            shard_offsets,
            mode,
        })
    }

    /// Get the match mode of this literal hash table
    #[must_use]
    pub fn mode(&self) -> MatchMode {
        self.mode
    }

    /// Lookup a literal string using sharded table
    #[must_use]
    pub fn lookup(&self, query: &str) -> Option<u32> {
        let normalized_query = match self.mode {
            MatchMode::CaseSensitive => query.to_string(),
            MatchMode::CaseInsensitive => query.to_lowercase(),
        };
        let query_hash = compute_hash(&normalized_query);

        let num_shards = self.header.num_shards as usize;
        let shard_id = hash_to_shard(&query_hash, num_shards);

        let shard_start = self.shard_offsets[shard_id] as usize;
        let shard_end = self.shard_offsets[shard_id + 1] as usize;
        let shard_capacity = shard_end - shard_start;

        if shard_capacity == 0 {
            return None;
        }

        let shard_mask = shard_capacity - 1;
        let base_slot = hash_to_slot(&query_hash, shard_mask);
        let mut slot = shard_start + base_slot;
        let entry_size = mem::size_of::<HashEntry>();

        for _ in 0..shard_capacity {
            let entry_offset = self.table_start + slot * entry_size;
            if entry_offset + entry_size > self.buffer.len() {
                return None;
            }

            let entry_bytes = &self.buffer[entry_offset..entry_offset + entry_size];
            let entry_hash: [u8; 12] = entry_bytes[0..12].try_into().unwrap();
            let pattern_id = u32::from_le_bytes(entry_bytes[12..16].try_into().unwrap());

            if entry_hash == EMPTY_HASH {
                return None;
            }

            if entry_hash == query_hash {
                return Some(pattern_id);
            }

            slot = shard_start + ((slot + 1 - shard_start) & shard_mask);
        }

        None
    }

    /// Get data offset for a pattern ID
    #[must_use]
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
    #[must_use]
    pub fn entry_count(&self) -> u32 {
        self.header.entry_count
    }

    /// Get table size
    #[must_use]
    pub fn table_size(&self) -> u32 {
        self.header.table_size
    }
}

/// Build a single shard from its entries
fn build_shard(shard_id: usize, entries: &[([u8; 12], u32)]) -> Shard {
    if entries.is_empty() {
        return Shard {
            shard_id,
            table: Vec::new(),
        };
    }

    let needed = (entries.len() * 10).div_ceil(6);
    let capacity = needed.next_power_of_two().max(16);
    let mask = capacity - 1;

    let mut map: FxHashMap<[u8; 12], u32> = FxHashMap::default();
    for (hash, pattern_id) in entries {
        map.insert(*hash, *pattern_id);
    }

    let mut table = vec![HashEntry::empty(); capacity];
    for (hash, pattern_id) in map.into_iter() {
        let mut pos = hash_to_slot(&hash, mask);

        while !table[pos].is_empty() {
            pos = (pos + 1) & mask;
        }

        table[pos] = HashEntry { hash, pattern_id };
    }

    Shard { table, shard_id }
}

/// Compute XXH3_128 and truncate to 96 bits
#[inline]
fn compute_hash(s: &str) -> [u8; 12] {
    let full = xxh3_128(s.as_bytes());
    let bytes = full.to_le_bytes();
    bytes[0..12].try_into().unwrap()
}

/// Extract shard ID from hash
#[inline]
fn hash_to_shard(hash: &[u8; 12], num_shards: usize) -> usize {
    let bucket_bits = u64::from_le_bytes(hash[0..8].try_into().unwrap());
    #[allow(clippy::cast_possible_truncation)]
    let result = (bucket_bits % num_shards as u64) as usize;
    result
}

/// Extract slot index from hash
#[inline]
fn hash_to_slot(hash: &[u8; 12], mask: usize) -> usize {
    let bucket_bits = u64::from_le_bytes(hash[0..8].try_into().unwrap());
    #[allow(clippy::cast_possible_truncation)]
    let result = (bucket_bits & mask as u64) as usize;
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_hash_table() {
        let mut builder = LiteralHashBuilder::new(MatchMode::CaseSensitive);
        builder.add_pattern("test1", 0);
        builder.add_pattern("test2", 1);
        builder.add_pattern("test3", 2);

        let pattern_data = vec![(0, 100), (1, 200), (2, 300)];
        let bytes = builder.build(&pattern_data).unwrap();

        let hash = LiteralHash::from_buffer(&bytes, MatchMode::CaseSensitive).unwrap();
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
        let mut builder = LiteralHashBuilder::new(MatchMode::CaseSensitive);
        // Add many patterns to force collisions
        for i in 0..100 {
            let pattern = format!("pattern_{i}");
            builder.add_pattern(&pattern, i);
        }

        let pattern_data: Vec<_> = (0..100).map(|i| (i, i * 10)).collect();
        let bytes = builder.build(&pattern_data).unwrap();

        let hash = LiteralHash::from_buffer(&bytes, MatchMode::CaseSensitive).unwrap();
        for i in 0..100 {
            assert_eq!(hash.lookup(&format!("pattern_{i}")), Some(i));
        }
    }
}
