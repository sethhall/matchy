//! Literal String Hash Table for O(1) Lookups
//!
//! Memory-mapped hash table for exact string matching. Uses 96-bit XXH3 hashes
//! (stored as u64 + u32) with sharded parallel construction and linear probing.
//!
//! # Format (Version 3)
//!
//! ```text
//! [Header - 32 bytes]
//!   magic: [u8; 4]           // "LHSH"
//!   version: u32             // 3
//!   entry_count: u32         // Number of literal patterns
//!   table_size: u32          // Hash table size (slots)
//!   num_shards: u32          // Number of shards (power of 2)
//!   shard_bits: u32          // Bits for sharding (log2(num_shards))
//!   mappings_offset: u32     // Offset to pattern mappings
//!   table_offset: u32        // 8-byte aligned offset to hash table
//!
//! [Shard Offset Table]
//!   offsets: [u32; num_shards + 1]
//!
//! [Hash Table - Array of Structs]
//!   entries: [HashEntry; table_size]
//!     hash_lo: u64           // Lower 64 bits of XXH3
//!     hash_hi: u32           // Upper 32 bits of XXH3
//!     pattern_id: u32        // Pattern ID for data lookup
//!
//! [Pattern Mappings]
//!   count: u32
//!   mappings: [(pattern_id: u32, data_offset: u32); count]
//! ```

use matchy_match_mode::MatchMode;
use rayon::prelude::*;
use rustc_hash::FxHashMap;
use std::mem;
use xxhash_rust::xxh3::xxh3_128;

pub mod validation;

pub use validation::{validate_literal_hash, LiteralHashStats, LiteralHashValidationResult};

#[derive(Debug, Clone)]
pub enum LiteralHashError {
    InvalidFormat(String),
}

impl std::fmt::Display for LiteralHashError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidFormat(msg) => write!(f, "Invalid literal hash format: {msg}"),
        }
    }
}

impl std::error::Error for LiteralHashError {}

pub const LITERAL_HASH_MAGIC: &[u8; 4] = b"LHSH";
pub const MATCHY_LITERAL_HASH_VERSION: u32 = 3;

const HEADER_SIZE: usize = 32;
const EMPTY_HASH_LO: u64 = 0xFFFF_FFFF_FFFF_FFFF;
const EMPTY_HASH_HI: u32 = 0xFFFF_FFFF;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct LiteralHashHeader {
    pub magic: [u8; 4],
    pub version: u32,
    pub entry_count: u32,
    pub table_size: u32,
    pub num_shards: u32,
    pub shard_bits: u32,
    pub mappings_offset: u32,
    pub table_offset: u32, // 8-byte aligned offset to hash table
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HashEntry {
    pub hash_lo: u64,
    pub hash_hi: u32,
    pub pattern_id: u32,
}

impl HashEntry {
    const fn empty() -> Self {
        Self {
            hash_lo: EMPTY_HASH_LO,
            hash_hi: EMPTY_HASH_HI,
            pattern_id: 0,
        }
    }

    const fn is_empty(&self) -> bool {
        self.hash_lo == EMPTY_HASH_LO && self.hash_hi == EMPTY_HASH_HI
    }
}

struct Shard {
    table: Vec<HashEntry>,
    shard_id: usize,
}

pub struct LiteralHashBuilder {
    patterns: Vec<(u64, u32, u32)>, // (hash_lo, hash_hi, pattern_id)
    mode: MatchMode,
}

impl LiteralHashBuilder {
    #[must_use]
    pub fn new(mode: MatchMode) -> Self {
        Self {
            patterns: Vec::new(),
            mode,
        }
    }

    pub fn add_pattern(&mut self, pattern: &str, pattern_id: u32) {
        let normalized = match self.mode {
            MatchMode::CaseSensitive => pattern.to_string(),
            MatchMode::CaseInsensitive => pattern.to_lowercase(),
        };
        let (hash_lo, hash_hi) = compute_hash(&normalized);
        self.patterns.push((hash_lo, hash_hi, pattern_id));
    }

    pub fn build(self, pattern_data_offsets: &[(u32, u32)]) -> Result<Vec<u8>, LiteralHashError> {
        if self.patterns.is_empty() {
            return Ok(Vec::new());
        }

        let shard_bits: u32 = if self.patterns.len() < 10_000 {
            4
        } else if self.patterns.len() < 100_000 {
            5
        } else {
            6
        };
        let num_shards = 1 << shard_bits;

        let mut shard_buckets: Vec<Vec<(u64, u32, u32)>> =
            (0..num_shards).map(|_| Vec::new()).collect();

        for (hash_lo, hash_hi, pattern_id) in self.patterns {
            let shard_id = hash_to_shard(hash_lo, num_shards);
            shard_buckets[shard_id].push((hash_lo, hash_hi, pattern_id));
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

        let mut shard_offsets = vec![0u32; num_shards + 1];
        let mut offset = 0u32;
        for shard in &shards {
            shard_offsets[shard.shard_id] = offset;
            offset += u32::try_from(shard.table.len()).map_err(|_| {
                LiteralHashError::InvalidFormat("Shard size exceeds u32::MAX".into())
            })?;
        }
        shard_offsets[num_shards] = offset;

        let shard_table_size = (num_shards + 1) * 4;
        let table_start = align_to_8(HEADER_SIZE + shard_table_size);
        let table_bytes = table_size * mem::size_of::<HashEntry>();
        let mappings_offset = table_start + table_bytes;
        let mappings_size = 4 + pattern_data_offsets.len() * 8;

        let total_size = mappings_offset + mappings_size;
        let mut buffer = vec![0u8; total_size];

        let entry_count = shards
            .iter()
            .map(|s| s.table.iter().filter(|e| !e.is_empty()).count())
            .sum::<usize>();

        // Write header
        buffer[0..4].copy_from_slice(LITERAL_HASH_MAGIC);
        buffer[4..8].copy_from_slice(&MATCHY_LITERAL_HASH_VERSION.to_le_bytes());
        buffer[8..12].copy_from_slice(
            &u32::try_from(entry_count)
                .map_err(|_| {
                    LiteralHashError::InvalidFormat("Entry count exceeds u32::MAX".into())
                })?
                .to_le_bytes(),
        );
        buffer[12..16].copy_from_slice(
            &u32::try_from(table_size)
                .map_err(|_| LiteralHashError::InvalidFormat("Table size exceeds u32::MAX".into()))?
                .to_le_bytes(),
        );
        buffer[16..20].copy_from_slice(
            &u32::try_from(num_shards)
                .map_err(|_| {
                    LiteralHashError::InvalidFormat("Shard count exceeds u32::MAX".into())
                })?
                .to_le_bytes(),
        );
        buffer[20..24].copy_from_slice(&shard_bits.to_le_bytes());
        buffer[24..28].copy_from_slice(
            &u32::try_from(mappings_offset)
                .map_err(|_| {
                    LiteralHashError::InvalidFormat("Mappings offset exceeds u32::MAX".into())
                })?
                .to_le_bytes(),
        );
        buffer[28..32].copy_from_slice(
            &u32::try_from(table_start)
                .map_err(|_| {
                    LiteralHashError::InvalidFormat("Table offset exceeds u32::MAX".into())
                })?
                .to_le_bytes(),
        );

        // Write shard offsets
        let mut pos = HEADER_SIZE;
        for off in &shard_offsets {
            buffer[pos..pos + 4].copy_from_slice(&off.to_le_bytes());
            pos += 4;
        }

        // Write hash table entries
        pos = table_start;
        for shard in &shards {
            for entry in &shard.table {
                buffer[pos..pos + 8].copy_from_slice(&entry.hash_lo.to_le_bytes());
                buffer[pos + 8..pos + 12].copy_from_slice(&entry.hash_hi.to_le_bytes());
                buffer[pos + 12..pos + 16].copy_from_slice(&entry.pattern_id.to_le_bytes());
                pos += 16;
            }
        }

        // Write pattern mappings
        pos = mappings_offset;
        let pattern_count = u32::try_from(pattern_data_offsets.len()).map_err(|_| {
            LiteralHashError::InvalidFormat("Pattern count exceeds u32::MAX".into())
        })?;
        buffer[pos..pos + 4].copy_from_slice(&pattern_count.to_le_bytes());
        pos += 4;
        for (pattern_id, data_offset) in pattern_data_offsets {
            buffer[pos..pos + 4].copy_from_slice(&pattern_id.to_le_bytes());
            buffer[pos + 4..pos + 8].copy_from_slice(&data_offset.to_le_bytes());
            pos += 8;
        }

        Ok(buffer)
    }

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

#[derive(Clone)]
pub struct LiteralHash<'a> {
    buffer: &'a [u8],
    header: LiteralHashHeader,
    table_start: usize,
    shard_offsets: Vec<u32>,
    mode: MatchMode,
}

impl<'a> LiteralHash<'a> {
    pub fn from_buffer(buffer: &'a [u8], mode: MatchMode) -> Result<Self, LiteralHashError> {
        if buffer.len() < HEADER_SIZE {
            return Err(LiteralHashError::InvalidFormat(
                "Buffer too small for header".into(),
            ));
        }

        let magic = &buffer[0..4];
        if magic != LITERAL_HASH_MAGIC {
            return Err(LiteralHashError::InvalidFormat(format!(
                "Invalid magic: expected {LITERAL_HASH_MAGIC:?}, got {magic:?}"
            )));
        }

        let version = u32::from_le_bytes(buffer[4..8].try_into().unwrap());
        if version != MATCHY_LITERAL_HASH_VERSION {
            return Err(LiteralHashError::InvalidFormat(format!(
                "Unsupported version: {version} (expected {MATCHY_LITERAL_HASH_VERSION})"
            )));
        }

        let entry_count = u32::from_le_bytes(buffer[8..12].try_into().unwrap());
        let table_size = u32::from_le_bytes(buffer[12..16].try_into().unwrap());
        let num_shards = u32::from_le_bytes(buffer[16..20].try_into().unwrap());
        if num_shards > 256 {
            return Err(LiteralHashError::InvalidFormat(format!(
                "num_shards {num_shards} exceeds maximum 256"
            )));
        }
        let shard_bits = u32::from_le_bytes(buffer[20..24].try_into().unwrap());
        let mappings_offset = u32::from_le_bytes(buffer[24..28].try_into().unwrap());
        let table_offset = u32::from_le_bytes(buffer[28..32].try_into().unwrap());

        let header = LiteralHashHeader {
            magic: *LITERAL_HASH_MAGIC,
            version,
            entry_count,
            table_size,
            num_shards,
            shard_bits,
            mappings_offset,
            table_offset,
        };

        // Read shard offsets
        let shard_table_start = HEADER_SIZE;
        let mut shard_offsets = Vec::with_capacity(num_shards as usize + 1);
        for i in 0..=num_shards as usize {
            let off_pos = shard_table_start + i * 4;
            if off_pos + 4 > buffer.len() {
                return Err(LiteralHashError::InvalidFormat(
                    "Shard offset table truncated".into(),
                ));
            }
            let off = u32::from_le_bytes(buffer[off_pos..off_pos + 4].try_into().unwrap());
            shard_offsets.push(off);
        }

        let table_start = header.table_offset as usize;

        Ok(Self {
            buffer,
            header,
            table_start,
            shard_offsets,
            mode,
        })
    }

    #[must_use]
    pub fn mode(&self) -> MatchMode {
        self.mode
    }

    #[must_use]
    pub fn lookup(&self, query: &str) -> Option<u32> {
        let (query_lo, query_hi) = match self.mode {
            MatchMode::CaseSensitive => compute_hash(query),
            MatchMode::CaseInsensitive => compute_hash(&query.to_lowercase()),
        };

        let num_shards = self.header.num_shards as usize;
        let shard_id = hash_to_shard(query_lo, num_shards);

        let shard_start = self.shard_offsets[shard_id] as usize;
        let shard_end = self.shard_offsets[shard_id + 1] as usize;
        let shard_capacity = shard_end - shard_start;

        if shard_capacity == 0 {
            return None;
        }

        let shard_mask = shard_capacity - 1;
        let base_slot = hash_to_slot(query_lo, shard_mask);
        let entry_size = mem::size_of::<HashEntry>();

        for i in 0..shard_capacity {
            let slot = (base_slot + i) & shard_mask;
            let global_slot = shard_start + slot;
            let entry_offset = self.table_start + global_slot * entry_size;

            if entry_offset + entry_size > self.buffer.len() {
                return None;
            }

            let hash_lo = u64::from_le_bytes(
                self.buffer[entry_offset..entry_offset + 8]
                    .try_into()
                    .unwrap(),
            );

            // Check lower 64 bits first (fast path rejects most entries)
            if hash_lo == EMPTY_HASH_LO {
                let hash_hi = u32::from_le_bytes(
                    self.buffer[entry_offset + 8..entry_offset + 12]
                        .try_into()
                        .unwrap(),
                );
                if hash_hi == EMPTY_HASH_HI {
                    return None; // Empty slot
                }
            }

            if hash_lo == query_lo {
                let hash_hi = u32::from_le_bytes(
                    self.buffer[entry_offset + 8..entry_offset + 12]
                        .try_into()
                        .unwrap(),
                );
                if hash_hi == query_hi {
                    let pattern_id = u32::from_le_bytes(
                        self.buffer[entry_offset + 12..entry_offset + 16]
                            .try_into()
                            .unwrap(),
                    );
                    return Some(pattern_id);
                }
            }
        }

        None
    }

    #[must_use]
    pub fn get_data_offset(&self, pattern_id: u32) -> Option<u32> {
        let mappings_offset = self.header.mappings_offset as usize;

        if mappings_offset + 4 > self.buffer.len() {
            return None;
        }

        let count = u32::from_le_bytes(
            self.buffer[mappings_offset..mappings_offset + 4]
                .try_into()
                .ok()?,
        );

        let mappings_data_start = mappings_offset + 4;

        for i in 0..count {
            let offset = mappings_data_start + (i as usize) * 8;
            if offset + 8 > self.buffer.len() {
                return None;
            }

            let pid = u32::from_le_bytes(self.buffer[offset..offset + 4].try_into().ok()?);
            if pid == pattern_id {
                return Some(u32::from_le_bytes(
                    self.buffer[offset + 4..offset + 8].try_into().ok()?,
                ));
            }
        }

        None
    }

    #[must_use]
    pub fn entry_count(&self) -> u32 {
        self.header.entry_count
    }

    #[must_use]
    pub fn table_size(&self) -> u32 {
        self.header.table_size
    }
}

fn build_shard(shard_id: usize, entries: &[(u64, u32, u32)]) -> Shard {
    if entries.is_empty() {
        return Shard {
            table: Vec::new(),
            shard_id,
        };
    }

    let needed = (entries.len() * 10).div_ceil(6);
    let capacity = needed.next_power_of_two().max(16);
    let mask = capacity - 1;

    // Deduplicate by full 96-bit hash
    let mut map: FxHashMap<(u64, u32), u32> = FxHashMap::default();
    for (hash_lo, hash_hi, pattern_id) in entries {
        map.insert((*hash_lo, *hash_hi), *pattern_id);
    }

    let mut table = vec![HashEntry::empty(); capacity];

    for ((hash_lo, hash_hi), pattern_id) in map {
        let mut pos = hash_to_slot(hash_lo, mask);
        let mut probes = 0;

        while !table[pos].is_empty() {
            pos = (pos + 1) & mask;
            probes += 1;
            debug_assert!(probes < capacity, "hash table unexpectedly full");
        }

        table[pos] = HashEntry {
            hash_lo,
            hash_hi,
            pattern_id,
        };
    }

    Shard { table, shard_id }
}

/// Compute 96-bit hash as (u64, u32) from XXH3_128.
/// Never returns the empty marker to avoid collisions.
#[inline]
fn compute_hash(s: &str) -> (u64, u32) {
    let full = xxh3_128(s.as_bytes());
    let lo = (full & 0xFFFF_FFFF_FFFF_FFFF) as u64;
    let hi = ((full >> 64) & 0xFFFF_FFFF) as u32;

    // Avoid collision with empty marker by flipping bits in both halves
    if lo == EMPTY_HASH_LO && hi == EMPTY_HASH_HI {
        (lo ^ 1, hi ^ 1)
    } else {
        (lo, hi)
    }
}

#[inline]
const fn align_to_8(val: usize) -> usize {
    (val + 7) & !7
}

#[inline]
fn hash_to_shard(hash_lo: u64, num_shards: usize) -> usize {
    #[allow(clippy::cast_possible_truncation)]
    ((hash_lo % num_shards as u64) as usize)
}

#[inline]
fn hash_to_slot(hash_lo: u64, mask: usize) -> usize {
    #[allow(clippy::cast_possible_truncation)]
    (((hash_lo >> 32) as usize) & mask)
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
        for i in 0..100 {
            builder.add_pattern(&format!("pattern_{i}"), i);
        }

        let pattern_data: Vec<_> = (0..100).map(|i| (i, i * 10)).collect();
        let bytes = builder.build(&pattern_data).unwrap();

        let hash = LiteralHash::from_buffer(&bytes, MatchMode::CaseSensitive).unwrap();
        for i in 0..100 {
            assert_eq!(hash.lookup(&format!("pattern_{i}")), Some(i));
        }
    }

    #[test]
    fn test_case_insensitive() {
        let mut builder = LiteralHashBuilder::new(MatchMode::CaseInsensitive);
        builder.add_pattern("Example.Com", 0);
        builder.add_pattern("TEST", 1);

        let pattern_data = vec![(0, 100), (1, 200)];
        let bytes = builder.build(&pattern_data).unwrap();

        let hash = LiteralHash::from_buffer(&bytes, MatchMode::CaseInsensitive).unwrap();
        assert_eq!(hash.lookup("example.com"), Some(0));
        assert_eq!(hash.lookup("EXAMPLE.COM"), Some(0));
        assert_eq!(hash.lookup("test"), Some(1));
        assert_eq!(hash.lookup("TeSt"), Some(1));
    }

    #[test]
    fn test_empty_table() {
        let builder = LiteralHashBuilder::new(MatchMode::CaseSensitive);
        let bytes = builder.build(&[]).unwrap();
        assert!(bytes.is_empty());
    }

    #[test]
    fn test_large_table() {
        let mut builder = LiteralHashBuilder::new(MatchMode::CaseSensitive);
        for i in 0..10_000 {
            builder.add_pattern(&format!("entry_{i}"), i);
        }

        let pattern_data: Vec<_> = (0..10_000).map(|i| (i, i * 4)).collect();
        let bytes = builder.build(&pattern_data).unwrap();

        let hash = LiteralHash::from_buffer(&bytes, MatchMode::CaseSensitive).unwrap();

        assert_eq!(hash.lookup("entry_0"), Some(0));
        assert_eq!(hash.lookup("entry_5000"), Some(5000));
        assert_eq!(hash.lookup("entry_9999"), Some(9999));
        assert_eq!(hash.lookup("entry_10000"), None);
    }

    #[test]
    fn test_version_mismatch() {
        let mut buffer = vec![0u8; 128];
        buffer[0..4].copy_from_slice(b"LHSH");
        buffer[4..8].copy_from_slice(&2u32.to_le_bytes());

        let result = LiteralHash::from_buffer(&buffer, MatchMode::CaseSensitive);
        match result {
            Err(LiteralHashError::InvalidFormat(msg)) => {
                assert!(msg.contains("Unsupported version"), "got: {msg}");
            }
            Ok(_) => panic!("expected version mismatch error"),
        }
    }

    #[test]
    fn test_num_shards_limit() {
        let mut buffer = vec![0u8; 128];
        buffer[0..4].copy_from_slice(b"LHSH");
        buffer[4..8].copy_from_slice(&3u32.to_le_bytes());
        buffer[16..20].copy_from_slice(&1000u32.to_le_bytes());

        let result = LiteralHash::from_buffer(&buffer, MatchMode::CaseSensitive);
        assert!(
            matches!(result, Err(LiteralHashError::InvalidFormat(msg)) if msg.contains("exceeds maximum"))
        );
    }

    #[test]
    fn test_get_data_offset_not_found() {
        let mut builder = LiteralHashBuilder::new(MatchMode::CaseSensitive);
        builder.add_pattern("test", 0);
        let bytes = builder.build(&[(0, 100)]).unwrap();
        let hash = LiteralHash::from_buffer(&bytes, MatchMode::CaseSensitive).unwrap();

        assert_eq!(hash.get_data_offset(999), None);
    }

    #[test]
    fn test_empty_marker_not_returned_by_hash() {
        for i in 0..1000 {
            let (lo, hi) = compute_hash(&format!("test_string_{i}"));
            assert!(
                !(lo == EMPTY_HASH_LO && hi == EMPTY_HASH_HI),
                "compute_hash returned empty marker for input {i}"
            );
        }
    }

    #[test]
    fn test_binary_format_alignment() {
        const _: () = assert!(mem::size_of::<LiteralHashHeader>() == 32);
        const _: () = assert!(mem::size_of::<HashEntry>() == 16);
        const _: () = assert!(mem::align_of::<HashEntry>() == 8);

        let mut builder = LiteralHashBuilder::new(MatchMode::CaseSensitive);
        for i in 0..100 {
            builder.add_pattern(&format!("pattern_{i}"), i);
        }
        let pattern_data: Vec<_> = (0..100).map(|i| (i, i * 10)).collect();
        let bytes = builder.build(&pattern_data).unwrap();

        let table_offset = u32::from_le_bytes(bytes[28..32].try_into().unwrap()) as usize;
        assert!(
            table_offset.is_multiple_of(8),
            "table_offset {table_offset} not 8-byte aligned"
        );

        let table_size = u32::from_le_bytes(bytes[12..16].try_into().unwrap()) as usize;
        for i in 0..table_size {
            let entry_offset = table_offset + i * mem::size_of::<HashEntry>();
            assert!(
                entry_offset.is_multiple_of(8),
                "entry {i} at offset {entry_offset} not 8-byte aligned"
            );
        }

        let hash = LiteralHash::from_buffer(&bytes, MatchMode::CaseSensitive).unwrap();
        for i in 0..100 {
            assert_eq!(hash.lookup(&format!("pattern_{i}")), Some(i));
        }
    }
}
