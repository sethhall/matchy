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
//!     hash_hi: u32           // Bits 64..95 of XXH3_128
//!     pattern_id: u32        // Pattern ID for data lookup
//!
//! [Pattern Mappings]
//!   count: u32
//!   mappings: [(pattern_id: u32, data_offset: u32); count]
//! ```

use matchy_match_mode::MatchMode;
use rayon::prelude::*;
use rustc_hash::FxHashMap;
use std::cell::RefCell;
use std::mem;
use std::thread_local;
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

thread_local! {
    static NORMALIZED_QUERY_BUFFER: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

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
    table_size: usize,
    shard_offsets: Vec<u32>,
    mappings_start: usize,
    mapping_count: usize,
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
        if num_shards == 0 {
            return Err(LiteralHashError::InvalidFormat(
                "num_shards must be non-zero".into(),
            ));
        }
        if num_shards > 256 {
            return Err(LiteralHashError::InvalidFormat(format!(
                "num_shards {num_shards} exceeds maximum 256"
            )));
        }
        if !num_shards.is_power_of_two() {
            return Err(LiteralHashError::InvalidFormat(format!(
                "num_shards {num_shards} is not a power of two"
            )));
        }
        let shard_bits = u32::from_le_bytes(buffer[20..24].try_into().unwrap());
        if 1u32.checked_shl(shard_bits) != Some(num_shards) {
            return Err(LiteralHashError::InvalidFormat(format!(
                "shard_bits {shard_bits} is inconsistent with num_shards {num_shards}"
            )));
        }
        if table_size == 0 {
            return Err(LiteralHashError::InvalidFormat(
                "table_size must be non-zero".into(),
            ));
        }
        if entry_count > table_size {
            return Err(LiteralHashError::InvalidFormat(format!(
                "entry_count {entry_count} exceeds table_size {table_size}"
            )));
        }
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

        let num_shards = usize::try_from(num_shards)
            .map_err(|_| LiteralHashError::InvalidFormat("num_shards does not fit usize".into()))?;
        let shard_offset_count = num_shards
            .checked_add(1)
            .ok_or_else(|| LiteralHashError::InvalidFormat("Shard offset count overflow".into()))?;
        let shard_table_bytes = shard_offset_count
            .checked_mul(mem::size_of::<u32>())
            .ok_or_else(|| {
                LiteralHashError::InvalidFormat("Shard offset table size overflow".into())
            })?;

        // Read shard offsets only after validating the complete table envelope.
        let shard_table_start = HEADER_SIZE;
        let shard_table_end = shard_table_start
            .checked_add(shard_table_bytes)
            .ok_or_else(|| {
                LiteralHashError::InvalidFormat("Shard offset table end overflow".into())
            })?;
        if shard_table_end > buffer.len() {
            return Err(LiteralHashError::InvalidFormat(
                "Shard offset table truncated".into(),
            ));
        }

        let table_start = usize::try_from(header.table_offset).map_err(|_| {
            LiteralHashError::InvalidFormat("table_offset does not fit usize".into())
        })?;
        if !table_start.is_multiple_of(mem::align_of::<HashEntry>()) {
            return Err(LiteralHashError::InvalidFormat(format!(
                "table_offset {table_start} is not {}-byte aligned",
                mem::align_of::<HashEntry>()
            )));
        }
        if table_start < shard_table_end {
            return Err(LiteralHashError::InvalidFormat(format!(
                "table_offset {table_start} overlaps shard offset table ending at {shard_table_end}"
            )));
        }

        let table_size = usize::try_from(header.table_size)
            .map_err(|_| LiteralHashError::InvalidFormat("table_size does not fit usize".into()))?;
        let table_bytes = table_size
            .checked_mul(mem::size_of::<HashEntry>())
            .ok_or_else(|| LiteralHashError::InvalidFormat("Hash table size overflow".into()))?;
        let table_end = table_start.checked_add(table_bytes).ok_or_else(|| {
            LiteralHashError::InvalidFormat("Hash table end offset overflow".into())
        })?;
        if table_end > buffer.len() {
            return Err(LiteralHashError::InvalidFormat(format!(
                "Hash table ends at {table_end}, beyond buffer length {}",
                buffer.len()
            )));
        }

        let mappings_offset = usize::try_from(header.mappings_offset).map_err(|_| {
            LiteralHashError::InvalidFormat("mappings_offset does not fit usize".into())
        })?;
        if mappings_offset < table_end {
            return Err(LiteralHashError::InvalidFormat(format!(
                "mappings_offset {mappings_offset} overlaps hash table ending at {table_end}"
            )));
        }
        let mappings_start = mappings_offset
            .checked_add(mem::size_of::<u32>())
            .ok_or_else(|| {
                LiteralHashError::InvalidFormat("Pattern mapping header end overflow".into())
            })?;
        let mapping_count_bytes = buffer.get(mappings_offset..mappings_start).ok_or_else(|| {
            LiteralHashError::InvalidFormat("Pattern mapping count is truncated".into())
        })?;
        let mapping_count = usize::try_from(u32::from_le_bytes(
            mapping_count_bytes
                .try_into()
                .expect("mapping count slice has exact length"),
        ))
        .map_err(|_| {
            LiteralHashError::InvalidFormat("Pattern mapping count does not fit usize".into())
        })?;
        let mapping_bytes = mapping_count
            .checked_mul(2 * mem::size_of::<u32>())
            .ok_or_else(|| {
                LiteralHashError::InvalidFormat("Pattern mapping table size overflow".into())
            })?;
        let mappings_end = mappings_start.checked_add(mapping_bytes).ok_or_else(|| {
            LiteralHashError::InvalidFormat("Pattern mapping table end overflow".into())
        })?;
        if mappings_end > buffer.len() {
            return Err(LiteralHashError::InvalidFormat(format!(
                "Pattern mapping table ends at {mappings_end}, beyond buffer length {}",
                buffer.len()
            )));
        }

        let mut shard_offsets = Vec::with_capacity(shard_offset_count);
        for i in 0..shard_offset_count {
            let relative = i.checked_mul(mem::size_of::<u32>()).ok_or_else(|| {
                LiteralHashError::InvalidFormat("Shard offset position overflow".into())
            })?;
            let off_pos = shard_table_start.checked_add(relative).ok_or_else(|| {
                LiteralHashError::InvalidFormat("Shard offset position overflow".into())
            })?;
            let off_end = off_pos + mem::size_of::<u32>();
            let off = u32::from_le_bytes(
                buffer[off_pos..off_end]
                    .try_into()
                    .expect("validated shard offset slice has exact length"),
            );
            shard_offsets.push(off);
        }

        if shard_offsets.first().copied() != Some(0) {
            return Err(LiteralHashError::InvalidFormat(
                "First shard offset must be zero".into(),
            ));
        }
        if shard_offsets.last().copied() != Some(header.table_size) {
            return Err(LiteralHashError::InvalidFormat(format!(
                "Final shard offset must equal table_size {}",
                header.table_size
            )));
        }
        for (shard_id, offsets) in shard_offsets.windows(2).enumerate() {
            let start = offsets[0];
            let end = offsets[1];
            if end < start {
                return Err(LiteralHashError::InvalidFormat(format!(
                    "Shard {shard_id} offsets are not monotonic ({start} then {end})"
                )));
            }
        }
        for (shard_id, offsets) in shard_offsets.windows(2).enumerate() {
            let start = offsets[0];
            let end = offsets[1];
            if end > header.table_size {
                return Err(LiteralHashError::InvalidFormat(format!(
                    "Shard {shard_id} end {end} exceeds table_size {}",
                    header.table_size
                )));
            }
            let capacity = end - start;
            if capacity != 0 && !capacity.is_power_of_two() {
                return Err(LiteralHashError::InvalidFormat(format!(
                    "Shard {shard_id} capacity {capacity} is not a power of two"
                )));
            }
        }

        Ok(Self {
            buffer,
            header,
            table_start,
            table_size,
            shard_offsets,
            mappings_start,
            mapping_count,
            mode,
        })
    }

    #[must_use]
    pub fn mode(&self) -> MatchMode {
        self.mode
    }

    #[must_use]
    pub fn lookup(&self, query: &str) -> Option<u32> {
        let (query_lo, query_hi) = compute_query_hash(query, self.mode);

        let num_shards = self.header.num_shards as usize;
        let shard_id = hash_to_shard(query_lo, num_shards);

        let shard_start = usize::try_from(*self.shard_offsets.get(shard_id)?).ok()?;
        let shard_end = usize::try_from(*self.shard_offsets.get(shard_id.checked_add(1)?)?).ok()?;
        let shard_capacity = shard_end.checked_sub(shard_start)?;

        if shard_capacity == 0 {
            return None;
        }
        if !shard_capacity.is_power_of_two() {
            return None;
        }

        let shard_mask = shard_capacity - 1;
        let base_slot = hash_to_slot(query_lo, shard_mask);
        let entry_size = mem::size_of::<HashEntry>();

        for i in 0..shard_capacity {
            let slot = base_slot.wrapping_add(i) & shard_mask;
            let global_slot = shard_start.checked_add(slot)?;
            if global_slot >= self.table_size {
                return None;
            }
            let entry_offset = global_slot
                .checked_mul(entry_size)
                .and_then(|relative| self.table_start.checked_add(relative))?;
            let entry_end = entry_offset.checked_add(entry_size)?;
            let entry = self.buffer.get(entry_offset..entry_end)?;

            let hash_lo = u64::from_le_bytes(entry[..8].try_into().ok()?);

            // Check lower 64 bits first (fast path rejects most entries)
            if hash_lo == EMPTY_HASH_LO {
                let hash_hi = u32::from_le_bytes(entry[8..12].try_into().ok()?);
                if hash_hi == EMPTY_HASH_HI {
                    return None; // Empty slot
                }
            }

            if hash_lo == query_lo {
                let hash_hi = u32::from_le_bytes(entry[8..12].try_into().ok()?);
                if hash_hi == query_hi {
                    let pattern_id = u32::from_le_bytes(entry[12..16].try_into().ok()?);
                    return Some(pattern_id);
                }
            }
        }

        None
    }

    #[must_use]
    pub fn get_data_offset(&self, pattern_id: u32) -> Option<u32> {
        // Builder output is ordered by pattern ID, so use the compact mapping
        // table directly as a binary-search index. Hand-built legacy buffers
        // were not required to be sorted; retain a linear compatibility
        // fallback when the ordered search misses.
        let mut left = 0usize;
        let mut right = self.mapping_count;
        while left < right {
            let middle = left + (right - left) / 2;
            let (mapped_pattern_id, data_offset) = self.mapping_at(middle)?;
            match mapped_pattern_id.cmp(&pattern_id) {
                std::cmp::Ordering::Equal => return Some(data_offset),
                std::cmp::Ordering::Less => left = middle + 1,
                std::cmp::Ordering::Greater => right = middle,
            }
        }

        for (pid, data_offset) in self.data_mappings() {
            if pid == pattern_id {
                return Some(data_offset);
            }
        }

        None
    }

    fn mapping_at(&self, index: usize) -> Option<(u32, u32)> {
        const MAPPING_SIZE: usize = 2 * mem::size_of::<u32>();

        if index >= self.mapping_count {
            return None;
        }
        let offset = index
            .checked_mul(MAPPING_SIZE)
            .and_then(|relative| self.mappings_start.checked_add(relative))?;
        let end = offset.checked_add(MAPPING_SIZE)?;
        let mapping = self.buffer.get(offset..end)?;
        let pattern_id = u32::from_le_bytes(mapping[..4].try_into().ok()?);
        let data_offset = u32::from_le_bytes(mapping[4..].try_into().ok()?);
        Some((pattern_id, data_offset))
    }

    /// Iterate over `(pattern_id, data_offset)` mappings in serialized order.
    ///
    /// The offsets are relative to the containing MMDB data section. The
    /// iterator is allocation-free; malformed mapping envelopes are rejected
    /// when [`Self::from_buffer`] constructs the hash.
    pub fn data_mappings(&self) -> impl Iterator<Item = (u32, u32)> + '_ {
        (0..self.mapping_count).filter_map(move |index| self.mapping_at(index))
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
fn compute_hash_bytes(bytes: &[u8]) -> (u64, u32) {
    let full = xxh3_128(bytes);
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
fn compute_hash(s: &str) -> (u64, u32) {
    compute_hash_bytes(s.as_bytes())
}

fn compute_query_hash(query: &str, mode: MatchMode) -> (u64, u32) {
    match mode {
        MatchMode::CaseSensitive => compute_hash(query),
        MatchMode::CaseInsensitive if query.is_ascii() => NORMALIZED_QUERY_BUFFER.with(|buf| {
            let mut normalized = buf.borrow_mut();
            normalized.clear();
            normalized.extend_from_slice(query.as_bytes());
            normalized.make_ascii_lowercase();
            compute_hash_bytes(&normalized)
        }),
        MatchMode::CaseInsensitive => compute_hash(&query.to_lowercase()),
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

    fn put_u32(buffer: &mut [u8], offset: usize, value: u32) {
        buffer[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn basic_buffer() -> Vec<u8> {
        let mut builder = LiteralHashBuilder::new(MatchMode::CaseSensitive);
        builder.add_pattern("literal.example", 0);
        builder.build(&[(0, 42)]).unwrap()
    }

    fn synthetic_buffer(shard_offsets: &[u32], table_size: u32) -> Vec<u8> {
        assert!(shard_offsets.len() >= 2);
        let num_shards = u32::try_from(shard_offsets.len() - 1).unwrap();
        assert!(num_shards.is_power_of_two());
        let shard_table_end = HEADER_SIZE + mem::size_of_val(shard_offsets);
        let table_offset = align_to_8(shard_table_end);
        let table_end =
            table_offset + usize::try_from(table_size).unwrap() * mem::size_of::<HashEntry>();
        let mappings_offset = table_end;
        let mut buffer = vec![0u8; mappings_offset + mem::size_of::<u32>()];
        buffer[..4].copy_from_slice(LITERAL_HASH_MAGIC);
        put_u32(&mut buffer, 4, MATCHY_LITERAL_HASH_VERSION);
        put_u32(&mut buffer, 8, 0);
        put_u32(&mut buffer, 12, table_size);
        put_u32(&mut buffer, 16, num_shards);
        put_u32(&mut buffer, 20, num_shards.trailing_zeros());
        put_u32(&mut buffer, 24, u32::try_from(mappings_offset).unwrap());
        put_u32(&mut buffer, 28, u32::try_from(table_offset).unwrap());
        for (index, &offset) in shard_offsets.iter().enumerate() {
            put_u32(
                &mut buffer,
                HEADER_SIZE + index * mem::size_of::<u32>(),
                offset,
            );
        }
        put_u32(&mut buffer, mappings_offset, 0);
        buffer
    }

    fn assert_invalid(buffer: &[u8], expected: &str) {
        let error = match LiteralHash::from_buffer(buffer, MatchMode::CaseSensitive) {
            Ok(_) => panic!("expected malformed literal hash to be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(
            error.contains(expected),
            "expected error containing {expected:?}, got {error:?}"
        );
    }

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
        assert_eq!(
            hash.data_mappings().collect::<Vec<_>>(),
            pattern_data,
            "mapping iterator should preserve serialized order"
        );
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
    fn unsorted_legacy_mappings_use_compatibility_fallback() {
        let mut builder = LiteralHashBuilder::new(MatchMode::CaseSensitive);
        builder.add_pattern("zero", 0);
        builder.add_pattern("one", 1);
        builder.add_pattern("two", 2);
        let bytes = builder.build(&[(2, 300), (0, 100), (1, 200)]).unwrap();
        let hash = LiteralHash::from_buffer(&bytes, MatchMode::CaseSensitive).unwrap();

        assert_eq!(hash.get_data_offset(0), Some(100));
        assert_eq!(hash.get_data_offset(1), Some(200));
        assert_eq!(hash.get_data_offset(2), Some(300));
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
    fn rejects_invalid_header_relationships() {
        let valid = basic_buffer();
        let table_size = u32::from_le_bytes(valid[12..16].try_into().unwrap());

        let mut zero_shards = valid.clone();
        put_u32(&mut zero_shards, 16, 0);
        assert_invalid(&zero_shards, "non-zero");

        let mut non_power_of_two_shards = valid.clone();
        put_u32(&mut non_power_of_two_shards, 16, 3);
        assert_invalid(&non_power_of_two_shards, "not a power of two");

        let mut inconsistent_shard_bits = valid.clone();
        put_u32(&mut inconsistent_shard_bits, 20, 31);
        assert_invalid(&inconsistent_shard_bits, "inconsistent");

        let mut zero_table = valid.clone();
        put_u32(&mut zero_table, 12, 0);
        assert_invalid(&zero_table, "table_size must be non-zero");

        let mut too_many_entries = valid;
        put_u32(&mut too_many_entries, 8, table_size + 1);
        assert_invalid(&too_many_entries, "exceeds table_size");
    }

    #[test]
    fn rejects_invalid_table_and_mapping_envelopes() {
        let valid = basic_buffer();
        let table_offset = u32::from_le_bytes(valid[28..32].try_into().unwrap());
        let mappings_offset =
            usize::try_from(u32::from_le_bytes(valid[24..28].try_into().unwrap())).unwrap();

        let mut misaligned_table = valid.clone();
        put_u32(&mut misaligned_table, 28, table_offset + 1);
        assert_invalid(&misaligned_table, "not 8-byte aligned");

        let mut overlapping_table = valid.clone();
        put_u32(
            &mut overlapping_table,
            28,
            u32::try_from(HEADER_SIZE).unwrap(),
        );
        assert_invalid(&overlapping_table, "overlaps shard offset table");

        let mut truncated_table = valid.clone();
        put_u32(&mut truncated_table, 12, u32::MAX);
        assert_invalid(&truncated_table, "beyond buffer length");

        let mut overlapping_mappings = valid.clone();
        put_u32(&mut overlapping_mappings, 24, table_offset);
        assert_invalid(&overlapping_mappings, "overlaps hash table");

        let mut missing_mapping_count = valid.clone();
        let missing_mapping_offset = u32::try_from(missing_mapping_count.len()).unwrap();
        put_u32(&mut missing_mapping_count, 24, missing_mapping_offset);
        assert_invalid(&missing_mapping_count, "mapping count is truncated");

        let mut truncated_mappings = valid;
        put_u32(&mut truncated_mappings, mappings_offset, u32::MAX);
        assert_invalid(&truncated_mappings, "beyond buffer length");
    }

    #[test]
    fn rejects_invalid_shard_ranges() {
        let valid = basic_buffer();
        let num_shards =
            usize::try_from(u32::from_le_bytes(valid[16..20].try_into().unwrap())).unwrap();
        let table_size = u32::from_le_bytes(valid[12..16].try_into().unwrap());

        let mut nonzero_first = valid.clone();
        put_u32(&mut nonzero_first, HEADER_SIZE, 1);
        assert_invalid(&nonzero_first, "First shard offset must be zero");

        let mut wrong_final = valid.clone();
        put_u32(
            &mut wrong_final,
            HEADER_SIZE + num_shards * mem::size_of::<u32>(),
            table_size - 1,
        );
        assert_invalid(&wrong_final, "Final shard offset must equal table_size");

        let non_monotonic = synthetic_buffer(&[0, 16, 8], 8);
        assert_invalid(&non_monotonic, "not monotonic");

        let non_power_of_two_capacity = synthetic_buffer(&[0, 15], 15);
        assert_invalid(
            &non_power_of_two_capacity,
            "capacity 15 is not a power of two",
        );
    }

    #[test]
    fn rejects_truncated_shard_offset_table() {
        let mut buffer = basic_buffer();
        put_u32(&mut buffer, 16, 256);
        put_u32(&mut buffer, 20, 8);
        buffer.truncate(HEADER_SIZE + 8);
        assert_invalid(&buffer, "Shard offset table truncated");
    }

    #[test]
    fn lookup_and_mapping_arithmetic_fail_closed() {
        let header = LiteralHashHeader {
            magic: *LITERAL_HASH_MAGIC,
            version: MATCHY_LITERAL_HASH_VERSION,
            entry_count: 1,
            table_size: 1,
            num_shards: 1,
            shard_bits: 0,
            mappings_offset: 0,
            table_offset: 0,
        };
        let hash = LiteralHash {
            buffer: &[],
            header,
            table_start: usize::MAX,
            table_size: 1,
            shard_offsets: vec![0, 1],
            mappings_start: usize::MAX,
            mapping_count: 1,
            mode: MatchMode::CaseSensitive,
        };

        assert_eq!(hash.lookup("anything"), None);
        assert_eq!(hash.get_data_offset(0), None);
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
