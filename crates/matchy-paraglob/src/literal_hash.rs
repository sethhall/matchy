//! AC Literal ID Hash Table for O(1) Lookups
//!
//! This module provides a memory-mapped hash table for mapping AC literal IDs
//! to their associated pattern IDs. This enables O(1) database loading while
//! maintaining O(1) query performance.
//!
//! # Format
//!
//! The hash table is stored in a memory-mappable binary format:
//!
//! ```text
//! [Header]
//!   magic: [u8; 4]           // "ACLH"
//!   version: u32              // 1
//!   entry_count: u32          // Number of AC literals
//!   table_size: u32           // Hash table size (entry_count * 1.25)
//!   patterns_offset: u32      // Offset to pattern lists section
//!   patterns_size: u32        // Size of pattern lists section
//!
//! [Hash Table]
//!   entries: [HashEntry; table_size]
//!     literal_id: u32         // AC literal ID (or 0xFFFFFFFF if empty)
//!     patterns_offset: u32    // Offset into pattern lists section
//!     pattern_count: u32      // Number of patterns for this literal
//!     reserved: u32           // Reserved for alignment
//!
//! [Pattern Lists]
//!   For each literal: [pattern_id: u32, pattern_id: u32, ...]
//! ```

use crate::error::ParaglobError;
use rustc_hash::FxHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::mem;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

/// Magic bytes for AC literal hash section
pub const AC_LITERAL_HASH_MAGIC: &[u8; 4] = b"ACLH";

/// Current version of the AC literal hash format
pub const MATCHY_AC_LITERAL_HASH_VERSION: u32 = 1;

/// Empty slot marker
const EMPTY_SLOT: u32 = 0xFFFFFFFF;

/// Hash table header (24 bytes, 4-byte aligned)
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct ACLiteralHashHeader {
    /// Magic bytes "ACLH"
    pub magic: [u8; 4],
    /// Format version
    pub version: u32,
    /// Number of AC literals
    pub entry_count: u32,
    /// Hash table size
    pub table_size: u32,
    /// Offset to pattern lists section
    pub patterns_offset: u32,
    /// Size of pattern lists section
    pub patterns_size: u32,
}

/// Single hash table entry (16 bytes, 4-byte aligned)
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct ACHashEntry {
    /// AC literal ID (or EMPTY_SLOT if empty)
    pub literal_id: u32,
    /// Offset into pattern lists section
    pub patterns_offset: u32,
    /// Number of patterns for this literal
    pub pattern_count: u32,
    /// Reserved for alignment
    pub reserved: u32,
}

impl ACHashEntry {
    fn empty() -> Self {
        Self {
            literal_id: EMPTY_SLOT,
            patterns_offset: 0,
            pattern_count: 0,
            reserved: 0,
        }
    }

    fn is_empty(&self) -> bool {
        self.literal_id == EMPTY_SLOT
    }
}

/// Compute hash for a u32 literal ID
fn compute_hash(literal_id: u32) -> u64 {
    let mut hasher = FxHasher::default();
    literal_id.hash(&mut hasher);
    hasher.finish()
}

/// Builder for AC literal hash table
pub struct ACLiteralHashBuilder {
    // Map from AC literal ID to list of pattern IDs
    mappings: HashMap<u32, Vec<u32>>,
}

impl ACLiteralHashBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            mappings: HashMap::new(),
        }
    }

    /// Add a mapping from AC literal ID to pattern IDs
    pub fn add_mapping(&mut self, literal_id: u32, pattern_ids: Vec<u32>) {
        self.mappings.insert(literal_id, pattern_ids);
    }

    /// Build the hash table
    #[must_use]
    pub fn build(self) -> Vec<u8> {
        if self.mappings.is_empty() {
            return Vec::new();
        }

        // Calculate table size (125% of entries for ~0.8 load factor)
        let table_size = (self.mappings.len() * 5).div_ceil(4).max(16);

        // Build pattern lists section
        let mut pattern_lists = Vec::new();
        let mut pattern_offsets = HashMap::new();

        for (literal_id, pattern_ids) in &self.mappings {
            pattern_offsets.insert(*literal_id, pattern_lists.len());
            for pattern_id in pattern_ids {
                pattern_lists.extend_from_slice(&pattern_id.to_le_bytes());
            }
        }

        // Build hash table with linear probing
        let mut table = vec![ACHashEntry::empty(); table_size];

        for (literal_id, pattern_ids) in &self.mappings {
            let hash = compute_hash(*literal_id);
            let mut slot = usize::try_from(hash).unwrap_or(0) % table_size;

            // Linear probing to find empty slot
            loop {
                if table[slot].is_empty() {
                    table[slot] = ACHashEntry {
                        literal_id: *literal_id,
                        patterns_offset: u32::try_from(pattern_offsets[literal_id])
                            .expect("Pattern offset exceeds u32::MAX"),
                        pattern_count: u32::try_from(pattern_ids.len())
                            .expect("Pattern count exceeds u32::MAX"),
                        reserved: 0,
                    };
                    break;
                }
                slot = (slot + 1) % table_size;
            }
        }

        // Calculate offsets
        let header_size = mem::size_of::<ACLiteralHashHeader>();
        let table_bytes_size = table_size * mem::size_of::<ACHashEntry>();
        let patterns_offset = header_size + table_bytes_size;
        let patterns_size = pattern_lists.len();

        // Serialize everything
        let mut buffer = Vec::new();

        // Header
        let header = ACLiteralHashHeader {
            magic: *AC_LITERAL_HASH_MAGIC,
            version: MATCHY_AC_LITERAL_HASH_VERSION,
            entry_count: u32::try_from(self.mappings.len()).expect("Entry count exceeds u32::MAX"),
            table_size: u32::try_from(table_size).expect("Table size exceeds u32::MAX"),
            patterns_offset: u32::try_from(patterns_offset)
                .expect("Patterns offset exceeds u32::MAX"),
            patterns_size: u32::try_from(patterns_size).expect("Patterns size exceeds u32::MAX"),
        };

        buffer.extend_from_slice(&header.magic);
        buffer.extend_from_slice(&header.version.to_le_bytes());
        buffer.extend_from_slice(&header.entry_count.to_le_bytes());
        buffer.extend_from_slice(&header.table_size.to_le_bytes());
        buffer.extend_from_slice(&header.patterns_offset.to_le_bytes());
        buffer.extend_from_slice(&header.patterns_size.to_le_bytes());

        // Hash table entries
        for entry in &table {
            buffer.extend_from_slice(&entry.literal_id.to_le_bytes());
            buffer.extend_from_slice(&entry.patterns_offset.to_le_bytes());
            buffer.extend_from_slice(&entry.pattern_count.to_le_bytes());
            buffer.extend_from_slice(&entry.reserved.to_le_bytes());
        }

        // Pattern lists
        buffer.extend_from_slice(&pattern_lists);

        buffer
    }
}

impl Default for ACLiteralHashBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Memory-mapped AC literal hash table for lookups
#[derive(Clone)]
pub struct ACLiteralHash<'a> {
    table: &'a [u8],
    patterns: &'a [u8],
    table_size: usize,
}

impl<'a> ACLiteralHash<'a> {
    /// Load from memory-mapped buffer
    pub fn from_buffer(buffer: &'a [u8]) -> Result<Self, ParaglobError> {
        if buffer.len() < mem::size_of::<ACLiteralHashHeader>() {
            return Err(ParaglobError::InvalidPattern(
                "Buffer too small for AC literal hash header".to_string(),
            ));
        }

        // Read into an owned value so the source slice does not need to satisfy
        // `ACLiteralHashHeader`'s alignment requirement.
        let (header, _) = ACLiteralHashHeader::read_from_prefix(buffer).map_err(|_| {
            ParaglobError::InvalidPattern("Truncated AC literal hash header".to_string())
        })?;

        // Validate header
        if &header.magic != AC_LITERAL_HASH_MAGIC {
            return Err(ParaglobError::InvalidPattern(format!(
                "Invalid AC literal hash magic: expected {:?}, got {:?}",
                AC_LITERAL_HASH_MAGIC, header.magic
            )));
        }

        if header.version != MATCHY_AC_LITERAL_HASH_VERSION {
            return Err(ParaglobError::InvalidPattern(format!(
                "Unsupported AC literal hash version: {}",
                header.version
            )));
        }

        let table_size = usize::try_from(header.table_size).map_err(|_| {
            ParaglobError::InvalidPattern("AC literal hash table size is invalid".to_string())
        })?;
        if table_size == 0 {
            return Err(ParaglobError::InvalidPattern(
                "AC literal hash table size must be non-zero".to_string(),
            ));
        }

        let entry_count = usize::try_from(header.entry_count).map_err(|_| {
            ParaglobError::InvalidPattern("AC literal hash entry count is invalid".to_string())
        })?;
        if entry_count > table_size {
            return Err(ParaglobError::InvalidPattern(format!(
                "AC literal hash entry count {entry_count} exceeds table size {table_size}"
            )));
        }

        let table_start = mem::size_of::<ACLiteralHashHeader>();
        let table_bytes = table_size
            .checked_mul(mem::size_of::<ACHashEntry>())
            .ok_or_else(|| {
                ParaglobError::InvalidPattern(
                    "AC literal hash table size overflows address space".to_string(),
                )
            })?;
        let table_end = table_start.checked_add(table_bytes).ok_or_else(|| {
            ParaglobError::InvalidPattern(
                "AC literal hash table range overflows address space".to_string(),
            )
        })?;
        if table_end > buffer.len() {
            return Err(ParaglobError::InvalidPattern(format!(
                "Truncated AC literal hash table: need {table_end} bytes, have {}",
                buffer.len()
            )));
        }

        let patterns_start = usize::try_from(header.patterns_offset).map_err(|_| {
            ParaglobError::InvalidPattern("AC literal hash pattern offset is invalid".to_string())
        })?;
        if patterns_start < table_end {
            return Err(ParaglobError::InvalidPattern(format!(
                "AC literal hash pattern section overlaps table: offset {patterns_start}, table ends at {table_end}"
            )));
        }

        let patterns_size = usize::try_from(header.patterns_size).map_err(|_| {
            ParaglobError::InvalidPattern("AC literal hash pattern size is invalid".to_string())
        })?;
        if !patterns_size.is_multiple_of(mem::size_of::<u32>()) {
            return Err(ParaglobError::InvalidPattern(
                "AC literal hash pattern section is not a whole number of u32 values".to_string(),
            ));
        }
        let patterns_end = patterns_start.checked_add(patterns_size).ok_or_else(|| {
            ParaglobError::InvalidPattern(
                "AC literal hash pattern range overflows address space".to_string(),
            )
        })?;
        if patterns_end > buffer.len() {
            return Err(ParaglobError::InvalidPattern(format!(
                "Truncated AC literal hash pattern section: need {patterns_end} bytes, have {}",
                buffer.len()
            )));
        }

        Ok(Self {
            table: &buffer[table_start..table_end],
            patterns: &buffer[patterns_start..patterns_end],
            table_size,
        })
    }

    /// Visit pattern IDs for an AC literal ID without allocating.
    ///
    /// Returns `true` if the literal ID was found in the hash table, `false`
    /// otherwise.
    pub fn visit_pattern_ids(&self, literal_id: u32, mut visit: impl FnMut(u32)) -> bool {
        self.visit_pattern_ids_while(literal_id, |pattern_id| {
            visit(pattern_id);
            true
        })
    }

    /// Visit pattern IDs until the callback requests an early stop.
    ///
    /// This is used by bounded query paths so a pattern list is not scanned
    /// after its aggregate candidate cap has already been reached.
    pub(crate) fn visit_pattern_ids_while(
        &self,
        literal_id: u32,
        visit: impl FnMut(u32) -> bool,
    ) -> bool {
        let hash = compute_hash(literal_id);
        let mut slot = usize::try_from(hash).unwrap_or(0) % self.table_size;

        let entry_size = mem::size_of::<ACHashEntry>();

        for _ in 0..self.table_size {
            let entry_offset = slot * entry_size;
            let Some(entry_slice) = self.table.get(entry_offset..entry_offset + entry_size) else {
                return false;
            };
            let entry_literal_id = u32::from_le_bytes(
                entry_slice[..4]
                    .try_into()
                    .expect("validated hash entries contain four-byte fields"),
            );

            if entry_literal_id == EMPTY_SLOT {
                return false;
            }

            if entry_literal_id == literal_id {
                let patterns_offset = u32::from_le_bytes(
                    entry_slice[4..8]
                        .try_into()
                        .expect("validated hash entries contain four-byte fields"),
                );
                let pattern_count = u32::from_le_bytes(
                    entry_slice[8..12]
                        .try_into()
                        .expect("validated hash entries contain four-byte fields"),
                );
                return self.visit_pattern_list_while(
                    usize::try_from(patterns_offset).unwrap_or(usize::MAX),
                    usize::try_from(pattern_count).unwrap_or(usize::MAX),
                    visit,
                );
            }

            slot += 1;
            if slot == self.table_size {
                slot = 0;
            }
        }

        false
    }

    /// Visit pattern IDs while charging hash probes and list entries.
    ///
    /// `charge` is called once for every inspected hash slot and pattern-list
    /// item. Returning `false` from either callback stops immediately; a failed
    /// charge is reported separately from a visitor-requested stop.
    pub(crate) fn try_visit_pattern_ids_while(
        &self,
        literal_id: u32,
        mut charge: impl FnMut(usize) -> bool,
        mut visit: impl FnMut(u32) -> bool,
    ) -> Result<bool, ()> {
        let hash = compute_hash(literal_id);
        let mut slot = usize::try_from(hash).unwrap_or(0) % self.table_size;
        let entry_size = mem::size_of::<ACHashEntry>();

        for _ in 0..self.table_size {
            if !charge(1) {
                return Err(());
            }

            let entry_offset = slot * entry_size;
            let Some(entry_slice) = self.table.get(entry_offset..entry_offset + entry_size) else {
                return Ok(false);
            };
            let entry_literal_id = u32::from_le_bytes(
                entry_slice[..4]
                    .try_into()
                    .expect("validated hash entries contain four-byte fields"),
            );

            if entry_literal_id == EMPTY_SLOT {
                return Ok(false);
            }

            if entry_literal_id == literal_id {
                let patterns_offset = u32::from_le_bytes(
                    entry_slice[4..8]
                        .try_into()
                        .expect("validated hash entries contain four-byte fields"),
                );
                let pattern_count = u32::from_le_bytes(
                    entry_slice[8..12]
                        .try_into()
                        .expect("validated hash entries contain four-byte fields"),
                );
                let offset = usize::try_from(patterns_offset).unwrap_or(usize::MAX);
                let count = usize::try_from(pattern_count).unwrap_or(usize::MAX);
                let Some(bytes_needed) = count.checked_mul(mem::size_of::<u32>()) else {
                    return Ok(false);
                };
                let Some(pattern_bytes) = self
                    .patterns
                    .get(offset..)
                    .and_then(|tail| tail.get(..bytes_needed))
                else {
                    return Ok(false);
                };

                for pattern_bytes in pattern_bytes.chunks_exact(mem::size_of::<u32>()) {
                    if !charge(1) {
                        return Err(());
                    }
                    let pattern_id = u32::from_le_bytes(
                        pattern_bytes
                            .try_into()
                            .expect("slice length checked to be 4 bytes"),
                    );
                    if !visit(pattern_id) {
                        return Ok(false);
                    }
                }
                return Ok(true);
            }

            slot += 1;
            if slot == self.table_size {
                slot = 0;
            }
        }

        Ok(false)
    }

    /// Visit a pattern list from the patterns section without allocating.
    fn visit_pattern_list_while(
        &self,
        offset: usize,
        count: usize,
        mut visit: impl FnMut(u32) -> bool,
    ) -> bool {
        let Some(bytes_needed) = count.checked_mul(mem::size_of::<u32>()) else {
            return false;
        };
        let Some(pattern_bytes) = self
            .patterns
            .get(offset..)
            .and_then(|tail| tail.get(..bytes_needed))
        else {
            return false;
        };

        for pattern_bytes in pattern_bytes.chunks_exact(mem::size_of::<u32>()) {
            let pattern_id = u32::from_le_bytes(
                pattern_bytes
                    .try_into()
                    .expect("slice length checked to be 4 bytes"),
            );
            if !visit(pattern_id) {
                return false;
            }
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fallible_visitor_stops_scanning_pattern_list() {
        let mut builder = ACLiteralHashBuilder::new();
        builder.add_mapping(7, (0..100).collect());
        let buffer = builder.build();
        let hash = ACLiteralHash::from_buffer(&buffer).unwrap();
        let mut visited = Vec::new();

        let completed = hash.visit_pattern_ids_while(7, |pattern_id| {
            visited.push(pattern_id);
            visited.len() < 3
        });

        assert!(!completed);
        assert_eq!(visited, vec![0, 1, 2]);
    }

    #[test]
    fn work_charged_visitor_stops_when_budget_is_exhausted() {
        let mut builder = ACLiteralHashBuilder::new();
        builder.add_mapping(7, (0..100).collect());
        let buffer = builder.build();
        let hash = ACLiteralHash::from_buffer(&buffer).unwrap();
        let mut remaining = 2usize;
        let mut visited = Vec::new();

        let result = hash.try_visit_pattern_ids_while(
            7,
            |units| {
                let Some(next) = remaining.checked_sub(units) else {
                    return false;
                };
                remaining = next;
                true
            },
            |pattern_id| {
                visited.push(pattern_id);
                true
            },
        );

        assert_eq!(result, Err(()));
        assert_eq!(visited, vec![0]);
    }
}
