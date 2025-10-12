//! Offset-based binary format for zero-copy memory mapping
//!
//! This module defines the binary format used for serializing and loading
//! Paraglob pattern matchers. The format uses byte offsets instead of pointers,
//! allowing it to be memory-mapped and used directly without deserialization.
//!
//! # Format Overview
//!
//! The format consists of C-compatible packed structs that can be cast directly
//! from bytes. All references use byte offsets from the start of the buffer.
//!
//! # Layout
//!
//! ```text
//! [Header: ParaglobHeader (v3: 104 bytes)]
//! [AC Nodes: ACNode array]
//! [AC Edges: ACEdge arrays (variable, referenced by nodes)]
//! [AC Pattern IDs: u32 arrays (variable, referenced by nodes)]
//! [Pattern Entries: PatternEntry array]
//! [Pattern Strings: null-terminated UTF-8]
//! [Meta-word mappings: MetaWordMapping array]
//! [Pattern reference arrays: u32 arrays]
//! [Single wildcards: SingleWildcard array]
//! [Data section: optional (v2+)]
//! [Data mappings: optional (v2+)]
//! [AC Literal Mapping: optional (v3+)]
//! ```
//!
//! # Design Principles
//!
//! 1. **Alignment**: All structs are properly aligned for direct casting
//! 2. **Offsets**: All references use u32 byte offsets (4GB limit)
//! 3. **Zero-copy**: Can read directly from mmap without parsing
//! 4. **Portability**: Little-endian u32/u8 only (standard on x86/ARM)

use std::mem;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

/// Magic bytes identifying Paraglob binary format
pub const MAGIC: &[u8; 8] = b"PARAGLOB";

/// Current format version (v3: adds AC literal mapping for zero-copy loading)
pub const VERSION: u32 = 3;

/// Previous format version (v2: adds data section support)
pub const VERSION_V2: u32 = 2;

/// Previous format version (v1: patterns only, no data)
pub const VERSION_V1: u32 = 1;

/// Main header for serialized Paraglob database (104 bytes, 4-byte aligned)
///
/// This header appears at the start of every serialized Paraglob file.
/// All offsets are relative to the start of the buffer.
///
/// # Version History
/// - v1 (72 bytes): Original format, patterns only
/// - v2 (96 bytes): Adds data section support for pattern-associated data
/// - v3 (104 bytes): Adds AC literal mapping for O(1) zero-copy loading
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct ParaglobHeader {
    /// Magic bytes: "PARAGLOB"
    pub magic: [u8; 8],

    /// Format version (currently 2)
    pub version: u32,

    /// Match mode: 0=CaseSensitive, 1=CaseInsensitive
    pub match_mode: u32,

    // AC Automaton section
    /// Number of nodes in the AC trie
    pub ac_node_count: u32,

    /// Offset to first AC node
    pub ac_nodes_offset: u32,

    /// Total size of AC edges data
    pub ac_edges_size: u32,

    /// Total size of AC pattern ID arrays
    pub ac_patterns_size: u32,

    // Pattern section
    /// Total number of original glob patterns
    pub pattern_count: u32,

    /// Offset to pattern entry array
    pub patterns_offset: u32,

    /// Offset to pattern strings area
    pub pattern_strings_offset: u32,

    /// Total size of pattern strings
    pub pattern_strings_size: u32,

    // Meta-word mapping section
    /// Number of meta-word to pattern mappings
    pub meta_word_mapping_count: u32,

    /// Offset to meta-word mapping array
    pub meta_word_mappings_offset: u32,

    /// Total size of pattern reference arrays
    pub pattern_refs_size: u32,

    /// Number of pure wildcard patterns (no literals)
    pub wildcard_count: u32,

    /// Total size of the entire serialized buffer (bytes)
    pub total_buffer_size: u32,

    /// Reserved for future use
    pub reserved: u32,

    // ===== v2 ADDITIONS (24 bytes) =====
    /// Offset to data section (0 = no data section)
    /// Points to MMDB-encoded data or other serialized data
    pub data_section_offset: u32,

    /// Size of data section in bytes (0 = no data)
    pub data_section_size: u32,

    /// Offset to pattern→data mapping table (0 = no mappings)
    /// Each mapping is a PatternDataMapping struct
    pub mapping_table_offset: u32,

    /// Number of pattern→data mappings
    /// Should equal pattern_count if all patterns have data
    pub mapping_count: u32,

    /// Data type flags:
    /// - Bit 0: inline data (1) vs external references (0)
    /// - Bit 1-31: reserved
    pub data_flags: u32,

    /// Reserved for future v2+ features
    pub reserved_v2: u32,

    // ===== v3 ADDITIONS (8 bytes) =====
    /// Offset to AC literal→pattern mapping table (0 = no mapping, requires reconstruction)
    /// Points to serialized `HashMap<u32, Vec<u32>>` for instant loading
    /// Format: `[entry_count: u32]` followed by entries of:
    ///   `[literal_id: u32][pattern_count: u32][pattern_id: u32, ...]`
    pub ac_literal_map_offset: u32,

    /// Number of entries in AC literal mapping table
    /// 0 = v1/v2 file, requires reconstruct_literal_mapping()
    pub ac_literal_map_count: u32,
}

/// State encoding type for AC automaton nodes
///
/// Determines how transitions are stored and looked up for optimal performance.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateKind {
    /// No transitions (terminal state only)
    Empty = 0,
    /// Single transition - stored inline in node (75-80% of states)
    One = 1,
    /// 2-8 transitions - sparse edge array (10-15% of states)
    Sparse = 2,
    /// 9+ transitions - dense lookup table (2-5% of states)
    Dense = 3,
}

impl StateKind {
    /// Convert from u8 (for deserialization)
    #[inline]
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(StateKind::Empty),
            1 => Some(StateKind::One),
            2 => Some(StateKind::Sparse),
            3 => Some(StateKind::Dense),
            _ => None,
        }
    }
}

/// AC Automaton node (32 bytes, 8-byte aligned)
///
/// Represents a single node in the Aho-Corasick trie with state-specific encoding.
/// All child references are stored as offsets to allow zero-copy loading.
///
/// # State Encoding
///
/// The node uses different encodings based on transition count:
/// - **Empty** (0 transitions): No additional data needed
/// - **One** (1 transition): Character and target stored inline (no indirection!)
/// - **Sparse** (2-8 transitions): Offset to edge array, linear search
/// - **Dense** (9+ transitions): Offset to 256-entry lookup table, O(1) access
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct ACNode {
    /// Unique node ID
    pub node_id: u32,

    /// Offset to failure link node (0 = root)
    pub failure_offset: u32,

    /// State encoding type (StateKind enum)
    pub state_kind: u8,

    /// Depth from root node
    pub depth: u8,

    /// Is this a terminal/final state? (1=yes, 0=no)
    pub is_final: u8,

    /// Reserved for future flags
    pub reserved_flags: u8,

    /// ONE encoding: character for single transition
    pub one_char: u8,

    /// Reserved for alignment
    pub reserved_one: [u8; 3],

    /// SPARSE/DENSE encoding: offset-based lookup (4 bytes)
    /// - SPARSE: offset to ACEdge array
    /// - DENSE: offset to DenseLookup table
    /// - ONE: target offset for single transition
    pub edges_offset: u32,

    /// Number of edges (SPARSE/DENSE states only)
    pub edge_count: u16,

    /// Reserved for alignment
    pub reserved_edge: u16,

    /// Offset to pattern ID array
    pub patterns_offset: u32,

    /// Number of pattern IDs at this node
    pub pattern_count: u16,

    /// Reserved for alignment
    pub reserved_pattern: u16,
}
// Total: node_id(4) + failure_offset(4) + state_kind/depth/is_final/reserved(4)
//        + one_char/reserved_one(4) + edges_offset(4) + edge_count/reserved(4)
//        + patterns_offset(4) + pattern_count/reserved(4)
//        = 4+4+4+4+4+4+4+4 = 32 bytes ✓

/// AC Automaton edge (8 bytes, 4-byte aligned)
///
/// Represents a transition from one node to another on a specific character.
/// Used by SPARSE state encoding.
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct ACEdge {
    /// Input character (0-255)
    pub character: u8,

    /// Reserved for alignment
    pub reserved: [u8; 3],

    /// Offset to target node
    pub target_offset: u32,
}

/// Dense lookup table for states with many transitions (1024 bytes, 4-byte aligned)
///
/// Used by DENSE state encoding for O(1) transition lookup.
/// Each entry is a target node offset (0 = no transition).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct DenseLookup {
    /// Target offsets indexed by character (0-255)
    /// 0 means no transition for that character
    pub targets: [u32; 256],
}

/// Pattern entry (16 bytes, 8-byte aligned)
///
/// Metadata about a single glob pattern in the database.
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct PatternEntry {
    /// Pattern ID (matches IDs used in AC automaton)
    pub pattern_id: u32,

    /// Pattern type: 0=Literal, 1=Glob
    pub pattern_type: u8,

    /// Reserved for alignment
    pub reserved: [u8; 3],

    /// Offset to pattern string (null-terminated UTF-8)
    pub pattern_string_offset: u32,

    /// Length of pattern string (not including null)
    pub pattern_string_length: u32,
}

/// Meta-word to pattern mapping (12 bytes, 4-byte aligned)
///
/// Maps a meta-word (literal segment from AC automaton) to all patterns
/// that contain it. Used for hybrid AC + glob matching.
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct MetaWordMapping {
    /// Meta-word string offset
    pub meta_word_offset: u32,

    /// Offset to array of pattern IDs (u32[])
    pub pattern_ids_offset: u32,

    /// Number of patterns containing this meta-word
    pub pattern_count: u32,
}

/// Single wildcard entry (8 bytes, 4-byte aligned)
///
/// Represents a pattern with only wildcards (*, ?) and no literals.
/// These must be checked separately since they don't have AC matches.
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct SingleWildcard {
    /// Pattern ID
    pub pattern_id: u32,

    /// Offset to pattern string
    pub pattern_string_offset: u32,
}

/// Pattern-to-data mapping entry (12 bytes, 4-byte aligned)
///
/// Maps a pattern ID to associated data. Used in v2 format.
/// The data can be inline (stored in data section) or external
/// (reference to MMDB data section).
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct PatternDataMapping {
    /// Pattern ID this mapping applies to
    pub pattern_id: u32,

    /// Offset to data in data section (or external offset)
    /// Interpretation depends on data_flags in header
    pub data_offset: u32,

    /// Size of data in bytes (0 = use data section's size encoding)
    pub data_size: u32,
}

// Compile-time size assertions to ensure struct layout
const _: () = assert!(mem::size_of::<ParaglobHeader>() == 104); // v3: 8-byte magic + 24 * u32 fields
const _: () = assert!(mem::size_of::<ACNode>() == 32);
const _: () = assert!(mem::size_of::<ACEdge>() == 8);
const _: () = assert!(mem::size_of::<DenseLookup>() == 1024); // 256 * 4 bytes
const _: () = assert!(mem::size_of::<PatternEntry>() == 16);
const _: () = assert!(mem::size_of::<MetaWordMapping>() == 12);
const _: () = assert!(mem::size_of::<SingleWildcard>() == 8);
const _: () = assert!(mem::size_of::<PatternDataMapping>() == 12);

impl Default for ParaglobHeader {
    fn default() -> Self {
        Self::new()
    }
}

impl PatternDataMapping {
    /// Create a new pattern-to-data mapping
    pub fn new(pattern_id: u32, data_offset: u32, data_size: u32) -> Self {
        Self {
            pattern_id,
            data_offset,
            data_size,
        }
    }
}

impl ParaglobHeader {
    /// Create a new v3 header with magic and version
    pub fn new() -> Self {
        Self {
            magic: *MAGIC,
            version: VERSION,
            match_mode: 0,
            ac_node_count: 0,
            ac_nodes_offset: 0,
            ac_edges_size: 0,
            ac_patterns_size: 0,
            pattern_count: 0,
            patterns_offset: 0,
            pattern_strings_offset: 0,
            pattern_strings_size: 0,
            meta_word_mapping_count: 0,
            meta_word_mappings_offset: 0,
            pattern_refs_size: 0,
            wildcard_count: 0,
            total_buffer_size: 0,
            reserved: 0,
            // v2 fields
            data_section_offset: 0,
            data_section_size: 0,
            mapping_table_offset: 0,
            mapping_count: 0,
            data_flags: 0,
            reserved_v2: 0,
            // v3 fields
            ac_literal_map_offset: 0,
            ac_literal_map_count: 0,
        }
    }

    /// Validate header magic and version
    pub fn validate(&self) -> Result<(), &'static str> {
        if &self.magic != MAGIC {
            return Err("Invalid magic bytes");
        }
        if self.version != VERSION {
            return Err("Unsupported version - only v3 format supported");
        }
        Ok(())
    }

    /// Validate that all header offsets are within buffer bounds
    pub fn validate_offsets(&self, buffer_len: usize) -> Result<(), &'static str> {
        // Validate AC literal mapping offset if present
        if self.has_ac_literal_mapping() {
            let offset = self.ac_literal_map_offset as usize;
            if offset >= buffer_len {
                return Err("AC literal map offset out of bounds");
            }
        }

        // Validate data section if present
        if self.has_data_section() {
            let start = self.data_section_offset as usize;
            let size = self.data_section_size as usize;
            if start.checked_add(size).is_none_or(|end| end > buffer_len) {
                return Err("Data section out of bounds");
            }
        }

        // Validate mapping table if present
        if self.mapping_count > 0 {
            let offset = self.mapping_table_offset as usize;
            if offset >= buffer_len {
                return Err("Mapping table offset out of bounds");
            }
        }

        // Validate AC nodes section
        if self.ac_node_count > 0 {
            let offset = self.ac_nodes_offset as usize;
            let size = (self.ac_node_count as usize) * mem::size_of::<ACNode>();
            if offset.checked_add(size).is_none_or(|end| end > buffer_len) {
                return Err("AC nodes section out of bounds");
            }
        }

        // Validate patterns section
        if self.pattern_count > 0 {
            let offset = self.patterns_offset as usize;
            let size = (self.pattern_count as usize) * mem::size_of::<PatternEntry>();
            if offset.checked_add(size).is_none_or(|end| end > buffer_len) {
                return Err("Patterns section out of bounds");
            }
        }

        // Validate pattern strings section
        if self.pattern_strings_size > 0 {
            let start = self.pattern_strings_offset as usize;
            let size = self.pattern_strings_size as usize;
            if start.checked_add(size).is_none_or(|end| end > buffer_len) {
                return Err("Pattern strings section out of bounds");
            }
        }

        // Validate meta-word mappings
        if self.meta_word_mapping_count > 0 {
            let offset = self.meta_word_mappings_offset as usize;
            let size = (self.meta_word_mapping_count as usize) * mem::size_of::<MetaWordMapping>();
            if offset.checked_add(size).is_none_or(|end| end > buffer_len) {
                return Err("Meta-word mappings section out of bounds");
            }
        }

        Ok(())
    }

    /// Check if this file has a data section
    pub fn has_data_section(&self) -> bool {
        self.data_section_size > 0
    }

    /// Check if this file has a pre-built AC literal mapping (v3+)
    pub fn has_ac_literal_mapping(&self) -> bool {
        self.ac_literal_map_count > 0 && self.ac_literal_map_offset > 0
    }

    /// Check if data is inline (true) or external references (false)
    pub fn has_inline_data(&self) -> bool {
        (self.data_flags & 0x1) != 0
    }
}

impl ACNode {
    /// Create a new node with default EMPTY encoding
    pub fn new(node_id: u32, depth: u8) -> Self {
        Self {
            node_id,
            failure_offset: 0,
            state_kind: StateKind::Empty as u8,
            depth,
            is_final: 0,
            reserved_flags: 0,
            one_char: 0,
            reserved_one: [0; 3],
            edges_offset: 0,
            edge_count: 0,
            reserved_edge: 0,
            patterns_offset: 0,
            pattern_count: 0,
            reserved_pattern: 0,
        }
    }
}

impl ACEdge {
    /// Create a new edge
    pub fn new(character: u8, target_offset: u32) -> Self {
        Self {
            character,
            reserved: [0; 3],
            target_offset,
        }
    }
}

impl PatternEntry {
    /// Create a new pattern entry
    pub fn new(pattern_id: u32, pattern_type: u8) -> Self {
        Self {
            pattern_id,
            pattern_type,
            reserved: [0; 3],
            pattern_string_offset: 0,
            pattern_string_length: 0,
        }
    }
}

/// Helper to safely read a struct from a byte buffer at an offset
///
/// # Safety
///
/// Caller must ensure:
/// - offset + `size_of::<T>`() <= buffer.len()
/// - Buffer is properly aligned for T
/// - Bytes represent a valid T
pub unsafe fn read_struct<T: Copy>(buffer: &[u8], offset: usize) -> T {
    debug_assert!(offset + mem::size_of::<T>() <= buffer.len());
    let ptr = buffer.as_ptr().add(offset) as *const T;
    ptr.read_unaligned()
}

/// Helper to safely read a slice of structs from a byte buffer
///
/// # Safety
///
/// Caller must ensure:
/// - offset + `size_of::<T>`() * count <= buffer.len()
/// - Buffer contains valid T values
pub unsafe fn read_struct_slice<T: Copy>(buffer: &[u8], offset: usize, count: usize) -> &[T] {
    debug_assert!(offset + mem::size_of::<T>() * count <= buffer.len());
    let ptr = buffer.as_ptr().add(offset) as *const T;
    std::slice::from_raw_parts(ptr, count)
}

/// Helper to read a null-terminated UTF-8 string from buffer
///
/// # Safety
///
/// Caller must ensure:
/// - offset < buffer.len()
/// - String is null-terminated
/// - Bytes are valid UTF-8
pub unsafe fn read_cstring(buffer: &[u8], offset: usize) -> Result<&str, &'static str> {
    if offset >= buffer.len() {
        return Err("Offset out of bounds");
    }

    // Find null terminator
    let start = offset;
    let mut end = offset;
    while end < buffer.len() && buffer[end] != 0 {
        end += 1;
    }

    if end >= buffer.len() {
        return Err("String not null-terminated");
    }

    // Convert to str
    std::str::from_utf8(&buffer[start..end]).map_err(|_| "Invalid UTF-8")
}

/// Helper to read a UTF-8 string from buffer with known length (FAST PATH)
///
/// This is much faster than `read_cstring` because it doesn't scan for the null terminator.
/// Use this when you have the string length from PatternEntry.pattern_string_length.
///
/// # Safety
///
/// Caller must ensure:
/// - offset + length <= buffer.len()
/// - Bytes are valid UTF-8
/// - Length is correct
#[inline]
pub unsafe fn read_cstring_with_len(
    buffer: &[u8],
    offset: usize,
    length: usize,
) -> Result<&str, &'static str> {
    if offset + length > buffer.len() {
        return Err("Offset + length out of bounds");
    }

    // Direct slice without scanning for null terminator
    std::str::from_utf8(&buffer[offset..offset + length]).map_err(|_| "Invalid UTF-8")
}

/// Helper to read a UTF-8 string from buffer with known length (ULTRA-FAST PATH - NO UTF-8 VALIDATION)
///
/// This is the fastest option - it skips null terminator scanning AND UTF-8 validation.
/// Only use this in hot query paths where you KNOW the strings are valid UTF-8 (from build time).
///
/// # Safety
///
/// Caller must ensure:
/// - offset + length <= buffer.len()
/// - Bytes are DEFINITELY valid UTF-8 (undefined behavior if not!)
/// - Length is correct
#[inline]
pub unsafe fn read_str_unchecked(buffer: &[u8], offset: usize, length: usize) -> &str {
    debug_assert!(offset + length <= buffer.len());
    // SAFETY: Caller guarantees valid UTF-8
    std::str::from_utf8_unchecked(&buffer[offset..offset + length])
}

/// Helper to read a UTF-8 string from buffer with known length (SAFE PATH - validates UTF-8)
///
/// This validates UTF-8 on every read. Use for untrusted databases.
/// Slower than `read_str_unchecked` but prevents undefined behavior.
///
/// # Safety
///
/// Caller must ensure:
/// - offset + length <= buffer.len()
/// - Length is correct
///
/// UTF-8 validation is performed, so invalid UTF-8 returns an error.
#[inline]
pub unsafe fn read_str_checked(
    buffer: &[u8],
    offset: usize,
    length: usize,
) -> Result<&str, &'static str> {
    if offset + length > buffer.len() {
        return Err("Offset + length out of bounds");
    }
    std::str::from_utf8(&buffer[offset..offset + length]).map_err(|_| "Invalid UTF-8")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_size() {
        assert_eq!(mem::size_of::<ParaglobHeader>(), 104); // v3: 8-byte magic + 24 * u32
        assert_eq!(mem::align_of::<ParaglobHeader>(), 4);
    }

    #[test]
    fn test_node_size() {
        assert_eq!(mem::size_of::<ACNode>(), 32);
        assert_eq!(mem::align_of::<ACNode>(), 4);
    }

    #[test]
    fn test_edge_size() {
        assert_eq!(mem::size_of::<ACEdge>(), 8);
        assert_eq!(mem::align_of::<ACEdge>(), 4);
    }

    #[test]
    fn test_pattern_entry_size() {
        assert_eq!(mem::size_of::<PatternEntry>(), 16);
        assert_eq!(mem::align_of::<PatternEntry>(), 4);
    }

    #[test]
    fn test_header_validation() {
        let mut header = ParaglobHeader::new();
        assert!(header.validate().is_ok());
        assert_eq!(header.version, VERSION);

        header.magic = *b"INVALID!";
        assert!(header.validate().is_err());

        header.magic = *MAGIC;
        header.version = 999;
        assert!(header.validate().is_err());

        // Only v3 is valid
        header.version = VERSION_V1;
        assert!(header.validate().is_err());

        header.version = VERSION_V2;
        assert!(header.validate().is_err());

        header.version = VERSION;
        assert!(header.validate().is_ok());
    }

    #[test]
    fn test_v3_features() {
        let mut header = ParaglobHeader::new();
        assert_eq!(header.version, VERSION);
        assert!(!header.has_data_section());
        assert!(!header.has_inline_data());
        assert!(!header.has_ac_literal_mapping());

        // Add data section
        header.data_section_size = 1024;
        assert!(header.has_data_section());

        // Set inline data flag
        header.data_flags = 0x1;
        assert!(header.has_inline_data());

        // Add AC literal mapping
        header.ac_literal_map_offset = 1000;
        header.ac_literal_map_count = 50;
        assert!(header.has_ac_literal_mapping());
    }

    #[test]
    fn test_read_struct() {
        let mut buffer = vec![0u8; 104]; // v3 header size
        let header = ParaglobHeader::new();

        // Write header to buffer
        unsafe {
            let ptr = buffer.as_mut_ptr() as *mut ParaglobHeader;
            ptr.write(header);
        }

        // Read it back
        let read_header: ParaglobHeader = unsafe { read_struct(&buffer, 0) };
        assert_eq!(read_header.magic, *MAGIC);
        assert_eq!(read_header.version, VERSION);
        assert_eq!(read_header.version, 3);
    }

    #[test]
    fn test_read_cstring() {
        let buffer = b"hello\0world\0\0";

        unsafe {
            let s1 = read_cstring(buffer, 0).unwrap();
            assert_eq!(s1, "hello");

            let s2 = read_cstring(buffer, 6).unwrap();
            assert_eq!(s2, "world");

            let s3 = read_cstring(buffer, 12).unwrap();
            assert_eq!(s3, "");
        }
    }
}
