//! Offset-based binary format for zero-copy memory mapping
//!
//! This module defines the binary format used for serializing and loading
//! Paraglob pattern matchers. The format uses byte offsets instead of pointers,
//! allowing it to be memory-mapped and used directly without deserialization.
//!
//! # Format Overview
//!
//! The format consists of fixed-width `#[repr(C)]` records read from checked byte
//! ranges. Records are not `#[repr(packed)]`, and readers must not create
//! unaligned references by casting arbitrary bytes. Most header and pattern
//! offsets are relative to the PARAGLOB buffer; AC-local references are relative
//! to the serialized AC buffer, and [`PatternDataMapping::data_offset`] is
//! relative to the inline data section.
//!
//! # Layout
//!
//! ```text
//! [Header: ParaglobHeader (v5: 112 bytes)]
//! [AC Nodes: ACNodeHot array]
//! [AC Edges: ACEdge arrays (variable, referenced by nodes)]
//! [AC Pattern IDs: u32 arrays (variable, referenced by nodes)]
//! [Pattern Entries: PatternEntry array]
//! [Pattern Strings: null-terminated UTF-8]
//! [Meta-word mappings: MetaWordMapping array]
//! [Pattern reference arrays: u32 arrays]
//! [Single wildcards: SingleWildcard array]
//! [Glob Segments: GlobSegmentIndex + segment data (v5+)]
//! [Data section: optional (v2+)]
//! [Data mappings: optional (v2+)]
//! [AC Literal Mapping: optional (v3+)]
//! ```
//!
//! # Design Principles
//!
//! 1. **Alignment**: Typed tables begin at their documented alignment
//! 2. **Offsets**: Serialized references use documented `u32` offset bases (4GB limit)
//! 3. **Zero-copy**: Checked views can read serialized data directly from an mmap
//! 4. **Portability**: The format is little-endian; current readers do not byte-swap

use std::mem;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

/// Magic bytes identifying Paraglob binary format
pub const MAGIC: &[u8; 8] = b"PARAGLOB";

/// Current format version (v5: serialized glob segments for zero-copy loading)
pub const MATCHY_FORMAT_VERSION: u32 = 5;

/// Previous format version (v4: uses ACNodeHot for 50% memory reduction)
#[allow(dead_code)]
pub const MATCHY_FORMAT_VERSION_V4: u32 = 4;

/// Previous format version (v3: adds AC literal mapping for zero-copy loading)
#[allow(dead_code)] // Kept for reference and potential migration code
pub const MATCHY_FORMAT_VERSION_V3: u32 = 3;

/// Previous format version (v2: adds data section support)
#[allow(dead_code)] // Kept for reference and potential migration code
pub const MATCHY_FORMAT_VERSION_V2: u32 = 2;

/// Previous format version (v1: patterns only, no data)
#[allow(dead_code)] // Kept for reference and potential migration code
pub const MATCHY_FORMAT_VERSION_V1: u32 = 1;

/// Main header for serialized Paraglob database (112 bytes, 4-byte aligned)
///
/// This header appears at the start of every serialized Paraglob file.
/// All offsets are relative to the start of the buffer.
///
/// # Version History
/// - v1 (72 bytes): Original format, patterns only
/// - v2 (96 bytes): Adds data section support for pattern-associated data
/// - v3 (104 bytes): Adds AC literal mapping for O(1) zero-copy loading
/// - v4 (104 bytes): Uses ACNodeHot (20-byte) instead of ACNode (32-byte) - BREAKING
/// - v5 (112 bytes): Adds serialized glob segments for zero-copy loading
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct ParaglobHeader {
    /// Magic bytes: "PARAGLOB"
    pub magic: [u8; 8],

    /// Format version (currently 5)
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

    /// Endianness marker: 0x01=little-endian, 0x00=legacy little-endian.
    ///
    /// The format stores multi-byte values in little-endian order. `0x02` is
    /// reserved; current readers do not implement big-endian byte swapping.
    pub endianness: u8,

    /// Reserved for future use
    pub reserved: [u8; 3],

    // ===== v2 ADDITIONS (24 bytes) =====
    /// Offset to data section (0 = no data section)
    /// Points to MMDB-encoded data or other serialized data
    pub data_section_offset: u32,

    /// Size of data section in bytes (0 = no data)
    pub data_section_size: u32,

    /// Offset to pattern→data mapping table (0 = no mappings)
    /// Each mapping is a [`PatternDataMapping`] whose data offset is relative
    /// to the start of the data section.
    pub mapping_table_offset: u32,

    /// Number of pattern→data mappings
    /// Should equal pattern_count if all patterns have data
    pub mapping_count: u32,

    /// Data type flags:
    /// - Bit 0: inline data (1); the external-reference value (0) is reserved
    /// - Bit 1-31: reserved
    pub data_flags: u32,

    /// Reserved for future v2+ features
    pub reserved_v2: u32,

    // ===== v3 ADDITIONS (8 bytes) =====
    /// Offset to AC literal→pattern mapping table (0 = no mapping, requires reconstruction)
    /// Points to a serialized `HashMap<u32, Vec<u32>>` representation for direct loading
    /// Format: `[entry_count: u32]` followed by entries of:
    ///   `[literal_id: u32][pattern_count: u32][pattern_id: u32, ...]`
    pub ac_literal_map_offset: u32,

    /// Number of entries in AC literal mapping table
    /// 0 = v1/v2 file, requires reconstruct_literal_mapping()
    pub ac_literal_map_count: u32,

    // ===== v5 ADDITIONS (8 bytes) =====
    /// Offset to glob segment index (0 = no segments, use lazy parsing)
    /// Points to array of GlobSegmentIndex structs (one per pattern)
    pub glob_segments_offset: u32,

    /// Total size of glob segment data (index + segment structures + string data)
    pub glob_segments_size: u32,
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
    /// Lookup table for fast u8 -> StateKind conversion
    const LOOKUP: [Option<Self>; 256] = {
        let mut table = [None; 256];
        table[0] = Some(Self::Empty);
        table[1] = Some(Self::One);
        table[2] = Some(Self::Sparse);
        table[3] = Some(Self::Dense);
        table
    };

    /// Convert from u8 (for deserialization) - O(1) lookup
    #[inline(always)]
    #[must_use]
    pub const fn from_u8(value: u8) -> Option<Self> {
        Self::LOOKUP[value as usize]
    }
}

// Re-export ACNodeHot from matchy-ac
pub use matchy_ac::ACNodeHot;

/// AC Automaton node (32 bytes, 8-byte aligned) - DEPRECATED
///
/// Legacy 32-byte node structure. Kept for backward compatibility with old file formats.
/// New code should use ACNodeHot (20 bytes) for better cache performance.
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

/// Dense lookup table for states with many transitions (1024 bytes, 64-byte aligned)
///
/// Used by DENSE state encoding for O(1) transition lookup.
/// Each entry is a target node offset (0 = no transition).
///
/// **Cache-line alignment**: The 64-byte alignment ensures this structure starts on a
/// cache line boundary, preventing cache line splits and improving memory access performance
/// by 5-15% for dense state lookups. The structure size remains 1024 bytes; only the
/// placement in memory changes (average 32 bytes padding per instance).
#[repr(C, align(64))]
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
/// Maps a pattern ID to associated inline data. Introduced in v2; current v5
/// readers do not interpret the reserved external-reference encoding.
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct PatternDataMapping {
    /// Pattern ID this mapping applies to
    pub pattern_id: u32,

    /// Byte offset relative to the start of the header's data section
    pub data_offset: u32,

    /// Encoded data span in bytes, or zero for the legacy self-delimiting encoding
    pub data_size: u32,
}

/// Glob segment index entry (8 bytes, 4-byte aligned)
///
/// Points to the glob segment data for a specific pattern.
/// One entry exists for each pattern in the database.
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct GlobSegmentIndex {
    /// Offset to first GlobSegmentHeader for this pattern
    /// Relative to start of buffer
    pub first_segment_offset: u32,

    /// Number of segments in this pattern
    pub segment_count: u16,

    /// Reserved for alignment
    pub reserved: u16,
}

/// Glob segment header (12 bytes, 4-byte aligned)
///
/// Describes a single segment of a glob pattern (Literal, Star, Question, or CharClass).
/// Followed immediately by segment-specific data (string bytes or CharClassItem array).
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct GlobSegmentHeader {
    /// Segment type:
    /// - 0: Literal(String)
    /// - 1: Star
    /// - 2: Question
    /// - 3: CharClass
    pub segment_type: u8,

    /// Flags (for CharClass: bit 0 = negated)
    pub flags: u8,

    /// Reserved for alignment
    pub reserved: u16,

    /// Length of associated data in bytes
    /// - Literal: string byte length
    /// - Star/Question: 0
    /// - CharClass: number of CharClassItem entries * 12
    pub data_len: u32,

    /// Offset to associated data (relative to start of buffer)
    /// - Literal: offset to UTF-8 string bytes
    /// - Star/Question: unused (0)
    /// - CharClass: offset to CharClassItemEncoded array
    pub data_offset: u32,
}

/// Encoded character class item (12 bytes, 4-byte aligned)
///
/// Represents either a single character or a character range in a glob character class.
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct CharClassItemEncoded {
    /// Item type:
    /// - 0: Char(char1)
    /// - 1: Range(char1, char2)
    pub item_type: u8,

    /// Reserved for alignment
    pub reserved: [u8; 3],

    /// First character (or only character for Char variant)
    pub char1: u32,

    /// Second character (for Range variant only, 0 for Char)
    pub char2: u32,
}

// Compile-time size assertions to ensure struct layout
const _: () = assert!(mem::size_of::<ParaglobHeader>() == 112); // v5: 8-byte magic + 26 * u32 fields
const _: () = assert!(mem::size_of::<ACNodeHot>() == 20); // With one_target field: 4 + 4*4 = 20 bytes
const _: () = assert!(mem::size_of::<ACNode>() == 32); // Legacy: 2 per cache line
const _: () = assert!(mem::size_of::<ACEdge>() == 8);
const _: () = assert!(mem::size_of::<DenseLookup>() == 1024); // 256 * 4 bytes
const _: () = assert!(mem::align_of::<DenseLookup>() == 64); // Cache-line alignment for performance
const _: () = assert!(mem::size_of::<PatternEntry>() == 16);
const _: () = assert!(mem::size_of::<MetaWordMapping>() == 12);
const _: () = assert!(mem::size_of::<SingleWildcard>() == 8);
const _: () = assert!(mem::size_of::<PatternDataMapping>() == 12);
const _: () = assert!(mem::size_of::<GlobSegmentIndex>() == 8);
const _: () = assert!(mem::size_of::<GlobSegmentHeader>() == 12);
const _: () = assert!(mem::size_of::<CharClassItemEncoded>() == 12);

impl Default for ParaglobHeader {
    fn default() -> Self {
        Self::new()
    }
}

impl PatternDataMapping {
    /// Create a new pattern-to-data mapping
    #[must_use]
    pub fn new(pattern_id: u32, data_offset: u32, data_size: u32) -> Self {
        Self {
            pattern_id,
            data_offset,
            data_size,
        }
    }
}

impl ParaglobHeader {
    /// Create a new header using the current v5 magic and version
    #[must_use]
    pub fn new() -> Self {
        Self {
            magic: *MAGIC,
            version: MATCHY_FORMAT_VERSION,
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
            endianness: 0x01, // Little-endian marker (reserved for future use)
            reserved: [0; 3],
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
            // v5 fields
            glob_segments_offset: 0,
            glob_segments_size: 0,
        }
    }

    /// Validate header magic and version
    pub fn validate(&self) -> Result<(), &'static str> {
        if &self.magic != MAGIC {
            return Err("Invalid magic bytes");
        }
        if self.version != MATCHY_FORMAT_VERSION {
            return Err("Unsupported version - only v5 format supported");
        }
        Ok(())
    }

    /// Validate that every top-level section fits in the declared buffer.
    ///
    /// This is intentionally an O(section-count) envelope check. Query paths
    /// still validate node- and entry-level offsets before using them.
    pub fn validate_offsets(&self, buffer_len: usize) -> Result<(), &'static str> {
        let header_size = mem::size_of::<Self>();
        let declared_len = usize::try_from(self.total_buffer_size)
            .map_err(|_| "Declared buffer size is not addressable")?;
        if declared_len < header_size {
            return Err("Declared buffer is smaller than the Paraglob header");
        }
        if declared_len > buffer_len {
            return Err("Declared buffer size exceeds available bytes");
        }

        let section_fits = |start: u32, size: usize| -> bool {
            if size == 0 {
                return true;
            }
            let Ok(start) = usize::try_from(start) else {
                return false;
            };
            start >= header_size
                && start
                    .checked_add(size)
                    .is_some_and(|end| end <= declared_len)
        };
        let array_size = |count: u32, item_size: usize| -> Option<usize> {
            usize::try_from(count).ok()?.checked_mul(item_size)
        };

        let ac_size = usize::try_from(self.ac_edges_size)
            .map_err(|_| "AC automaton size is not addressable")?;
        if self.ac_node_count == 0 {
            if ac_size != 0 {
                return Err("AC automaton has bytes but no nodes");
            }
        } else {
            let nodes_size = array_size(self.ac_node_count, mem::size_of::<ACNodeHot>())
                .ok_or("AC node array size overflows address space")?;
            if ac_size < nodes_size {
                return Err("AC automaton is smaller than its declared node array");
            }
            if !section_fits(self.ac_nodes_offset, ac_size) {
                return Err("AC automaton section out of bounds");
            }
        }

        let patterns_size = array_size(self.pattern_count, mem::size_of::<PatternEntry>())
            .ok_or("Pattern entry array size overflows address space")?;
        if !section_fits(self.patterns_offset, patterns_size) {
            return Err("Pattern entries section out of bounds");
        }

        let pattern_strings_size = usize::try_from(self.pattern_strings_size)
            .map_err(|_| "Pattern strings size is not addressable")?;
        if !section_fits(self.pattern_strings_offset, pattern_strings_size) {
            return Err("Pattern strings section out of bounds");
        }

        let pattern_strings_end = usize::try_from(self.pattern_strings_offset)
            .ok()
            .and_then(|start| start.checked_add(pattern_strings_size))
            .ok_or("Pattern strings range overflows address space")?;
        let wildcard_start = pattern_strings_end
            .checked_add(7)
            .map(|end| end & !7)
            .ok_or("Wildcard section alignment overflows address space")?;
        let wildcard_size = array_size(self.wildcard_count, mem::size_of::<SingleWildcard>())
            .ok_or("Wildcard entry array size overflows address space")?;
        if wildcard_size > 0
            && (wildcard_start < header_size
                || wildcard_start
                    .checked_add(wildcard_size)
                    .is_none_or(|end| end > declared_len))
        {
            return Err("Wildcard section out of bounds");
        }

        let meta_word_mappings_size = array_size(
            self.meta_word_mapping_count,
            mem::size_of::<MetaWordMapping>(),
        )
        .ok_or("Meta-word mapping array size overflows address space")?;
        if !section_fits(self.meta_word_mappings_offset, meta_word_mappings_size) {
            return Err("Meta-word mappings section out of bounds");
        }

        let data_size = usize::try_from(self.data_section_size)
            .map_err(|_| "Data section size is not addressable")?;
        if !section_fits(self.data_section_offset, data_size) {
            return Err("Data section out of bounds");
        }

        let mapping_size = array_size(self.mapping_count, mem::size_of::<PatternDataMapping>())
            .ok_or("Pattern data mapping array size overflows address space")?;
        if !section_fits(self.mapping_table_offset, mapping_size) {
            return Err("Pattern data mapping section out of bounds");
        }

        if self.has_ac_literal_mapping()
            && !section_fits(
                self.ac_literal_map_offset,
                mem::size_of::<crate::literal_hash::ACLiteralHashHeader>(),
            )
        {
            return Err("AC literal map header out of bounds");
        }

        let glob_segments_size = usize::try_from(self.glob_segments_size)
            .map_err(|_| "Glob segments size is not addressable")?;
        let glob_index_size = array_size(self.pattern_count, mem::size_of::<GlobSegmentIndex>())
            .ok_or("Glob segment index size overflows address space")?;
        if glob_segments_size < glob_index_size {
            return Err("Glob segment section is smaller than its pattern index");
        }
        if !section_fits(self.glob_segments_offset, glob_segments_size) {
            return Err("Glob segments section out of bounds");
        }

        Ok(())
    }

    /// Check if this file has a data section
    #[must_use]
    pub fn has_data_section(&self) -> bool {
        self.data_section_size > 0
    }

    /// Check if this file has a pre-built AC literal mapping (v3+)
    #[must_use]
    pub fn has_ac_literal_mapping(&self) -> bool {
        self.ac_literal_map_count > 0 && self.ac_literal_map_offset > 0
    }

    /// Check if data is inline (true) or external references (false)
    #[allow(dead_code)] // Reserved for future use
    #[must_use]
    pub fn has_inline_data(&self) -> bool {
        (self.data_flags & 0x1) != 0
    }

    /// Check if this file has pre-built glob segments (v5+)
    #[allow(dead_code)] // Reserved for v5 format implementation
    #[must_use]
    pub fn has_glob_segments(&self) -> bool {
        self.glob_segments_size > 0 && self.glob_segments_offset > 0
    }
}

impl ACNode {
    /// Create a new node with default EMPTY encoding
    #[allow(dead_code)]
    #[must_use]
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
    #[allow(dead_code)] // Used by builder code in other crates
    #[must_use]
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
    #[must_use]
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
#[allow(dead_code)]
#[must_use]
pub unsafe fn read_struct<T: Copy>(buffer: &[u8], offset: usize) -> T {
    debug_assert!(offset + mem::size_of::<T>() <= buffer.len());
    let ptr = buffer.as_ptr().add(offset).cast::<T>();
    ptr.read_unaligned()
}

/// Helper to safely read a slice of structs from a byte buffer
///
/// # Safety
///
/// Caller must ensure:
/// - offset + `size_of::<T>`() * count <= buffer.len()
/// - Buffer contains valid T values
#[allow(dead_code)]
#[must_use]
pub unsafe fn read_struct_slice<T: Copy>(buffer: &[u8], offset: usize, count: usize) -> &[T] {
    debug_assert!(offset + mem::size_of::<T>() * count <= buffer.len());
    let ptr = buffer.as_ptr().add(offset).cast::<T>();
    std::slice::from_raw_parts(ptr, count)
}

/// Helper to read a null-terminated UTF-8 string from buffer
///
/// Returns error if offset is out of bounds, string is not null-terminated,
/// or bytes are not valid UTF-8.
pub fn read_cstring(buffer: &[u8], offset: usize) -> Result<&str, &'static str> {
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
#[allow(dead_code)]
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
#[allow(dead_code)]
#[must_use]
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
#[allow(dead_code)]
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
        assert_eq!(mem::size_of::<ParaglobHeader>(), 112); // v5: 8-byte magic + 26 * u32
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
        assert_eq!(header.version, MATCHY_FORMAT_VERSION);

        header.magic = *b"INVALID!";
        assert!(header.validate().is_err());

        header.magic = *MAGIC;
        header.version = 999;
        assert!(header.validate().is_err());

        // Only v4 is valid
        header.version = MATCHY_FORMAT_VERSION_V1;
        assert!(header.validate().is_err());

        header.version = MATCHY_FORMAT_VERSION_V2;
        assert!(header.validate().is_err());

        header.version = MATCHY_FORMAT_VERSION_V3;
        assert!(header.validate().is_err());

        header.version = MATCHY_FORMAT_VERSION;
        assert!(header.validate().is_ok());
    }

    #[test]
    fn test_wildcard_section_cannot_overlap_header() {
        let header_size = mem::size_of::<ParaglobHeader>();
        let wildcard_size = mem::size_of::<SingleWildcard>();
        let mut header = ParaglobHeader::new();
        header.total_buffer_size = u32::try_from(header_size + wildcard_size).unwrap();
        header.wildcard_count = 1;

        // An empty string section used to make the derived wildcard offset zero,
        // allowing the file header to be interpreted as wildcard records.
        header.pattern_strings_offset = 0;
        assert_eq!(
            header.validate_offsets(header_size + wildcard_size),
            Err("Wildcard section out of bounds")
        );

        header.pattern_strings_offset = u32::try_from(header_size).unwrap();
        assert!(header.validate_offsets(header_size + wildcard_size).is_ok());
    }

    #[test]
    fn test_v3_features() {
        let mut header = ParaglobHeader::new();
        assert_eq!(header.version, MATCHY_FORMAT_VERSION);
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
        let mut buffer = vec![0u8; 112]; // v5 header size
        let header = ParaglobHeader::new();

        // Serialize as bytes because Vec<u8> does not guarantee the alignment
        // required for writing a ParaglobHeader through a typed pointer.
        buffer.copy_from_slice(header.as_bytes());

        // Read it back
        // SAFETY: `read_struct` performs an unaligned read from a complete header.
        let read_header: ParaglobHeader = unsafe { read_struct(&buffer, 0) };
        assert_eq!(read_header.magic, *MAGIC);
        assert_eq!(read_header.version, MATCHY_FORMAT_VERSION);
        assert_eq!(read_header.version, 5);
    }

    #[test]
    fn test_read_cstring() {
        let buffer = b"hello\0world\0\0";

        let s1 = read_cstring(buffer, 0).unwrap();
        assert_eq!(s1, "hello");

        let s2 = read_cstring(buffer, 6).unwrap();
        assert_eq!(s2, "world");

        let s3 = read_cstring(buffer, 12).unwrap();
        assert_eq!(s3, "");
    }
}
