//! Binary format structures for paraglob
//!
//! This module defines the on-disk binary format structures for both the
//! Aho-Corasick automaton and the full Paraglob database. All structures
//! use `#[repr(C)]` to ensure exact C/C++ compatibility for memory-mapped
//! file operations.
//!
//! # Binary Format Overview
//!
//! The binary format supports two levels:
//!
//! ## 1. OffsetAc Format (Basic Aho-Corasick)
//! - Magic: "MMAC" (Memory-Mapped Aho-Corasick)
//! - Header: `OffsetAcHeader` (32 bytes)
//! - Nodes: Array of `OffsetAcNode` (24 bytes each)
//! - Edges: Arrays of `OffsetAcEdge` (8 bytes each)
//! - Meta-words: Null-terminated strings with `OffsetMetaWordRef`
//!
//! ## 2. OffsetParaglob Format (Full Glob Matching)
//! - Magic: "MMPG" (Memory-Mapped Paraglob)
//! - Extends OffsetAc with additional metadata
//! - Header: `OffsetParaglobHeader` (64 bytes)
//! - Includes all OffsetAc data plus:
//!   - Original glob pattern strings
//!   - Meta-word to pattern mappings
//!   - Single wildcard patterns
//!
//! # Memory Layout
//!
//! All offsets are relative to the start of the file/buffer.
//! All structures are properly aligned (4 or 8 byte boundaries).
//! Offsets of 0 indicate "null" (no data).
//!
//! # Binary Compatibility
//!
//! These structures must maintain exact binary compatibility with the C++
//! implementation. The magic bytes "MMAC" and "MMPG" are historical identifiers
//! indicating "Memory-Mapped" formats, though the memory-mapping is an
//! implementation detail.
//!
//! # Safety
//!
//! When working with these structures from memory-mapped files:
//! - Always validate offsets are within buffer bounds
//! - Check alignment requirements before casting
//! - Verify magic bytes and version numbers
//! - Use the validation module for safety checks

use std::fmt;

/// Magic bytes for OffsetAc format: "MMAC" (Memory-Mapped Aho-Corasick)
pub const MAGIC_AC: [u8; 4] = *b"MMAC";

/// Magic bytes for OffsetParaglob format: "MMPG" (Memory-Mapped Paraglob)
pub const MAGIC_PARAGLOB: [u8; 4] = *b"MMPG";

/// Current binary format version
pub const FORMAT_VERSION: u32 = 1;

// ============================================================================
// OffsetAc Structures (Basic Aho-Corasick)
// ============================================================================

/// File header for OffsetAc format (32 bytes)
///
/// This is the main header for the Aho-Corasick automaton binary format.
/// All offsets are relative to the start of the file/buffer.
///
/// Magic bytes: "MMAC" identifies this as an OffsetAc format file.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct OffsetAcHeader {
    /// Magic bytes: "MMAC" (0x4D4D4143)
    pub magic: [u8; 4],
    /// Format version number
    pub version: u32,
    /// Total number of nodes in the automaton
    pub node_count: u32,
    /// Offset to the root node (typically 32, right after header)
    pub root_node_offset: u32,
    /// Total number of meta-words extracted from patterns
    pub meta_word_count: u32,
    /// Offset to the meta-word string table
    pub meta_word_table_offset: u32,
    /// Total size of the entire buffer
    pub total_buffer_size: u32,
    /// Reserved for future use (should be 0)
    pub reserved: u32,
}

/// Node in the Aho-Corasick automaton (24 bytes, 8-byte aligned)
///
/// Each node represents a state in the automaton. Nodes are connected by
/// edges (character transitions) and failure links (for efficient matching).
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct OffsetAcNode {
    /// Unique node identifier (0 is root)
    pub node_id: u32,
    /// Offset to failure node (0 = no failure link, use root)
    pub failure_node_offset: u32,
    /// Offset to array of edges (0 = no edges)
    pub edges_offset: u32,
    /// Offset to array of pattern references (0 = no patterns match here)
    pub patterns_offset: u32,
    /// Number of outgoing edges
    pub num_edges: u16,
    /// Number of patterns that match at this node
    pub num_patterns: u16,
    /// True if this is a final/accepting state
    pub is_final: u8,
    /// Distance from root node (0 = root)
    pub depth: u8,
    /// Reserved for alignment (should be 0)
    pub reserved: u16,
}

/// Edge in the Aho-Corasick automaton (8 bytes, 4-byte aligned)
///
/// Edges represent character transitions between nodes.
/// Each node's edges are stored as a sorted array for binary search.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct OffsetAcEdge {
    /// Input character (0-255)
    pub character: u8,
    /// Reserved for alignment (should be 0)
    pub reserved: [u8; 3],
    /// Offset to target node
    pub target_node_offset: u32,
}

/// Reference to a meta-word string (8 bytes, 4-byte aligned)
///
/// Meta-words are substrings extracted from glob patterns for AC matching.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct OffsetMetaWordRef {
    /// Offset to null-terminated meta-word string
    pub meta_word_offset: u32,
    /// Unique meta-word identifier
    pub meta_word_id: u32,
}

// ============================================================================
// OffsetParaglob Structures (Full Glob Matching)
// ============================================================================

/// Extended header for full Paraglob format (64 bytes)
///
/// This extends the basic OffsetAcHeader with additional metadata needed
/// for complete glob pattern matching without recompilation.
///
/// Magic bytes: "MMPG" identifies this as a full Paraglob format file.
/// The base header is included but its magic is changed from "MMAC" to "MMPG".
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct OffsetParaglobHeader {
    /// Base OffsetAc header (32 bytes) - magic will be "MMPG" not "MMAC"
    pub base: OffsetAcHeader,
    
    // Paraglob-specific extensions (32 bytes)
    /// Total number of original glob patterns
    pub pattern_count: u32,
    /// Offset to pattern entry table
    pub pattern_table_offset: u32,
    /// Offset to meta-word→pattern mapping table
    pub meta_word_mapping_table_offset: u32,
    /// Number of meta-word→pattern mappings
    pub meta_word_mapping_count: u32,
    /// Offset to pattern reference arrays
    pub pattern_refs_offset: u32,
    /// Number of single wildcard patterns (pure * or ?)
    pub single_wildcard_count: u32,
    /// Offset to single wildcard table
    pub single_wildcard_table_offset: u32,
    /// Reserved for future use (should be 0)
    pub reserved1: u32,
}

/// Pattern entry in the pattern table (12 bytes)
///
/// Stores metadata about each original glob pattern.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct OffsetPatternEntry {
    /// Unique pattern identifier
    pub pattern_id: u32,
    /// Offset to null-terminated pattern string
    pub pattern_string_offset: u32,
    /// Length of pattern string (not including null terminator)
    pub pattern_string_length: u32,
}

/// Meta-word to pattern mapping (16 bytes)
///
/// Maps each meta-word (from the AC automaton) to all glob patterns
/// that contain it. This enables efficient pattern filtering.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct OffsetMetaWordPatternMapping {
    /// Meta-word ID (from OffsetAc)
    pub meta_word_id: u32,
    /// Offset to array of pattern IDs
    pub pattern_refs_offset: u32,
    /// Number of patterns containing this meta-word
    pub num_patterns: u32,
    /// Reserved for alignment (should be 0)
    pub reserved: u32,
}

/// Pattern reference (4 bytes)
///
/// Simple reference to a pattern by ID.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct OffsetPatternRef {
    /// Pattern ID
    pub pattern_id: u32,
}

/// Single wildcard pattern entry (8 bytes)
///
/// For patterns that are pure wildcards (like "*", "?", "*.txt")
/// that don't need AC matching.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct OffsetSingleWildcard {
    /// Pattern ID
    pub pattern_id: u32,
    /// Offset to null-terminated pattern string
    pub pattern_string_offset: u32,
}

// ============================================================================
// Size Verification
// ============================================================================

// Static assertions to verify structure sizes match C++
const _: () = {
    assert!(std::mem::size_of::<OffsetAcHeader>() == 32);
    assert!(std::mem::size_of::<OffsetAcNode>() == 24);
    assert!(std::mem::size_of::<OffsetAcEdge>() == 8);
    assert!(std::mem::size_of::<OffsetMetaWordRef>() == 8);
    assert!(std::mem::size_of::<OffsetParaglobHeader>() == 64);
    assert!(std::mem::size_of::<OffsetPatternEntry>() == 12);
    assert!(std::mem::size_of::<OffsetMetaWordPatternMapping>() == 16);
    assert!(std::mem::size_of::<OffsetPatternRef>() == 4);
    assert!(std::mem::size_of::<OffsetSingleWildcard>() == 8);
};

// ============================================================================
// Display Implementations for Debugging
// ============================================================================

impl fmt::Display for OffsetAcHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "OffsetAcHeader {{ magic: {:?}, version: {}, nodes: {}, meta_words: {}, size: {} }}",
            std::str::from_utf8(&self.magic).unwrap_or("???"),
            self.version,
            self.node_count,
            self.meta_word_count,
            self.total_buffer_size
        )
    }
}

impl fmt::Display for OffsetParaglobHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "OffsetParaglobHeader {{ base: {}, patterns: {}, wildcards: {} }}",
            self.base, self.pattern_count, self.single_wildcard_count
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_struct_sizes() {
        // Verify all structures have the expected sizes
        assert_eq!(std::mem::size_of::<OffsetAcHeader>(), 32);
        assert_eq!(std::mem::size_of::<OffsetAcNode>(), 24);
        assert_eq!(std::mem::size_of::<OffsetAcEdge>(), 8);
        assert_eq!(std::mem::size_of::<OffsetMetaWordRef>(), 8);
        assert_eq!(std::mem::size_of::<OffsetParaglobHeader>(), 64);
        assert_eq!(std::mem::size_of::<OffsetPatternEntry>(), 12);
        assert_eq!(std::mem::size_of::<OffsetMetaWordPatternMapping>(), 16);
        assert_eq!(std::mem::size_of::<OffsetPatternRef>(), 4);
        assert_eq!(std::mem::size_of::<OffsetSingleWildcard>(), 8);
    }

    #[test]
    fn test_struct_alignment() {
        // Verify proper alignment
        assert_eq!(std::mem::align_of::<OffsetAcHeader>(), 4);
        assert_eq!(std::mem::align_of::<OffsetAcNode>(), 4);
        assert_eq!(std::mem::align_of::<OffsetAcEdge>(), 4);
        assert_eq!(std::mem::align_of::<OffsetMetaWordRef>(), 4);
        assert_eq!(std::mem::align_of::<OffsetParaglobHeader>(), 4);
    }

    #[test]
    fn test_magic_bytes() {
        assert_eq!(&MAGIC_AC, b"MMAC");
        assert_eq!(&MAGIC_PARAGLOB, b"MMPG");
    }

    #[test]
    fn test_format_version() {
        assert_eq!(FORMAT_VERSION, 1);
    }
}
