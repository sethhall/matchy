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
//! [Header: ParaglobHeader (64 bytes)]
//! [AC Nodes: ACNode array]
//! [AC Edges: ACEdge arrays (variable, referenced by nodes)]
//! [AC Pattern IDs: u32 arrays (variable, referenced by nodes)]
//! [Pattern Entries: PatternEntry array]
//! [Pattern Strings: null-terminated UTF-8]
//! [Meta-word mappings: MetaWordMapping array]
//! [Pattern reference arrays: u32 arrays]
//! [Single wildcards: SingleWildcard array]
//! ```
//!
//! # Design Principles
//!
//! 1. **Alignment**: All structs are properly aligned for direct casting
//! 2. **Offsets**: All references use u32 byte offsets (4GB limit)
//! 3. **Zero-copy**: Can read directly from mmap without parsing
//! 4. **Portability**: Little-endian u32/u8 only (standard on x86/ARM)

use std::mem;

/// Magic bytes identifying Paraglob binary format
pub const MAGIC: &[u8; 8] = b"PARAGLOB";

/// Current format version
pub const VERSION: u32 = 1;

/// Main header for serialized Paraglob database (64 bytes, 8-byte aligned)
///
/// This header appears at the start of every serialized Paraglob file.
/// All offsets are relative to the start of the buffer.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ParaglobHeader {
    /// Magic bytes: "PARAGLOB"
    pub magic: [u8; 8],
    
    /// Format version (currently 1)
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
}

/// AC Automaton node (32 bytes, 8-byte aligned)
///
/// Represents a single node in the Aho-Corasick trie.
/// All child references are stored as offsets to allow zero-copy loading.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ACNode {
    /// Unique node ID
    pub node_id: u32,
    
    /// Offset to failure link node (0 = root)
    pub failure_offset: u32,
    
    /// Offset to edge array (0 = no edges)
    pub edges_offset: u32,
    
    /// Number of outgoing edges
    pub edge_count: u16,
    
    /// Reserved for alignment
    pub reserved1: u16,
    
    /// Offset to pattern ID array (0 = no patterns)
    pub patterns_offset: u32,
    
    /// Number of pattern IDs at this node
    pub pattern_count: u16,
    
    /// Is this a terminal/word node?
    pub is_final: u8,
    
    /// Depth from root
    pub depth: u8,
    
    /// Reserved for future use (padding to 32 bytes)
    pub reserved2: [u32; 2],
}

/// AC Automaton edge (8 bytes, 4-byte aligned)
///
/// Represents a transition from one node to another on a specific character.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ACEdge {
    /// Input character (0-255)
    pub character: u8,
    
    /// Reserved for alignment
    pub reserved: [u8; 3],
    
    /// Offset to target node
    pub target_offset: u32,
}

/// Pattern entry (16 bytes, 8-byte aligned)
///
/// Metadata about a single glob pattern in the database.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
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
#[derive(Debug, Clone, Copy)]
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
#[derive(Debug, Clone, Copy)]
pub struct SingleWildcard {
    /// Pattern ID
    pub pattern_id: u32,
    
    /// Offset to pattern string
    pub pattern_string_offset: u32,
}

// Compile-time size assertions to ensure struct layout
const _: () = assert!(mem::size_of::<ParaglobHeader>() == 64);
const _: () = assert!(mem::size_of::<ACNode>() == 32);
const _: () = assert!(mem::size_of::<ACEdge>() == 8);
const _: () = assert!(mem::size_of::<PatternEntry>() == 16);
const _: () = assert!(mem::size_of::<MetaWordMapping>() == 12);
const _: () = assert!(mem::size_of::<SingleWildcard>() == 8);

impl Default for ParaglobHeader {
    fn default() -> Self {
        Self::new()
    }
}

impl ParaglobHeader {
    /// Create a new header with magic and version
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
        }
    }
    
    /// Validate header magic and version
    pub fn validate(&self) -> Result<(), &'static str> {
        if &self.magic != MAGIC {
            return Err("Invalid magic bytes");
        }
        if self.version != VERSION {
            return Err("Unsupported version");
        }
        Ok(())
    }
}

impl ACNode {
    /// Create a new node
    pub fn new(node_id: u32, depth: u8) -> Self {
        Self {
            node_id,
            failure_offset: 0,
            edges_offset: 0,
            edge_count: 0,
            reserved1: 0,
            patterns_offset: 0,
            pattern_count: 0,
            is_final: 0,
            depth,
            reserved2: [0; 2],
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
    std::str::from_utf8(&buffer[start..end])
        .map_err(|_| "Invalid UTF-8")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_size() {
        assert_eq!(mem::size_of::<ParaglobHeader>(), 64);
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
        
        header.magic = *b"INVALID!";
        assert!(header.validate().is_err());
        
        header.magic = *MAGIC;
        header.version = 999;
        assert!(header.validate().is_err());
    }

    #[test]
    fn test_read_struct() {
        let mut buffer = vec![0u8; 64];
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
