//! Offset-based binary format for zero-copy memory mapping
//!
//! This module re-exports the binary format structures from `matchy-paraglob`.
//! The canonical definitions live in `matchy-paraglob::offset_format` to ensure
//! a single source of truth for all `#[repr(C)]` binary format structures.
//!
//! # What This Module Provides
//!
//! - `ParaglobHeader` - Main header (112 bytes, v5)
//! - `PatternDataMapping` - Pattern-to-data offset mapping
//! - `GlobSegmentIndex`, `GlobSegmentHeader`, `CharClassItemEncoded` - Glob segment structures
//! - `MAGIC`, `MATCHY_FORMAT_VERSION*` - Format constants
//! - Helper functions for reading structures from byte buffers
//!
//! # Why Re-exports?
//!
//! Binary format structures are defined once in `matchy-paraglob` and re-exported
//! here to avoid duplication. This prevents drift between identical `#[repr(C)]`
//! structs that must remain byte-for-byte compatible.

// Re-export all binary format structures from the canonical source
pub use matchy_paraglob::offset_format::{
    // Helper functions
    read_cstring,
    read_cstring_with_len,
    read_str_checked,
    read_str_unchecked,
    read_struct,
    read_struct_slice,
    // Glob segment structures
    CharClassItemEncoded,
    GlobSegmentHeader,
    GlobSegmentIndex,
    // Main header
    ParaglobHeader,
    // Pattern data mapping
    PatternDataMapping,
    // Format constants
    MAGIC,
    MATCHY_FORMAT_VERSION,
    MATCHY_FORMAT_VERSION_V1,
    MATCHY_FORMAT_VERSION_V2,
    MATCHY_FORMAT_VERSION_V3,
    MATCHY_FORMAT_VERSION_V4,
};

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem;

    #[test]
    fn test_reexports_match_expected_sizes() {
        // Verify re-exported types have expected sizes
        assert_eq!(mem::size_of::<ParaglobHeader>(), 112);
        assert_eq!(mem::size_of::<PatternDataMapping>(), 12);
        assert_eq!(mem::size_of::<GlobSegmentIndex>(), 8);
        assert_eq!(mem::size_of::<GlobSegmentHeader>(), 12);
        assert_eq!(mem::size_of::<CharClassItemEncoded>(), 12);
    }

    #[test]
    fn test_header_validation() {
        let mut header = ParaglobHeader::new();
        assert!(header.validate().is_ok());
        assert_eq!(header.version, MATCHY_FORMAT_VERSION);

        header.magic = *b"INVALID!";
        assert!(header.validate().is_err());
    }
}
