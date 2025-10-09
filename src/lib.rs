//! Paraglob Rust - Fast multi-pattern glob matching
//!
//! This library provides efficient glob pattern matching using the Aho-Corasick
//! algorithm with **zero-copy memory-mapped file support**.
//!
//! # Quick Start
//!
//! ```rust
//! use paraglob_rs::Paraglob;
//! use paraglob_rs::glob::MatchMode;
//!
//! // Build a matcher from patterns
//! let patterns = vec!["*.txt", "test_*", "hello"];
//! let mut pg = Paraglob::build_from_patterns(&patterns, MatchMode::CaseSensitive)?;
//!
//! // Find matches
//! let matches = pg.find_all("test_file.txt");
//! println!("Matched patterns: {:?}", matches);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! # File-Based Usage (Zero-Copy)
//!
//! ```rust,no_run
//! use paraglob_rs::serialization::{save, load};
//! use paraglob_rs::Paraglob;
//! use paraglob_rs::glob::MatchMode;
//!
//! // Build once and save
//! let patterns = vec!["*.txt", "*.rs"];
//! let pg = Paraglob::build_from_patterns(&patterns, MatchMode::CaseSensitive)?;
//! save(&pg, "patterns.pgb")?;
//!
//! // Load instantly in any process (~1ms, zero-copy)
//! let mut pg_loaded = load("patterns.pgb", MatchMode::CaseSensitive)?;
//! let matches = pg_loaded.paraglob_mut().find_all("test.txt");
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! # Key Features
//!
//! - **Zero-Copy Loading**: Files load in ~1ms via memory mapping
//! - **Shared Memory**: Multiple processes share physical RAM (99% savings)
//! - **Serializable**: Save/load pattern databases to disk
//! - **C-Compatible**: Stable C API for FFI
//! - **Fast Matching**: Aho-Corasick algorithm with glob support
//!
//! # Architecture
//!
//! The library uses an offset-based binary format that can be directly
//! memory-mapped without deserialization:
//!
//! ```text
//! ┌─────────────────────────────────────┐
//! │  File Format (offset-based)        │
//! ├─────────────────────────────────────┤
//! │  1. Header (magic, version, sizes)  │
//! │  2. AC Automaton (states, goto)     │
//! │  3. Pattern Data (globs, literals)  │
//! │  4. String Table (deduplicated)     │
//! └─────────────────────────────────────┘
//!          ↓ mmap() syscall (~1ms)
//! ┌─────────────────────────────────────┐
//! │  Memory (read-only, shared)         │
//! │  Zero deserialization needed!       │
//! └─────────────────────────────────────┘
//! ```

#![warn(missing_docs)]
#![warn(clippy::all)]

// Module declarations
pub mod ac_offset;
/// Error types for Paraglob operations
pub mod error;
pub mod glob;
pub mod mmap;
pub mod offset_format;
pub mod paraglob_offset;
pub mod serialization;

// Public C API
pub mod c_api;

// Re-exports for Rust consumers
pub use crate::error::ParaglobError;
pub use crate::paraglob_offset::Paraglob;

// Version information
/// Library version string
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Library major version
pub const VERSION_MAJOR: u32 = 0;

/// Library minor version
pub const VERSION_MINOR: u32 = 1;

/// Library patch version
pub const VERSION_PATCH: u32 = 0;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        assert_eq!(VERSION_MAJOR, 0);
        assert_eq!(VERSION_MINOR, 1);
        assert_eq!(VERSION_PATCH, 0);
    }
}
