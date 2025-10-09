//! MaxMind DB (MMDB) Reader
//!
//! This module provides functionality for reading MaxMind DB files,
//! which are used for GeoIP lookups and other IP-based data lookups.
//!
//! The MMDB format uses a binary search tree for efficient IP address
//! lookups. Data is stored in the MMDB data section format, which we
//! already support via `DataValue` and `DataDecoder`.
//!
//! ## Architecture
//!
//! - **types**: MMDB-specific types and constants
//! - **format**: Binary format parsing and metadata extraction
//! - **tree**: Search tree traversal for IP lookups
//! - **metadata**: Metadata parsing
//!
//! Data decoding reuses `crate::data_section::DataDecoder` since
//! MMDB data format is what we already implemented for v2.

pub mod types;
pub mod format;

// TODO: Implement these modules
// pub mod tree;

// Re-export key types
pub use types::{IpVersion, MmdbError, RecordSize, METADATA_MARKER};
pub use format::{MmdbHeader, MmdbMetadata, find_metadata_marker};

// Use DataValue from data_section as our MMDB value type
pub use crate::data_section::DataValue as MmdbValue;
