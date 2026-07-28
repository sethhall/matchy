//! MMDB-specific Type Definitions
//!
//! MMDB-specific types. Data values use the existing `DataValue` type
//! from `data_section` module which is already MMDB-compatible.

use std::fmt;

/// MMDB metadata marker: "\xAB\xCD\xEFMaxMind.com"
pub const METADATA_MARKER: &[u8] = b"\xAB\xCD\xEFMaxMind.com";

/// MMDB-specific error types
#[derive(Debug, Clone)]
pub enum MmdbError {
    /// Invalid file format
    InvalidFormat(String),
    /// Metadata not found
    MetadataNotFound,
    /// Invalid metadata structure
    InvalidMetadata(String),
    /// Data decoding error (wraps DataDecoder errors)
    DecodeError(String),
    /// IO error
    IoError(String),
    /// Invalid IP address
    InvalidIpAddress(String),
    /// Network/IP lookup error
    LookupError(String),
}

impl fmt::Display for MmdbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFormat(msg) => write!(f, "Invalid MMDB format: {msg}"),
            Self::MetadataNotFound => write!(f, "MMDB metadata marker not found"),
            Self::InvalidMetadata(msg) => write!(f, "Invalid metadata: {msg}"),
            Self::DecodeError(msg) => write!(f, "Data decode error: {msg}"),
            Self::IoError(msg) => write!(f, "IO error: {msg}"),
            Self::InvalidIpAddress(msg) => write!(f, "Invalid IP address: {msg}"),
            Self::LookupError(msg) => write!(f, "Lookup error: {msg}"),
        }
    }
}

impl std::error::Error for MmdbError {}

// Convert data_section errors to MmdbError
impl From<String> for MmdbError {
    fn from(msg: String) -> Self {
        Self::DecodeError(msg)
    }
}

// Re-export tree vocabulary from ip-trie; MMDB metadata selects these values
// but does not own their semantics.
pub use matchy_ip_trie::{IpVersion, RecordSize};

// Helper function for MMDB metadata parsing
pub fn record_size_from_bits(bits: u16) -> Result<RecordSize, MmdbError> {
    match bits {
        24 => Ok(RecordSize::Bits24),
        28 => Ok(RecordSize::Bits28),
        32 => Ok(RecordSize::Bits32),
        _ => Err(MmdbError::InvalidFormat(format!(
            "Invalid record size: {bits} bits"
        ))),
    }
}
