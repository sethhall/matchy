//! Error types for matchy format operations

use std::fmt;

/// Errors that can occur during database format operations
#[derive(Debug, Clone)]
pub enum FormatError {
    /// Invalid IP address or CIDR notation
    InvalidIpAddress(String),
    /// Invalid pattern syntax
    InvalidPattern(String),
    /// IP tree building error
    IpTreeError(String),
    /// Pattern matching error
    PatternError(String),
    /// Literal hash error
    LiteralHashError(String),
    /// I/O error
    IoError(String),
    /// Entry validation error (schema validation failed)
    ValidationError(String),
    /// Generic error
    Other(String),
}

impl fmt::Display for FormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidIpAddress(msg) => write!(f, "Invalid IP address: {msg}"),
            Self::InvalidPattern(msg) => write!(f, "Invalid pattern: {msg}"),
            Self::IpTreeError(msg) => write!(f, "IP tree error: {msg}"),
            Self::PatternError(msg) => write!(f, "Pattern error: {msg}"),
            Self::LiteralHashError(msg) => write!(f, "Literal hash error: {msg}"),
            Self::IoError(msg) => write!(f, "I/O error: {msg}"),
            Self::ValidationError(msg) => write!(f, "Validation error: {msg}"),
            Self::Other(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for FormatError {}

// Conversions from component errors
impl From<matchy_paraglob::error::ParaglobError> for FormatError {
    fn from(err: matchy_paraglob::error::ParaglobError) -> Self {
        Self::PatternError(err.to_string())
    }
}

impl From<matchy_literal_hash::LiteralHashError> for FormatError {
    fn from(err: matchy_literal_hash::LiteralHashError) -> Self {
        Self::LiteralHashError(err.to_string())
    }
}

impl From<matchy_ip_trie::IpTreeError> for FormatError {
    fn from(err: matchy_ip_trie::IpTreeError) -> Self {
        Self::IpTreeError(err.to_string())
    }
}

impl From<std::io::Error> for FormatError {
    fn from(err: std::io::Error) -> Self {
        Self::IoError(err.to_string())
    }
}

impl From<String> for FormatError {
    fn from(s: String) -> Self {
        Self::Other(s)
    }
}

impl From<&str> for FormatError {
    fn from(s: &str) -> Self {
        Self::Other(s.to_string())
    }
}

// Conversion: FormatError -> ParaglobError
// This allows code that uses ParaglobError to also accept FormatError.
// When matchy-format operations fail, they can be converted into ParaglobError
// so the caller can handle both types uniformly.
impl From<FormatError> for matchy_paraglob::error::ParaglobError {
    fn from(err: FormatError) -> Self {
        match err {
            FormatError::InvalidIpAddress(msg) | FormatError::InvalidPattern(msg) => {
                Self::InvalidPattern(msg)
            }
            FormatError::IoError(msg) => Self::Io(msg),
            FormatError::IpTreeError(msg)
            | FormatError::PatternError(msg)
            | FormatError::LiteralHashError(msg)
            | FormatError::ValidationError(msg)
            | FormatError::Other(msg) => Self::Other(msg),
        }
    }
}
