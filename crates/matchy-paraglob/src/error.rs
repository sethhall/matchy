/// Error types for the matchy library
use std::fmt;

/// Result type alias for paraglob operations
pub type Result<T> = std::result::Result<T, ParaglobError>;

/// Main error type for paraglob operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParaglobError {
    /// Pattern-related errors
    InvalidPattern(String),

    /// I/O errors
    Io(String),

    /// Memory mapping errors
    Mmap(String),

    /// Format/parsing errors
    Format(String),

    /// Validation errors
    Validation(String),

    /// Serialization/deserialization errors
    SerializationError(String),

    /// Resource limit exceeded (e.g., too many states, too much memory)
    ResourceLimitExceeded(String),

    /// General errors
    Other(String),
}

impl fmt::Display for ParaglobError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPattern(msg) => write!(f, "Invalid pattern: {msg}"),
            Self::Io(msg) => write!(f, "I/O error: {msg}"),
            Self::Mmap(msg) => write!(f, "Memory mapping error: {msg}"),
            Self::Format(msg) => write!(f, "Format error: {msg}"),
            Self::Validation(msg) => write!(f, "Validation error: {msg}"),
            Self::SerializationError(msg) => write!(f, "Serialization error: {msg}"),
            Self::ResourceLimitExceeded(msg) => {
                write!(f, "Resource limit exceeded: {msg}")
            }
            Self::Other(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for ParaglobError {}

impl From<std::io::Error> for ParaglobError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err.to_string())
    }
}

impl From<String> for ParaglobError {
    fn from(msg: String) -> Self {
        Self::Other(msg)
    }
}

impl From<&str> for ParaglobError {
    fn from(msg: &str) -> Self {
        Self::Other(msg.to_string())
    }
}

impl From<crate::glob::GlobError> for ParaglobError {
    fn from(err: crate::glob::GlobError) -> Self {
        match err {
            crate::glob::GlobError::InvalidPattern(msg) => Self::InvalidPattern(msg),
        }
    }
}

impl From<matchy_ac::ACError> for ParaglobError {
    fn from(err: matchy_ac::ACError) -> Self {
        match err {
            matchy_ac::ACError::InvalidPattern(msg) => Self::InvalidPattern(msg),
            matchy_ac::ACError::ResourceLimitExceeded(msg) => Self::ResourceLimitExceeded(msg),
            matchy_ac::ACError::InvalidInput(msg) => Self::Other(msg),
        }
    }
}

impl From<matchy_ip_trie::IpTreeError> for ParaglobError {
    fn from(err: matchy_ip_trie::IpTreeError) -> Self {
        match err {
            matchy_ip_trie::IpTreeError::InvalidPattern(msg) => Self::InvalidPattern(msg),
            matchy_ip_trie::IpTreeError::ResourceLimitExceeded(msg) => {
                Self::ResourceLimitExceeded(msg)
            }
            matchy_ip_trie::IpTreeError::Other(msg) => Self::Other(msg),
        }
    }
}

// Note: matchy-format dependency would create a circular dependency
// This conversion is implemented in matchy crate which depends on both
