//! Match mode configuration for text matching operations.
//!
//! This crate provides the `MatchMode` enum which controls case-sensitivity
//! in pattern matching operations across the matchy ecosystem.

/// Match mode for text matching operations.
///
/// Controls whether text comparisons are case-sensitive or case-insensitive.
///
/// ASCII case folding is consistent across exact literals and glob patterns.
/// For non-ASCII text, the current implementations differ: exact literals use
/// Unicode lowercase expansion while glob matching folds ASCII bytes only. Use
/// [`Self::CaseSensitive`] when uniform non-ASCII semantics are required.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchMode {
    /// Case-sensitive matching - "abc" matches "abc" but not "ABC"
    CaseSensitive,
    /// Case-insensitive matching with the non-ASCII limitation described above.
    /// For ASCII, "abc" matches "ABC", "Abc", etc.
    CaseInsensitive,
}
