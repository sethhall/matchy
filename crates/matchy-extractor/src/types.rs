//! Core types for pattern extraction.
//!
//! This module contains the fundamental types used throughout the extractor:
//! - [`HashType`] - Classification of file hash types (MD5, SHA1, etc.)
//! - [`ExtractedItem`] - Enum of all extractable pattern types
//! - [`Match`] - A single extraction result with position information

use std::net::{Ipv4Addr, Ipv6Addr};

/// Type of file hash
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashType {
    /// MD5 hash (32 hex characters)
    Md5,
    /// SHA1 hash (40 hex characters)
    Sha1,
    /// SHA256 hash (64 hex characters)
    Sha256,
    /// SHA384 hash (96 hex characters)
    Sha384,
    /// SHA512 hash (128 hex characters)
    Sha512,
}

impl HashType {
    /// Get hash type from byte length
    #[must_use]
    pub fn from_len(len: usize) -> Option<Self> {
        match len {
            32 => Some(Self::Md5),
            40 => Some(Self::Sha1),
            64 => Some(Self::Sha256),
            96 => Some(Self::Sha384),
            128 => Some(Self::Sha512),
            _ => None,
        }
    }

    /// Get expected length for this hash type
    #[must_use]
    pub fn len(&self) -> usize {
        match self {
            Self::Md5 => 32,
            Self::Sha1 => 40,
            Self::Sha256 => 64,
            Self::Sha384 => 96,
            Self::Sha512 => 128,
        }
    }

    /// Check if hash is empty (always false - hashes are never empty)
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        false
    }

    /// Get the human-readable type name for this hash type
    ///
    /// Returns a consistent string representation:
    /// - `"MD5"` for 32-character MD5 hashes
    /// - `"SHA1"` for 40-character SHA1 hashes
    /// - `"SHA256"` for 64-character SHA256 hashes
    /// - `"SHA384"` for 96-character SHA384 hashes
    /// - `"SHA512"` for 128-character SHA512 hashes
    ///
    /// # Example
    /// ```
    /// # use matchy_extractor::HashType;
    /// assert_eq!(HashType::Md5.type_name(), "MD5");
    /// assert_eq!(HashType::Sha256.type_name(), "SHA256");
    /// ```
    #[must_use]
    pub fn type_name(&self) -> &'static str {
        match self {
            Self::Md5 => "MD5",
            Self::Sha1 => "SHA1",
            Self::Sha256 => "SHA256",
            Self::Sha384 => "SHA384",
            Self::Sha512 => "SHA512",
        }
    }
}

/// Type of extracted pattern
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtractedItem<'a> {
    /// Domain name (e.g., "example.com")
    Domain(&'a str),
    /// Email address (e.g., "user@example.com")
    Email(&'a str),
    /// IPv4 address
    Ipv4(Ipv4Addr),
    /// IPv6 address
    Ipv6(Ipv6Addr),
    /// File hash (MD5, SHA1, or SHA256)
    Hash(HashType, &'a str),
    /// Bitcoin address (all formats: legacy, P2SH, bech32)
    Bitcoin(&'a str),
    /// Ethereum address
    Ethereum(&'a str),
    /// Monero address
    Monero(&'a str),
}

impl<'a> ExtractedItem<'a> {
    /// Get the human-readable type name for this extracted item
    ///
    /// Returns a consistent string representation of the item type:
    /// - `"Domain"`, `"Email"`, `"IPv4"`, `"IPv6"`
    /// - `"MD5"`, `"SHA1"`, `"SHA256"`, `"SHA384"` for hashes
    /// - `"Bitcoin"`, `"Ethereum"`, `"Monero"` for cryptocurrency addresses
    ///
    /// This is useful for logging, output formatting, and avoiding repetitive
    /// pattern matching across your codebase.
    ///
    /// # Example
    /// ```
    /// # use matchy_extractor::Extractor;
    /// # let extractor = Extractor::new().unwrap();
    /// let line = b"Check example.com and 192.168.1.1";
    /// for match_item in extractor.extract_from_line(line) {
    ///     println!("{}: {}", match_item.item.type_name(), match_item.as_str(line));
    /// }
    /// // Output:
    /// // Domain: example.com
    /// // IPv4: 192.168.1.1
    /// ```
    ///
    /// # See Also
    /// - [`as_value()`](Self::as_value) - Get the extracted value as a string
    #[must_use]
    pub fn type_name(&self) -> &'static str {
        match self {
            ExtractedItem::Domain(_) => "Domain",
            ExtractedItem::Email(_) => "Email",
            ExtractedItem::Ipv4(_) => "IPv4",
            ExtractedItem::Ipv6(_) => "IPv6",
            ExtractedItem::Hash(hash_type, _) => hash_type.type_name(),
            ExtractedItem::Bitcoin(_) => "Bitcoin",
            ExtractedItem::Ethereum(_) => "Ethereum",
            ExtractedItem::Monero(_) => "Monero",
        }
    }

    /// Get the extracted value as a string
    ///
    /// Returns the string representation of the extracted item.
    /// For IP addresses, this converts them to their canonical string form.
    ///
    /// This allocates a new `String` and is useful when you need an owned value
    /// (e.g., for storage, returning from functions, or when the original input
    /// goes out of scope). If you only need a string slice referencing the
    /// original input, use [`Match::as_str()`] instead.
    ///
    /// # Example
    /// ```
    /// # use matchy_extractor::Extractor;
    /// # let extractor = Extractor::new().unwrap();
    /// let line = b"Check 192.168.1.1 and example.com";
    /// let values: Vec<String> = extractor
    ///     .extract_from_line(line)
    ///     .map(|m| m.item.as_value())
    ///     .collect();
    /// // Note: extraction order is IPv4, then Domain
    /// assert_eq!(values, vec!["example.com", "192.168.1.1"]);
    /// ```
    ///
    /// # See Also
    /// - [`type_name()`](Self::type_name) - Get the type name of this item
    /// - [`Match::as_str()`] - Get a zero-copy string slice
    #[must_use]
    pub fn as_value(&self) -> String {
        match self {
            ExtractedItem::Domain(s)
            | ExtractedItem::Email(s)
            | ExtractedItem::Bitcoin(s)
            | ExtractedItem::Ethereum(s)
            | ExtractedItem::Monero(s)
            | ExtractedItem::Hash(_, s) => (*s).to_string(),
            ExtractedItem::Ipv4(ip) => ip.to_string(),
            ExtractedItem::Ipv6(ip) => ip.to_string(),
        }
    }
}

/// A single extracted match with position information
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Match<'a> {
    /// The extracted item
    pub item: ExtractedItem<'a>,
    /// Byte span in the input (start, end) - exclusive end
    pub span: (usize, usize),
}

impl<'a> Match<'a> {
    /// Create a new match with the given item and span
    #[inline]
    #[must_use]
    pub fn new(item: ExtractedItem<'a>, start: usize, end: usize) -> Self {
        Self {
            item,
            span: (start, end),
        }
    }

    /// Get the matched text as a string slice.
    /// Returns empty string if the matched bytes are not valid UTF-8.
    #[must_use]
    pub fn as_str(&self, input: &'a [u8]) -> &'a str {
        std::str::from_utf8(&input[self.span.0..self.span.1]).unwrap_or("")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_type_from_len() {
        assert_eq!(HashType::from_len(32), Some(HashType::Md5));
        assert_eq!(HashType::from_len(40), Some(HashType::Sha1));
        assert_eq!(HashType::from_len(64), Some(HashType::Sha256));
        assert_eq!(HashType::from_len(96), Some(HashType::Sha384));
        assert_eq!(HashType::from_len(128), Some(HashType::Sha512));
        assert_eq!(HashType::from_len(31), None);
        assert_eq!(HashType::from_len(0), None);
    }

    #[test]
    fn test_hash_type_len() {
        assert_eq!(HashType::Md5.len(), 32);
        assert_eq!(HashType::Sha1.len(), 40);
        assert_eq!(HashType::Sha256.len(), 64);
        assert_eq!(HashType::Sha384.len(), 96);
        assert_eq!(HashType::Sha512.len(), 128);
    }

    #[test]
    fn test_hash_type_name() {
        assert_eq!(HashType::Md5.type_name(), "MD5");
        assert_eq!(HashType::Sha1.type_name(), "SHA1");
        assert_eq!(HashType::Sha256.type_name(), "SHA256");
        assert_eq!(HashType::Sha384.type_name(), "SHA384");
        assert_eq!(HashType::Sha512.type_name(), "SHA512");
    }

    #[test]
    fn test_hash_type_is_empty() {
        assert!(!HashType::Md5.is_empty());
        assert!(!HashType::Sha512.is_empty());
    }

    #[test]
    fn test_extracted_item_type_name() {
        assert_eq!(ExtractedItem::Domain("example.com").type_name(), "Domain");
        assert_eq!(
            ExtractedItem::Email("user@example.com").type_name(),
            "Email"
        );
        assert_eq!(
            ExtractedItem::Ipv4(Ipv4Addr::new(192, 168, 1, 1)).type_name(),
            "IPv4"
        );
        assert_eq!(
            ExtractedItem::Hash(HashType::Sha256, "abc123").type_name(),
            "SHA256"
        );
        assert_eq!(ExtractedItem::Bitcoin("bc1q...").type_name(), "Bitcoin");
        assert_eq!(ExtractedItem::Ethereum("0x...").type_name(), "Ethereum");
        assert_eq!(ExtractedItem::Monero("4...").type_name(), "Monero");
    }

    #[test]
    fn test_extracted_item_as_value() {
        assert_eq!(
            ExtractedItem::Domain("example.com").as_value(),
            "example.com"
        );
        assert_eq!(
            ExtractedItem::Ipv4(Ipv4Addr::new(192, 168, 1, 1)).as_value(),
            "192.168.1.1"
        );
    }

    #[test]
    fn test_match_as_str() {
        let input = b"hello world";
        let m = Match::new(ExtractedItem::Domain("hello"), 0, 5);
        assert_eq!(m.as_str(input), "hello");
    }
}
