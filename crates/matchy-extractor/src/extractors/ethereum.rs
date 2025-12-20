//! Ethereum address extraction with EIP-55 checksum validation.

use tiny_keccak::{Hasher, Keccak};

use crate::finders::{Finder, FinderResults};
use crate::types::{ExtractedItem, Match};
use crate::util::{is_all_hex_simd, is_boundary_fast};

use super::PatternExtractor;

pub struct EthereumExtractor {
    pub require_word_boundaries: bool,
}

impl EthereumExtractor {
    pub fn new(require_word_boundaries: bool) -> Self {
        Self {
            require_word_boundaries,
        }
    }
}

fn validate_ethereum_checksum(addr: &str) -> bool {
    if addr.len() != 42 || !addr.starts_with("0x") {
        return false;
    }

    let addr_hex = &addr[2..];

    let all_lower = addr_hex
        .chars()
        .filter(|c| c.is_alphabetic())
        .all(char::is_lowercase);
    let all_upper = addr_hex
        .chars()
        .filter(|c| c.is_alphabetic())
        .all(char::is_uppercase);

    if all_lower || all_upper {
        return true;
    }

    let addr_lower = addr_hex.to_lowercase();

    let mut hasher = Keccak::v256();
    hasher.update(addr_lower.as_bytes());
    let mut hash = [0u8; 32];
    hasher.finalize(&mut hash);

    for (i, c) in addr_hex.chars().enumerate() {
        if c.is_alphabetic() {
            let hash_byte = hash[i / 2];
            let nibble = if i % 2 == 0 {
                hash_byte >> 4
            } else {
                hash_byte & 0x0f
            };

            let should_be_uppercase = nibble >= 8;

            if c.is_uppercase() != should_be_uppercase {
                return false;
            }
        }
    }

    true
}

impl PatternExtractor for EthereumExtractor {
    fn required_finders(&self) -> &'static [Finder] {
        &[Finder::HexPrefix]
    }

    fn extract<'a>(&self, results: &FinderResults<'a>, matches: &mut Vec<Match<'a>>) {
        let chunk = results.chunk;
        let hex_prefixes = results.hex_prefixes();

        for &start in hex_prefixes {
            if start + 42 > chunk.len() {
                continue;
            }

            if self.require_word_boundaries && start > 0 && !is_boundary_fast(chunk[start - 1]) {
                continue;
            }

            let end = start + 42;

            if self.require_word_boundaries && end < chunk.len() && !is_boundary_fast(chunk[end]) {
                continue;
            }

            if !is_all_hex_simd(&chunk[start + 2..end]) {
                continue;
            }

            if let Ok(addr_str) = std::str::from_utf8(&chunk[start..end]) {
                if validate_ethereum_checksum(addr_str) {
                    matches.push(Match::new(ExtractedItem::Ethereum(addr_str), start, end));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn extract_ethereum(input: &[u8]) -> Vec<String> {
        let extractor = EthereumExtractor::new(true);
        let mut results = FinderResults::new(input);
        results.ensure(Finder::HexPrefix);
        let mut matches = Vec::new();
        extractor.extract(&results, &mut matches);
        matches
            .iter()
            .filter_map(|m| match &m.item {
                ExtractedItem::Ethereum(e) => Some(e.to_string()),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn test_ethereum_extraction_lowercase() {
        let addrs = extract_ethereum(b"Transfer to 0x5aeda56215b167893e80b4fe645ba6d5bab767de");
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0], "0x5aeda56215b167893e80b4fe645ba6d5bab767de");
    }

    #[test]
    fn test_ethereum_extraction_checksummed() {
        let addrs = extract_ethereum(b"Send to 0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed");
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0], "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed");
    }

    #[test]
    fn test_ethereum_reject_invalid_checksum() {
        let addrs = extract_ethereum(b"Bad address 0x5aAeb6053f3e94c9b9a09f33669435e7ef1beaed");
        assert!(addrs.is_empty());
    }

    #[test]
    fn test_ethereum_reject_wrong_length() {
        let addrs = extract_ethereum(b"Short address 0x5aeda56215b167893e80b4fe645ba6d5bab7");
        assert!(addrs.is_empty());
    }

    #[test]
    fn test_ethereum_reject_non_hex() {
        let addrs = extract_ethereum(b"Invalid 0x5aeda56215b167893e80b4fe645ba6d5bab767dg");
        assert!(addrs.is_empty());
    }

    #[test]
    fn test_ethereum_in_log_line() {
        let addrs = extract_ethereum(
            b"2025-01-15 10:32:45 Transaction to=0x5aeda56215b167893e80b4fe645ba6d5bab767de value=1000000000000000000",
        );
        assert_eq!(addrs.len(), 1);
    }
}
