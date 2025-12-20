//! Bitcoin address extraction (legacy, P2SH, bech32).

use sha2::{Digest, Sha256};

use crate::finders::{Finder, FinderResults};
use crate::types::{ExtractedItem, Match};

use super::PatternExtractor;

pub struct BitcoinExtractor;

impl BitcoinExtractor {
    pub fn new() -> Self {
        Self
    }
}

impl Default for BitcoinExtractor {
    fn default() -> Self {
        Self::new()
    }
}

fn validate_bitcoin_base58(addr: &str) -> bool {
    let decoded = match bs58::decode(addr).into_vec() {
        Ok(d) => d,
        Err(_) => return false,
    };

    if decoded.len() < 5 {
        return false;
    }

    let (payload, checksum) = decoded.split_at(decoded.len() - 4);

    let hash1 = Sha256::digest(payload);
    let hash2 = Sha256::digest(hash1);

    &hash2[..4] == checksum
}

fn validate_bitcoin_bech32(addr: &str) -> bool {
    use bech32::Hrp;

    if let Ok((hrp, _data)) = bech32::decode(addr) {
        hrp == Hrp::parse("bc").unwrap()
    } else {
        false
    }
}

impl PatternExtractor for BitcoinExtractor {
    fn required_finders(&self) -> &'static [Finder] {
        &[Finder::WordBoundaries]
    }

    fn extract<'a>(&self, results: &FinderResults<'a>, matches: &mut Vec<Match<'a>>) {
        let chunk = results.chunk;
        let boundaries = results.word_boundaries();

        for window in boundaries.chunks_exact(2) {
            let start = window[0];
            let end = window[1];
            let len = end - start;

            if !(26..=62).contains(&len) {
                continue;
            }

            let candidate = &chunk[start..end];

            if candidate.len() >= 3 && &candidate[..3] == b"bc1" {
                if let Ok(addr_str) = std::str::from_utf8(candidate) {
                    if validate_bitcoin_bech32(addr_str) {
                        matches.push(Match::new(ExtractedItem::Bitcoin(addr_str), start, end));
                    }
                }
            } else if candidate[0] == b'1' || candidate[0] == b'3' {
                if let Ok(addr_str) = std::str::from_utf8(candidate) {
                    if validate_bitcoin_base58(addr_str) {
                        matches.push(Match::new(ExtractedItem::Bitcoin(addr_str), start, end));
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn extract_bitcoin(input: &[u8]) -> Vec<String> {
        let extractor = BitcoinExtractor::new();
        let mut results = FinderResults::new(input);
        results.ensure(Finder::WordBoundaries);
        let mut matches = Vec::new();
        extractor.extract(&results, &mut matches);
        matches
            .iter()
            .filter_map(|m| match &m.item {
                ExtractedItem::Bitcoin(b) => Some(b.to_string()),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn test_bitcoin_legacy_extraction() {
        let addrs = extract_bitcoin(b"Send to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa for payment");
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0], "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
    }

    #[test]
    fn test_bitcoin_p2sh_extraction() {
        let addrs = extract_bitcoin(b"Payment to 3Cbq7aT1tY8kMxWLbitaG7yT6bPbKChq64 confirmed");
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0], "3Cbq7aT1tY8kMxWLbitaG7yT6bPbKChq64");
    }

    #[test]
    fn test_bitcoin_bech32_extraction() {
        let addrs = extract_bitcoin(b"Withdraw to bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq");
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0], "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq");
    }

    #[test]
    fn test_bitcoin_reject_invalid_checksum() {
        let addrs = extract_bitcoin(b"Fake address 1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf00 is invalid");
        assert!(addrs.is_empty());
    }

    #[test]
    fn test_bitcoin_reject_too_short() {
        let addrs = extract_bitcoin(b"Short address 1A1zP1eP is invalid");
        assert!(addrs.is_empty());
    }
}
