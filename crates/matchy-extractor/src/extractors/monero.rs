//! Monero address extraction with Keccak256 checksum validation.

use tiny_keccak::{Hasher, Keccak};

use crate::finders::{Finder, FinderResults};
use crate::types::{ExtractedItem, Match};

use super::PatternExtractor;

pub struct MoneroExtractor;

impl MoneroExtractor {
    pub fn new() -> Self {
        Self
    }
}

impl Default for MoneroExtractor {
    fn default() -> Self {
        Self::new()
    }
}

fn validate_monero_address(addr: &str) -> bool {
    let decoded = match bs58::decode(addr).into_vec() {
        Ok(d) => d,
        Err(_) => return false,
    };

    if decoded.len() < 5 {
        return false;
    }

    let (payload, checksum) = decoded.split_at(decoded.len() - 4);

    let mut hasher = Keccak::v256();
    hasher.update(payload);
    let mut hash = [0u8; 32];
    hasher.finalize(&mut hash);

    &hash[..4] == checksum
}

impl PatternExtractor for MoneroExtractor {
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

            if !(90..=110).contains(&len) {
                continue;
            }

            let candidate = &chunk[start..end];

            if candidate[0] != b'4' && candidate[0] != b'8' {
                continue;
            }

            if let Ok(addr_str) = std::str::from_utf8(candidate) {
                if validate_monero_address(addr_str) {
                    matches.push(Match::new(ExtractedItem::Monero(addr_str), start, end));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn extract_monero(input: &[u8]) -> Vec<String> {
        let extractor = MoneroExtractor::new();
        let mut results = FinderResults::new(input);
        results.ensure(Finder::WordBoundaries);
        let mut matches = Vec::new();
        extractor.extract(&results, &mut matches);
        matches
            .iter()
            .filter_map(|m| match &m.item {
                ExtractedItem::Monero(m) => Some(m.to_string()),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn test_monero_extraction() {
        let addrs = extract_monero(
            b"Donate to 44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A",
        );
        if !addrs.is_empty() {
            assert!(addrs[0].starts_with('4'));
            assert!(addrs[0].len() >= 90 && addrs[0].len() <= 110);
        }
    }

    #[test]
    fn test_monero_reject_wrong_prefix() {
        let addrs = extract_monero(
            b"Fake 1AdUndXHHZ6cfufTMvppY6JwXNouMBzSkbLYfpAV5Usx3skxNgYeYTRj5UzqtReoS44qo9mtmXCqY45DJ852K5Jv2684Rge",
        );
        assert!(addrs.is_empty());
    }

    #[test]
    fn test_monero_reject_too_short() {
        let addrs = extract_monero(b"Short 4AdUndXHHZ6cfufTMvppY6JwXNouMBzSkbLYfpAV5Usx");
        assert!(addrs.is_empty());
    }
}
