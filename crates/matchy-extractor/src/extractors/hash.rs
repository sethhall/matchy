//! File hash extraction (MD5, SHA1, SHA256, SHA384, SHA512).

use crate::finders::{Finder, FinderResults};
use crate::types::{ExtractedItem, HashType, Match};
use crate::util::is_all_hex_simd;

use super::PatternExtractor;

pub struct HashExtractor;

impl HashExtractor {
    pub fn new() -> Self {
        Self
    }
}

impl Default for HashExtractor {
    fn default() -> Self {
        Self::new()
    }
}

impl PatternExtractor for HashExtractor {
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

            if let Some(hash_type) = HashType::from_len(len) {
                let candidate = &chunk[start..end];

                if is_all_hex_simd(candidate) {
                    if let Ok(hash_str) = std::str::from_utf8(candidate) {
                        matches.push(Match::new(
                            ExtractedItem::Hash(hash_type, hash_str),
                            start,
                            end,
                        ));
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn extract_hashes(input: &[u8]) -> Vec<(HashType, String)> {
        let extractor = HashExtractor::new();
        let mut results = FinderResults::new(input);
        results.ensure(Finder::WordBoundaries);
        let mut matches = Vec::new();
        extractor.extract(&results, &mut matches);
        matches
            .iter()
            .filter_map(|m| match &m.item {
                ExtractedItem::Hash(ht, h) => Some((*ht, h.to_string())),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn test_hash_extraction_md5() {
        let hashes = extract_hashes(b"File hash: 5d41402abc4b2a76b9719d911017c592 uploaded");
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0].0, HashType::Md5);
        assert_eq!(hashes[0].1, "5d41402abc4b2a76b9719d911017c592");
    }

    #[test]
    fn test_hash_extraction_sha1() {
        let hashes = extract_hashes(b"SHA1: 2fd4e1c67a2d28fced849ee1bb76e7391b93eb12 verified");
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0].0, HashType::Sha1);
    }

    #[test]
    fn test_hash_extraction_sha256() {
        let hashes = extract_hashes(
            b"SHA256: 2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae detected",
        );
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0].0, HashType::Sha256);
    }

    #[test]
    fn test_hash_extraction_sha384() {
        let hashes = extract_hashes(b"SHA384: cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7 verified");
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0].0, HashType::Sha384);
    }

    #[test]
    fn test_hash_extraction_sha512() {
        let hashes = extract_hashes(b"SHA512: cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e found");
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0].0, HashType::Sha512);
    }

    #[test]
    fn test_hash_extraction_multiple() {
        let hashes = extract_hashes(
            b"MD5: 5d41402abc4b2a76b9719d911017c592 SHA1: 2fd4e1c67a2d28fced849ee1bb76e7391b93eb12",
        );
        assert_eq!(hashes.len(), 2);
        assert_eq!(hashes[0].0, HashType::Md5);
        assert_eq!(hashes[1].0, HashType::Sha1);
    }

    #[test]
    fn test_hash_extraction_uppercase() {
        let hashes = extract_hashes(b"Hash: 5D41402ABC4B2A76B9719D911017C592 found");
        assert_eq!(hashes.len(), 1);
    }

    #[test]
    fn test_hash_reject_wrong_length() {
        let hashes = extract_hashes(b"Hash: 5d41402abc4b2a76b9719d91101 invalid");
        assert!(hashes.is_empty());
    }

    #[test]
    fn test_hash_reject_non_hex() {
        let hashes = extract_hashes(b"Hash: 5d41402abc4b2a76b9719d911017c5gz invalid");
        assert!(hashes.is_empty());
    }

    #[test]
    fn test_hash_with_punctuation() {
        let hashes = extract_hashes(b"Hash: [5d41402abc4b2a76b9719d911017c592] in brackets");
        assert_eq!(hashes.len(), 1);
    }
}
