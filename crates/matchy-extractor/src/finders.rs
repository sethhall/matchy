//! Pre-computation infrastructure for extraction.
//!
//! Extractors can register which finders they need, and the core will run
//! each finder at most once per chunk, sharing results across extractors.

use crate::util::is_boundary_fast;

/// Types of pre-computed position data an extractor can request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Finder {
    /// Word boundaries: Vec of positions where tokens start/end
    WordBoundaries,
    /// Dot positions (for domains, IPv4)
    Dots,
    /// Double-colon positions (for IPv6)
    DoubleColons,
    /// At-sign positions (for emails)
    AtSigns,
    /// "0x" prefix positions (for Ethereum)
    HexPrefix,
}

/// Pre-computed finder results, computed once and shared across extractors.
pub struct FinderResults<'a> {
    pub chunk: &'a [u8],
    word_boundaries: Option<Vec<usize>>,
    dots: Option<Vec<usize>>,
    double_colons: Option<Vec<usize>>,
    at_signs: Option<Vec<usize>>,
    hex_prefixes: Option<Vec<usize>>,
}

impl<'a> FinderResults<'a> {
    /// Create new finder results for the given chunk.
    pub fn new(chunk: &'a [u8]) -> Self {
        Self {
            chunk,
            word_boundaries: None,
            dots: None,
            double_colons: None,
            at_signs: None,
            hex_prefixes: None,
        }
    }

    /// Compute the specified finder if not already computed.
    pub fn ensure(&mut self, finder: Finder) {
        match finder {
            Finder::WordBoundaries => {
                if self.word_boundaries.is_none() {
                    self.word_boundaries = Some(find_word_boundaries(self.chunk));
                }
            }
            Finder::Dots => {
                if self.dots.is_none() {
                    self.dots = Some(memchr::memchr_iter(b'.', self.chunk).collect());
                }
            }
            Finder::DoubleColons => {
                if self.double_colons.is_none() {
                    let finder = memchr::memmem::Finder::new(b"::");
                    self.double_colons = Some(finder.find_iter(self.chunk).collect());
                }
            }
            Finder::AtSigns => {
                if self.at_signs.is_none() {
                    self.at_signs = Some(memchr::memchr_iter(b'@', self.chunk).collect());
                }
            }
            Finder::HexPrefix => {
                if self.hex_prefixes.is_none() {
                    let finder = memchr::memmem::Finder::new(b"0x");
                    self.hex_prefixes = Some(finder.find_iter(self.chunk).collect());
                }
            }
        }
    }

    /// Get word boundaries (panics if not computed - programmer error).
    #[inline]
    pub fn word_boundaries(&self) -> &[usize] {
        self.word_boundaries
            .as_ref()
            .expect("WordBoundaries not requested by extractor")
    }

    /// Get dot positions (panics if not computed - programmer error).
    #[inline]
    pub fn dots(&self) -> &[usize] {
        self.dots.as_ref().expect("Dots not requested by extractor")
    }

    /// Get double-colon positions (panics if not computed - programmer error).
    #[inline]
    pub fn double_colons(&self) -> &[usize] {
        self.double_colons
            .as_ref()
            .expect("DoubleColons not requested by extractor")
    }

    /// Get at-sign positions (panics if not computed - programmer error).
    #[inline]
    pub fn at_signs(&self) -> &[usize] {
        self.at_signs
            .as_ref()
            .expect("AtSigns not requested by extractor")
    }

    /// Get hex prefix positions (panics if not computed - programmer error).
    #[inline]
    pub fn hex_prefixes(&self) -> &[usize] {
        self.hex_prefixes
            .as_ref()
            .expect("HexPrefix not requested by extractor")
    }
}

/// Find all word boundary positions in chunk.
/// Returns positions where tokens start/end as pairs: [start1, end1, start2, end2, ...].
pub fn find_word_boundaries(chunk: &[u8]) -> Vec<usize> {
    let mut boundaries = Vec::new();
    find_word_boundaries_into(chunk, &mut boundaries);
    boundaries
}

/// Find all word boundary positions in chunk and append to provided buffer.
/// A token is a sequence of non-boundary characters.
pub fn find_word_boundaries_into(chunk: &[u8], boundaries: &mut Vec<usize>) {
    if chunk.is_empty() {
        return;
    }

    let additional = chunk.len() / 4;
    if boundaries.capacity() < boundaries.len() + additional {
        boundaries.reserve(additional);
    }

    let mut in_token = !is_boundary_fast(chunk[0]);
    if in_token {
        boundaries.push(0);
    }

    for (i, &byte) in chunk.iter().enumerate().skip(1) {
        let is_boundary = is_boundary_fast(byte);

        if in_token && is_boundary {
            boundaries.push(i);
            in_token = false;
        } else if !in_token && !is_boundary {
            boundaries.push(i);
            in_token = true;
        }
    }

    if in_token {
        boundaries.push(chunk.len());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_word_boundaries_simple() {
        let chunk = b"hello world";
        let boundaries = find_word_boundaries(chunk);
        // [0, 5, 6, 11] -> "hello" at 0..5, "world" at 6..11
        assert_eq!(boundaries, vec![0, 5, 6, 11]);
    }

    #[test]
    fn test_find_word_boundaries_empty() {
        let boundaries = find_word_boundaries(b"");
        assert!(boundaries.is_empty());
    }

    #[test]
    fn test_find_word_boundaries_single_word() {
        let boundaries = find_word_boundaries(b"hello");
        assert_eq!(boundaries, vec![0, 5]);
    }

    #[test]
    fn test_find_word_boundaries_multiple_spaces() {
        let boundaries = find_word_boundaries(b"a  b");
        assert_eq!(boundaries, vec![0, 1, 3, 4]);
    }

    #[test]
    fn test_finder_results_dots() {
        let chunk = b"example.com and test.org";
        let mut results = FinderResults::new(chunk);
        results.ensure(Finder::Dots);
        assert_eq!(results.dots(), &[7, 20]);
    }

    #[test]
    fn test_finder_results_at_signs() {
        let chunk = b"user@example.com and test@test.com";
        let mut results = FinderResults::new(chunk);
        results.ensure(Finder::AtSigns);
        assert_eq!(results.at_signs(), &[4, 25]);
    }

    #[test]
    fn test_finder_results_double_colons() {
        let chunk = b"addr 2001:db8::1 here";
        let mut results = FinderResults::new(chunk);
        results.ensure(Finder::DoubleColons);
        assert_eq!(results.double_colons(), &[13]);
    }

    #[test]
    fn test_finder_results_hex_prefix() {
        let chunk = b"eth 0x1234 and 0xabcd";
        let mut results = FinderResults::new(chunk);
        results.ensure(Finder::HexPrefix);
        assert_eq!(results.hex_prefixes(), &[4, 15]);
    }

    #[test]
    fn test_finder_results_caching() {
        let chunk = b"test.com";
        let mut results = FinderResults::new(chunk);
        results.ensure(Finder::Dots);
        let first = results.dots().to_vec();
        results.ensure(Finder::Dots); // Should not recompute
        let second = results.dots().to_vec();
        assert_eq!(first, second);
    }
}
