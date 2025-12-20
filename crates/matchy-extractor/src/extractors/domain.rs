//! Domain name extraction.

use crate::finders::{Finder, FinderResults};
use crate::psl::find_valid_tld_suffix_bytes;
use crate::types::{ExtractedItem, Match};
use crate::util::{is_boundary_fast, is_domain_char_fast};

use super::PatternExtractor;

pub struct DomainExtractor {
    pub min_labels: usize,
    pub require_word_boundaries: bool,
}

impl DomainExtractor {
    pub fn new(min_labels: usize, require_word_boundaries: bool) -> Self {
        Self {
            min_labels,
            require_word_boundaries,
        }
    }

    fn is_valid_domain(&self, domain_bytes: &[u8]) -> bool {
        let mut label_count = 0;
        let mut label_start = 0;

        for (i, &byte) in domain_bytes.iter().enumerate() {
            if byte == b'.' {
                if !self.is_valid_label(&domain_bytes[label_start..i]) {
                    return false;
                }
                label_count += 1;
                label_start = i + 1;
            }
        }

        if !self.is_valid_label(&domain_bytes[label_start..]) {
            return false;
        }
        label_count += 1;

        label_count >= self.min_labels
    }

    #[inline]
    fn is_valid_label(&self, label: &[u8]) -> bool {
        if label.is_empty() {
            return false;
        }
        if label[0] == b'-' || label[label.len() - 1] == b'-' {
            return false;
        }
        true
    }
}

impl PatternExtractor for DomainExtractor {
    fn required_finders(&self) -> &'static [Finder] {
        &[Finder::Dots]
    }

    fn extract<'a>(&self, results: &FinderResults<'a>, matches: &mut Vec<Match<'a>>) {
        let chunk = results.chunk;
        let dots = results.dots();

        let mut last_domain_end = 0;

        for &dot_pos in dots {
            if dot_pos < last_domain_end {
                continue;
            }

            let mut start = dot_pos;
            while start > 0 && is_domain_char_fast(chunk[start - 1]) {
                start -= 1;
            }

            let mut end = dot_pos + 1;
            while end < chunk.len() && is_domain_char_fast(chunk[end]) {
                end += 1;
            }

            if start >= dot_pos || end <= dot_pos + 1 {
                continue;
            }

            let candidate_bytes = &chunk[start..end];

            let tld_start = match find_valid_tld_suffix_bytes(candidate_bytes) {
                Some(pos) => pos,
                None => continue,
            };

            if tld_start == 0 {
                continue;
            }

            if self.require_word_boundaries {
                if start > 0 && !is_boundary_fast(chunk[start - 1]) {
                    continue;
                }
                if end < chunk.len() && !is_boundary_fast(chunk[end]) {
                    continue;
                }
            }

            if self.is_valid_domain(candidate_bytes) {
                if let Ok(candidate) = std::str::from_utf8(candidate_bytes) {
                    matches.push(Match::new(ExtractedItem::Domain(candidate), start, end));
                    last_domain_end = end;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn extract_domains(input: &[u8]) -> Vec<String> {
        let extractor = DomainExtractor::new(2, true);
        let mut results = FinderResults::new(input);
        results.ensure(Finder::Dots);
        let mut matches = Vec::new();
        extractor.extract(&results, &mut matches);
        matches
            .iter()
            .filter_map(|m| match &m.item {
                ExtractedItem::Domain(d) => Some(d.to_string()),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn test_domain_extraction_basic() {
        let domains = extract_domains(b"Visit example.com for more info");
        assert_eq!(domains, vec!["example.com"]);
    }

    #[test]
    fn test_domain_extraction_multiple() {
        let domains = extract_domains(b"Check google.com and github.com");
        assert_eq!(domains, vec!["google.com", "github.com"]);
    }

    #[test]
    fn test_domain_extraction_subdomain() {
        let domains = extract_domains(b"Visit api.example.com today");
        assert_eq!(domains, vec!["api.example.com"]);
    }

    #[test]
    fn test_domain_extraction_with_protocol() {
        let domains = extract_domains(b"Go to https://www.example.com/path");
        assert_eq!(domains, vec!["www.example.com"]);
    }

    #[test]
    fn test_domain_min_labels() {
        let extractor = DomainExtractor::new(3, true);
        let input = b"Visit example.com and api.test.example.com";
        let mut results = FinderResults::new(input);
        results.ensure(Finder::Dots);
        let mut matches = Vec::new();
        extractor.extract(&results, &mut matches);
        let domains: Vec<_> = matches
            .iter()
            .filter_map(|m| match &m.item {
                ExtractedItem::Domain(d) => Some(*d),
                _ => None,
            })
            .collect();
        assert_eq!(domains, vec!["api.test.example.com"]);
    }

    #[test]
    fn test_false_positive_rejection() {
        let domains = extract_domains(b"This is blah.community stuff");
        assert!(
            !domains.iter().any(|d| d.ends_with(".com")),
            "Should not extract .com from .community"
        );
    }

    #[test]
    fn test_key_value_pair_extraction() {
        let domains = extract_domains(b"Request: host=api.example.com method=GET");
        assert_eq!(domains, vec!["api.example.com"]);
    }

    #[test]
    fn test_reject_bare_tld() {
        let domains = extract_domains(b"Visit .app or .com for info");
        assert!(domains.is_empty());
    }

    #[test]
    fn test_unicode_domain() {
        let domains = extract_domains("Visit münchen.de for info".as_bytes());
        assert_eq!(domains.len(), 1);
        assert!(domains[0].contains("ünchen") || domains[0].contains("xn--"));
    }
}
