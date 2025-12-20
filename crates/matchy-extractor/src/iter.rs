//! Iterator over extracted patterns in a line.

use crate::extractors::ExtractorKind;
use crate::finders::FinderResults;
use crate::types::Match;

pub struct ExtractIter<'a> {
    matches: Vec<Match<'a>>,
    current_idx: usize,
}

impl<'a> ExtractIter<'a> {
    pub fn new(extractors: &[ExtractorKind], line: &'a [u8]) -> Self {
        let mut matches = Vec::new();

        let mut results = FinderResults::new(line);

        for extractor in extractors {
            for finder in extractor.required_finders() {
                results.ensure(*finder);
            }
        }

        for extractor in extractors {
            extractor.extract(&results, &mut matches);
        }

        Self {
            matches,
            current_idx: 0,
        }
    }
}

impl<'a> Iterator for ExtractIter<'a> {
    type Item = Match<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current_idx < self.matches.len() {
            let match_item = self.matches[self.current_idx].clone();
            self.current_idx += 1;
            Some(match_item)
        } else {
            None
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.matches.len() - self.current_idx;
        (remaining, Some(remaining))
    }
}

impl<'a> ExactSizeIterator for ExtractIter<'a> {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extractors::{DomainExtractor, Ipv4Extractor};
    use crate::types::ExtractedItem;

    #[test]
    fn test_extract_iter_basic() {
        let extractors = vec![
            ExtractorKind::Domain(DomainExtractor::new(2, true)),
            ExtractorKind::Ipv4(Ipv4Extractor::new(true)),
        ];

        let line = b"Check example.com and 192.168.1.1";
        let iter = ExtractIter::new(&extractors, line);
        let matches: Vec<_> = iter.collect();

        assert!(matches.len() >= 2);

        let has_domain = matches
            .iter()
            .any(|m| matches!(m.item, ExtractedItem::Domain(_)));
        let has_ip = matches
            .iter()
            .any(|m| matches!(m.item, ExtractedItem::Ipv4(_)));

        assert!(has_domain);
        assert!(has_ip);
    }

    #[test]
    fn test_extract_iter_size_hint() {
        let extractors = vec![ExtractorKind::Domain(DomainExtractor::new(2, true))];

        let line = b"Visit google.com and github.com";
        let iter = ExtractIter::new(&extractors, line);

        assert_eq!(iter.size_hint(), (2, Some(2)));
    }

    #[test]
    fn test_extract_iter_empty() {
        let extractors = vec![ExtractorKind::Domain(DomainExtractor::new(2, true))];

        let line = b"No domains here";
        let iter = ExtractIter::new(&extractors, line);
        let matches: Vec<_> = iter.collect();

        assert!(matches.is_empty());
    }
}
