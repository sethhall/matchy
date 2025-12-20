//! Email address extraction.

use crate::finders::{Finder, FinderResults};
use crate::psl::find_valid_tld_suffix_bytes;
use crate::types::{ExtractedItem, Match};
use crate::util::{is_domain_char, is_email_local_char, is_word_boundary};

use super::PatternExtractor;

pub struct EmailExtractor {
    pub require_word_boundaries: bool,
}

impl EmailExtractor {
    pub fn new(require_word_boundaries: bool) -> Self {
        Self {
            require_word_boundaries,
        }
    }

    fn extract_email_at(&self, line: &[u8], at_pos: usize) -> Option<(usize, usize)> {
        let mut start = at_pos;
        while start > 0 && is_email_local_char(line[start - 1]) {
            start -= 1;
        }

        if start == at_pos {
            return None;
        }

        if self.require_word_boundaries && start > 0 && !is_word_boundary(line[start - 1]) {
            return None;
        }

        let mut end = at_pos + 1;
        while end < line.len() && is_domain_char(line[end]) {
            end += 1;
        }

        if end == at_pos + 1 {
            return None;
        }

        if self.require_word_boundaries && end < line.len() && !is_word_boundary(line[end]) {
            return None;
        }

        let local_part = &line[start..at_pos];
        let domain_part = &line[at_pos + 1..end];

        if local_part.windows(2).any(|w| w == b"..") {
            return None;
        }

        let has_letter = local_part.iter().any(|&b| b.is_ascii_alphabetic());
        if !has_letter {
            return None;
        }

        if !domain_part.contains(&b'.') {
            return None;
        }

        find_valid_tld_suffix_bytes(domain_part)?;

        Some((start, end))
    }
}

impl PatternExtractor for EmailExtractor {
    fn required_finders(&self) -> &'static [Finder] {
        &[Finder::AtSigns]
    }

    fn extract<'a>(&self, results: &FinderResults<'a>, matches: &mut Vec<Match<'a>>) {
        let chunk = results.chunk;
        let at_signs = results.at_signs();

        for &at_pos in at_signs {
            if let Some(email_span) = self.extract_email_at(chunk, at_pos) {
                if let Ok(email_str) = std::str::from_utf8(&chunk[email_span.0..email_span.1]) {
                    matches.push(Match::new(
                        ExtractedItem::Email(email_str),
                        email_span.0,
                        email_span.1,
                    ));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn extract_emails(input: &[u8]) -> Vec<String> {
        let extractor = EmailExtractor::new(true);
        let mut results = FinderResults::new(input);
        results.ensure(Finder::AtSigns);
        let mut matches = Vec::new();
        extractor.extract(&results, &mut matches);
        matches
            .iter()
            .filter_map(|m| match &m.item {
                ExtractedItem::Email(e) => Some(e.to_string()),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn test_email_extraction_basic() {
        let emails = extract_emails(b"Contact user@example.com for info");
        assert_eq!(emails, vec!["user@example.com"]);
    }

    #[test]
    fn test_email_extraction_multiple() {
        let emails = extract_emails(b"Email alice@test.com or bob@company.org");
        assert_eq!(emails, vec!["alice@test.com", "bob@company.org"]);
    }

    #[test]
    fn test_email_with_plus() {
        let emails = extract_emails(b"Send to user+tag@example.com");
        assert_eq!(emails, vec!["user+tag@example.com"]);
    }

    #[test]
    fn test_email_reject_consecutive_dots() {
        let emails = extract_emails(b"Invalid email: s...@example.com");
        assert!(emails.is_empty());
    }

    #[test]
    fn test_email_reject_no_letter() {
        let emails = extract_emails(b"Invalid email: .@example.com");
        assert!(emails.is_empty());
    }

    #[test]
    fn test_email_accept_uuid_local() {
        let emails =
            extract_emails(b"Valid email: 34480FE2-5610-4973-AA09-3ABB60D38D55@example.com");
        assert_eq!(emails.len(), 1);
    }

    #[test]
    fn test_email_reject_ip_domain() {
        let emails = extract_emails(b"Invalid email: user@192.168.1.222");
        assert!(emails.is_empty());
    }

    #[test]
    fn test_email_reject_fake_tld() {
        let emails = extract_emails(b"Invalid email: test@Uv3.peer");
        assert!(emails.is_empty());
    }
}
