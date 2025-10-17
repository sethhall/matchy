//! Fast extraction of structured patterns from log lines and text data.
//!
//! This module provides high-speed extraction of domains, IP addresses, emails,
//! and URLs from arbitrary text using Aho-Corasick anchor pattern matching followed
//! by fast boundary scanning.

use crate::error::ParaglobError;
use crate::glob::MatchMode;
use crate::paraglob_offset::Paraglob;
use crate::serialization::from_bytes;
use std::net::{Ipv4Addr, Ipv6Addr};

/// Builder for PatternExtractor
pub struct PatternExtractorBuilder {
    extract_domains: bool,
    extract_emails: bool,
    extract_ipv4: bool,
    extract_ipv6: bool,
    extract_urls: bool,
    require_valid_tld: bool,
    min_domain_labels: usize,
    require_word_boundaries: bool,
}

impl PatternExtractorBuilder {
    /// Create a new builder with default configuration
    pub fn new() -> Self {
        Self {
            extract_domains: true,
            extract_emails: true,
            extract_ipv4: true,
            extract_ipv6: true,
            extract_urls: true,
            require_valid_tld: true,
            min_domain_labels: 2,
            require_word_boundaries: true,
        }
    }

    /// Enable or disable domain extraction
    pub fn extract_domains(mut self, enable: bool) -> Self {
        self.extract_domains = enable;
        self
    }

    /// Enable or disable email extraction
    pub fn extract_emails(mut self, enable: bool) -> Self {
        self.extract_emails = enable;
        self
    }

    /// Enable or disable IPv4 extraction
    pub fn extract_ipv4(mut self, enable: bool) -> Self {
        self.extract_ipv4 = enable;
        self
    }

    /// Enable or disable IPv6 extraction
    pub fn extract_ipv6(mut self, enable: bool) -> Self {
        self.extract_ipv6 = enable;
        self
    }

    /// Enable or disable URL extraction
    pub fn extract_urls(mut self, enable: bool) -> Self {
        self.extract_urls = enable;
        self
    }

    /// Require domain TLDs to be in Public Suffix List
    pub fn require_valid_tld(mut self, require: bool) -> Self {
        self.require_valid_tld = require;
        self
    }

    /// Set minimum number of domain labels (e.g., 2 for "example.com")
    pub fn min_domain_labels(mut self, min: usize) -> Self {
        self.min_domain_labels = min;
        self
    }

    /// Require word boundaries around extracted patterns
    pub fn require_word_boundaries(mut self, require: bool) -> Self {
        self.require_word_boundaries = require;
        self
    }

    /// Build the PatternExtractor
    pub fn build(self) -> Result<PatternExtractor, ParaglobError> {
        // Load embedded TLD automaton if domain extraction enabled
        let tld_matcher = if self.extract_domains {
            let paraglob = from_bytes(TLD_AUTOMATON, MatchMode::CaseInsensitive)?;
            Some(paraglob)
        } else {
            None
        };

        Ok(PatternExtractor {
            extract_domains: self.extract_domains,
            extract_emails: self.extract_emails,
            extract_ipv4: self.extract_ipv4,
            extract_ipv6: self.extract_ipv6,
            extract_urls: self.extract_urls,
            require_valid_tld: self.require_valid_tld,
            min_domain_labels: self.min_domain_labels,
            require_word_boundaries: self.require_word_boundaries,
            tld_matcher,
        })
    }
}

impl Default for PatternExtractorBuilder {
    fn default() -> Self {
        Self::new()
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
    /// URL (e.g., "<https://example.com/path>")
    Url(&'a str),
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
    /// Get the matched text as a string slice
    pub fn as_str(&self, input: &'a [u8]) -> &'a str {
        // Safe because we validated UTF-8 during extraction
        unsafe { std::str::from_utf8_unchecked(&input[self.span.0..self.span.1]) }
    }
}

/// Fast pattern extractor using Aho-Corasick anchor matching
pub struct PatternExtractor {
    // Configuration fields
    extract_domains: bool,
    extract_emails: bool,
    extract_ipv4: bool,
    extract_ipv6: bool,
    extract_urls: bool,
    require_valid_tld: bool,
    min_domain_labels: usize,
    require_word_boundaries: bool,
    /// TLD matcher (Paraglob with all public suffixes)
    tld_matcher: Option<Paraglob>,
}

impl PatternExtractor {
    /// Create a new extractor with default configuration
    pub fn new() -> Result<Self, ParaglobError> {
        Self::builder().build()
    }

    /// Create a builder for custom configuration
    pub fn builder() -> PatternExtractorBuilder {
        PatternExtractorBuilder::new()
    }

    /// Extract patterns from a line using an iterator (zero-allocation)
    ///
    /// Returns an iterator that lazily extracts matches as you iterate.
    /// This is more efficient than collecting into a Vec.
    ///
    /// # Example
    /// ```ignore
    /// for match_item in extractor.extract_from_line(line) {
    ///     // Process each match
    /// }
    /// ```
    pub fn extract_from_line<'a>(&'a self, line: &'a [u8]) -> ExtractIter<'a> {
        ExtractIter::new(self, line)
    }

    /// Check if domain extraction is enabled
    pub fn extract_domains(&self) -> bool {
        self.extract_domains
    }

    /// Check if email extraction is enabled
    pub fn extract_emails(&self) -> bool {
        self.extract_emails
    }

    /// Check if IPv4 extraction is enabled
    pub fn extract_ipv4(&self) -> bool {
        self.extract_ipv4
    }

    /// Check if IPv6 extraction is enabled
    pub fn extract_ipv6(&self) -> bool {
        self.extract_ipv6
    }

    /// Check if URL extraction is enabled
    pub fn extract_urls(&self) -> bool {
        self.extract_urls
    }

    /// Get minimum domain labels requirement
    pub fn min_domain_labels(&self) -> usize {
        self.min_domain_labels
    }

    /// Extract domains by finding TLD anchors and expanding boundaries
    fn extract_domains_internal<'a>(&self, line: &'a [u8], matches: &mut Vec<Match<'a>>) {
        use memchr::memchr;

        let tld_matcher = match self.tld_matcher.as_ref() {
            Some(m) => m,
            None => return,
        };

        // Quick pre-filter: skip if no dots at all (domains need at least one)
        // This SIMD check is extremely fast and saves TLD matching on lines without domains
        if memchr(b'.', line).is_none() {
            return;
        }

        // Find all TLD suffix matches with positions using byte-based matching
        // No UTF-8 validation needed - AC works on raw bytes
        // Returns (end_position, pattern_id) for each TLD match
        let tld_matches = tld_matcher.find_matches_with_positions_bytes(line);

        for (tld_end, _pattern_id) in tld_matches {
            // e.g., "evil.example.com" with ".com" match gives tld_end = 18

            // Fast boundary check: TLD must be followed by non-domain char or end of line
            // This rejects false positives like "blah.community" (.com matches but continues)
            // Single byte check is much faster than backward scan
            if tld_end < line.len() && is_domain_char(line[tld_end]) {
                continue; // TLD continues with domain chars - not a real TLD boundary
            }

            // Expand backwards to find domain start
            if let Some(domain_span) = self.expand_domain_backwards(line, tld_end) {
                let domain_bytes = &line[domain_span.0..domain_span.1];

                // Validate UTF-8 only on the domain candidate (not the whole line!)
                // This is a small slice (10-30 bytes typically) vs entire KB lines
                let domain_str = match std::str::from_utf8(domain_bytes) {
                    Ok(s) => s,
                    Err(_) => continue, // Invalid UTF-8 in domain - skip
                };

                // Validate the extracted domain (label checks, etc.)
                if self.is_valid_domain(line, domain_span) {
                    matches.push(Match {
                        item: ExtractedItem::Domain(domain_str),
                        span: domain_span,
                    });
                }
            }
        }
    }

    /// Expand backwards from TLD end to find domain start
    /// Walks through all bytes (ASCII + UTF-8) until hitting a boundary character
    fn expand_domain_backwards(&self, line: &[u8], tld_end: usize) -> Option<(usize, usize)> {
        if tld_end == 0 {
            return None;
        }

        // Find the start of the domain by scanning backwards
        let mut start = tld_end;

        // Walk backwards through all bytes until we hit a boundary
        // This includes:
        // - ASCII alphanumeric, hyphen, dot
        // - UTF-8 start bytes (0xC0-0xFF)
        // - UTF-8 continuation bytes (0x80-0xBF)
        // We stop at ASCII boundary characters (whitespace, punctuation)
        while start > 0 {
            let b = line[start - 1];

            // Stop at ASCII boundary characters
            if b.is_ascii() && is_word_boundary(b) {
                break;
            }

            // Continue through:
            // - ASCII alphanumeric/hyphen/dot
            // - All UTF-8 bytes (0x80-0xFF)
            start -= 1;
        }

        // Check word boundary at end if required
        if self.require_word_boundaries
            && tld_end < line.len()
            && !is_word_boundary(line[tld_end])
        {
            return None; // Domain continues - not a real boundary
        }

        if start >= tld_end {
            return None; // Empty domain
        }

        Some((start, tld_end))
    }

    /// Validate an extracted domain candidate
    fn is_valid_domain(&self, line: &[u8], span: (usize, usize)) -> bool {
        let domain_bytes = &line[span.0..span.1];

        // Note: UTF-8 validation is unnecessary here because:
        // 1. The entire line was validated as UTF-8 before TLD matching (line 234)
        // 2. is_valid_label() enforces ASCII-only ([a-z0-9-]), which is always valid UTF-8
        // 3. Punycode domains (xn--*) are ASCII, and we don't decode them

        // Validate labels without allocating - iterate and count simultaneously
        let mut label_count = 0;
        let mut label_start = 0;

        for (i, &byte) in domain_bytes.iter().enumerate() {
            if byte == b'.' {
                // Validate the label we just passed
                if !self.is_valid_label(&domain_bytes[label_start..i]) {
                    return false;
                }
                label_count += 1;
                label_start = i + 1;
            }
        }

        // Validate final label (after last dot or entire domain if no dots)
        if !self.is_valid_label(&domain_bytes[label_start..]) {
            return false;
        }
        label_count += 1;

        // Check minimum label count
        label_count >= self.min_domain_labels
    }

    /// Validate a single domain label (bytes between dots)
    #[inline]
    fn is_valid_label(&self, label: &[u8]) -> bool {
        if label.is_empty() {
            return false; // Empty label (e.g., "..")
        }

        // Label can't start or end with hyphen
        if label[0] == b'-' || label[label.len() - 1] == b'-' {
            return false;
        }

        // That's it! We already validated:
        // - TLD is from trusted PSL
        // - Boundaries are correct (word boundaries)
        // - UTF-8 is valid (checked before calling this)
        // No need to validate individual characters - if it has a valid TLD
        // and valid boundaries, it's a domain
        true
    }

    /// Extract IPv4 addresses using SIMD-accelerated dot search
    /// Strategy: Find dots (rare), check for digit.digit pattern, then parse
    fn extract_ipv4_internal<'a>(&self, line: &'a [u8], matches: &mut Vec<Match<'a>>) {
        use memchr::memchr_iter;

        // Track last parsed end position to skip overlapping candidates
        let mut last_end = 0;

        // Find all dots using SIMD - much faster than scanning every byte
        for dot_pos in memchr_iter(b'.', line) {
            // Quick reject: need space for at least "1.2.3.4" (7 chars)
            if dot_pos == 0 || dot_pos + 6 > line.len() {
                continue;
            }

            // Quick check: is this dot between digits? (digit.digit pattern)
            if !line[dot_pos - 1].is_ascii_digit() || !line[dot_pos + 1].is_ascii_digit() {
                continue;
            }

            // Look for at least 3 dots in a reasonable window around this position
            // This is a strong signal of an IP address
            let window_start = dot_pos.saturating_sub(3);
            let window_end = (dot_pos + 12).min(line.len());
            let window = &line[window_start..window_end];

            // Count dots in window (we need 3 total for an IPv4)
            let dot_count = memchr_iter(b'.', window).count();
            if dot_count < 3 {
                continue; // Not enough dots for a full IP
            }

            // High confidence this is near an IP - find start of number sequence
            let mut start = dot_pos;
            while start > 0 && (line[start - 1].is_ascii_digit() || line[start - 1] == b'.') {
                start -= 1;
            }

            // Skip if we already parsed this area
            if start < last_end {
                continue;
            }

            // Now try full parse from the start of this number sequence
            if let Some((ip, end)) = self.try_parse_ipv4(line, start) {
                matches.push(Match {
                    item: ExtractedItem::Ipv4(ip),
                    span: (start, end),
                });
                last_end = end;
            }
        }
    }

    /// Try to parse an IPv4 address starting at position
    fn try_parse_ipv4(&self, line: &[u8], start: usize) -> Option<(Ipv4Addr, usize)> {
        let mut pos = start;
        let mut octets = Vec::new();

        // Check word boundary at start if required
        if self.require_word_boundaries && start > 0 && !is_word_boundary(line[start - 1]) {
            return None;
        }

        // Parse up to 4 octets
        for octet_idx in 0..4 {
            // Parse octet (1-3 digits)
            let mut octet_str = String::new();
            let mut digit_count = 0;

            while pos < line.len() && line[pos].is_ascii_digit() && digit_count < 3 {
                octet_str.push(line[pos] as char);
                pos += 1;
                digit_count += 1;
            }

            if digit_count == 0 {
                return None; // No digits found
            }

            // Parse octet value (u8::parse already ensures 0-255 range)
            let octet: u8 = match octet_str.parse() {
                Ok(val) => val,
                _ => return None, // Invalid octet
            };

            octets.push(octet);

            // Expect dot after first 3 octets
            if octet_idx < 3 {
                if pos >= line.len() || line[pos] != b'.' {
                    return None; // Missing dot
                }
                pos += 1; // Skip dot
            }
        }

        // Check word boundary at end if required
        if self.require_word_boundaries && pos < line.len() && !is_word_boundary(line[pos]) {
            return None;
        }

        if octets.len() == 4 {
            let ip = Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]);
            Some((ip, pos))
        } else {
            None
        }
    }

    /// Extract email addresses using SIMD-accelerated @ search
    fn extract_emails_internal<'a>(&self, line: &'a [u8], matches: &mut Vec<Match<'a>>) {
        use memchr::memchr_iter;

        // Find all @ symbols using SIMD - much faster than scanning every byte
        for at_pos in memchr_iter(b'@', line) {
            // Found @, try to extract email around it
            if let Some(email_span) = self.extract_email_at(line, at_pos) {
                // Validate UTF-8
                if let Ok(email_str) = std::str::from_utf8(&line[email_span.0..email_span.1]) {
                    matches.push(Match {
                        item: ExtractedItem::Email(email_str),
                        span: email_span,
                    });
                }
            }
        }
    }

    /// Extract email around @ symbol at given position
    fn extract_email_at(&self, line: &[u8], at_pos: usize) -> Option<(usize, usize)> {
        // Expand backwards for local part
        let mut start = at_pos;
        while start > 0 && is_email_local_char(line[start - 1]) {
            start -= 1;
        }

        if start == at_pos {
            return None; // Empty local part
        }

        // Check word boundary at start if required
        if self.require_word_boundaries && start > 0 && !is_word_boundary(line[start - 1]) {
            return None;
        }

        // Expand forwards for domain part
        let mut end = at_pos + 1;
        while end < line.len() && is_domain_char(line[end]) {
            end += 1;
        }

        if end == at_pos + 1 {
            return None; // Empty domain part
        }

        // Check word boundary at end if required
        if self.require_word_boundaries && end < line.len() && !is_word_boundary(line[end]) {
            return None;
        }

        // Validate domain part has at least one dot and valid TLD
        let domain_part = &line[at_pos + 1..end];
        if !domain_part.contains(&b'.') {
            return None; // Domain must have at least one dot
        }

        Some((start, end))
    }
}


/// Iterator over extracted patterns in a line
///
/// Lazily extracts patterns as you iterate, avoiding allocation
/// when not all matches are needed.
pub struct ExtractIter<'a> {
    #[allow(dead_code)]
    extractor: &'a PatternExtractor,
    #[allow(dead_code)]
    line: &'a [u8],
    matches: Vec<Match<'a>>,
    current_idx: usize,
}

impl<'a> ExtractIter<'a> {
    fn new(extractor: &'a PatternExtractor, line: &'a [u8]) -> Self {
        // Extract all matches upfront into a Vec
        // We can optimize this later to be truly lazy if needed
        let mut matches = Vec::new();

        // Extract domains if enabled
        if extractor.extract_domains {
            extractor.extract_domains_internal(line, &mut matches);
        }

        // Extract IPv4 addresses
        if extractor.extract_ipv4 {
            extractor.extract_ipv4_internal(line, &mut matches);
        }

        // Extract email addresses
        if extractor.extract_emails {
            extractor.extract_emails_internal(line, &mut matches);
        }

        // TODO: Extract IPv6, URLs

        Self {
            extractor,
            line,
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

// Embedded TLD automaton - generated by cargo update-psl
const TLD_AUTOMATON: &[u8] = include_bytes!("data/tld_automaton.ac");

/// Character classification helpers for fast boundary scanning
#[inline]
fn is_domain_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-' || b == b'.'
}

#[inline]
fn is_email_local_char(b: u8) -> bool {
    // Simplified RFC 5322 - common chars in local part
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b'+')
}

#[inline]
fn is_word_boundary(b: u8) -> bool {
    b.is_ascii_whitespace()
        || matches!(
            b,
            b'/' | b','
                | b';'
                | b':'
                | b'('
                | b')'
                | b'['
                | b']'
                | b'{'
                | b'}'
                | b'<'
                | b'>'
                | b'"'
                | b'\''
                | b'@'  // Stop domain extraction at @ (emails)
                | b'=' // Stop at = (key-value pairs: domain=example.com)
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extractor_creation() {
        let extractor = PatternExtractor::new().unwrap();
        assert!(extractor.extract_domains());
    }

    #[test]
    fn test_builder() {
        let extractor = PatternExtractor::builder()
            .extract_domains(true)
            .extract_emails(false)
            .min_domain_labels(3)
            .build()
            .unwrap();

        assert!(extractor.extract_domains());
        assert!(!extractor.extract_emails());
        assert_eq!(extractor.min_domain_labels(), 3);
    }

    #[test]
    fn test_character_classification() {
        assert!(is_domain_char(b'a'));
        assert!(is_domain_char(b'0'));
        assert!(is_domain_char(b'-'));
        assert!(is_domain_char(b'.'));
        assert!(!is_domain_char(b'@'));
        assert!(!is_domain_char(b' '));

        assert!(is_email_local_char(b'a'));
        assert!(is_email_local_char(b'+'));
        assert!(!is_email_local_char(b'@'));

        assert!(is_word_boundary(b' '));
        assert!(is_word_boundary(b','));
        assert!(!is_word_boundary(b'a'));
    }

    #[test]
    fn test_domain_extraction_basic() {
        let extractor = PatternExtractor::new().unwrap();

        let line = b"Visit example.com for more info";
        let matches: Vec<_> = extractor.extract_from_line(line).collect();

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].as_str(line), "example.com");
        match matches[0].item {
            ExtractedItem::Domain(d) => assert_eq!(d, "example.com"),
            _ => panic!("Expected domain"),
        }
    }

    #[test]
    fn test_domain_extraction_multiple() {
        let extractor = PatternExtractor::new().unwrap();

        let line = b"Check google.com and github.com";
        let matches: Vec<_> = extractor.extract_from_line(line).collect();

        assert_eq!(matches.len(), 2);
        assert_eq!(matches[0].as_str(line), "google.com");
        assert_eq!(matches[1].as_str(line), "github.com");
    }

    #[test]
    fn test_domain_extraction_subdomain() {
        let extractor = PatternExtractor::new().unwrap();

        let line = b"Visit api.example.com today";
        let matches: Vec<_> = extractor.extract_from_line(line).collect();

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].as_str(line), "api.example.com");
    }

    #[test]
    fn test_domain_extraction_with_protocol() {
        let extractor = PatternExtractor::new().unwrap();

        let line = b"Go to https://www.example.com/path";
        let matches: Vec<_> = extractor.extract_from_line(line).collect();

        // Should extract just the domain, not the protocol or path
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].as_str(line), "www.example.com");
    }

    #[test]
    fn test_domain_min_labels() {
        let extractor = PatternExtractor::builder()
            .extract_domains(true)
            .min_domain_labels(3) // Require at least 3 labels
            .build()
            .unwrap();

        let line = b"Visit example.com and api.test.example.com";
        let matches: Vec<_> = extractor.extract_from_line(line).collect();

        // Only the 3-label domain should match
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].as_str(line), "api.test.example.com");
    }

    #[test]
    fn test_domain_extraction_log_line() {
        let extractor = PatternExtractor::new().unwrap();

        // Realistic log line
        let line =
            b"2024-01-15 10:32:45 GET /api evil.example.com 192.168.1.1 - malware.badsite.org";
        let matches: Vec<_> = extractor.extract_from_line(line).collect();

        assert!(matches.len() >= 2);
        // Should find both domains
        let domains: Vec<&str> = matches
            .iter()
            .filter_map(|m| match m.item {
                ExtractedItem::Domain(d) => Some(d),
                _ => None,
            })
            .collect();

        assert!(domains.contains(&"evil.example.com"));
        assert!(domains.contains(&"malware.badsite.org"));
    }

    #[test]
    fn test_ipv4_extraction_basic() {
        let extractor = PatternExtractor::new().unwrap();

        let line = b"Server at 192.168.1.1 responded";
        let matches: Vec<_> = extractor.extract_from_line(line).collect();

        // Should find the IP
        let ips: Vec<Ipv4Addr> = matches
            .iter()
            .filter_map(|m| match m.item {
                ExtractedItem::Ipv4(ip) => Some(ip),
                _ => None,
            })
            .collect();

        assert_eq!(ips.len(), 1);
        assert_eq!(ips[0].to_string(), "192.168.1.1");
    }

    #[test]
    fn test_ipv4_extraction_multiple() {
        let extractor = PatternExtractor::new().unwrap();

        let line = b"Traffic from 10.0.0.5 to 172.16.0.10";
        let matches: Vec<_> = extractor.extract_from_line(line).collect();

        let ips: Vec<Ipv4Addr> = matches
            .iter()
            .filter_map(|m| match m.item {
                ExtractedItem::Ipv4(ip) => Some(ip),
                _ => None,
            })
            .collect();

        assert_eq!(ips.len(), 2);
        assert_eq!(ips[0].to_string(), "10.0.0.5");
        assert_eq!(ips[1].to_string(), "172.16.0.10");
    }

    #[test]
    fn test_unicode_domain_extraction() {
        let extractor = PatternExtractor::new().unwrap();

        // German domain with umlaut (münchen.de in UTF-8)
        let line = "Visit münchen.de for info".as_bytes();
        let matches: Vec<_> = extractor.extract_from_line(line).collect();

        // Should extract the Unicode domain
        assert_eq!(matches.len(), 1);
        let domain = match matches[0].item {
            ExtractedItem::Domain(d) => d,
            _ => panic!("Expected domain"),
        };

        // Domain contains UTF-8 characters
        assert!(domain.contains("ünchen") || domain.contains("xn--"));
    }

    #[test]
    fn test_mixed_unicode_ascii_domains() {
        let extractor = PatternExtractor::new().unwrap();

        // Line with both ASCII and Unicode domains
        let line = "Check café.fr and example.com".as_bytes();
        let matches: Vec<_> = extractor.extract_from_line(line).collect();

        // Should extract both domains
        assert!(matches.len() >= 2);

        let domains: Vec<&str> = matches
            .iter()
            .filter_map(|m| match m.item {
                ExtractedItem::Domain(d) => Some(d),
                _ => None,
            })
            .collect();

        // ASCII domain should be extracted normally
        assert!(domains.iter().any(|d| d.contains("example.com")));
        // Unicode domain should be extracted (either as-is or punycode)
        assert!(domains
            .iter()
            .any(|d| d.contains("caf") || d.contains("xn--")));
    }

    #[test]
    fn test_binary_log_with_ascii_domain() {
        let extractor = PatternExtractor::new().unwrap();

        // Binary log line with non-UTF-8 bytes but ASCII domain
        let mut line = Vec::new();
        line.extend_from_slice(b"Log: ");
        line.push(0xFF); // Invalid UTF-8 byte
        line.push(0xFE); // Invalid UTF-8 byte
        line.extend_from_slice(b" evil.com ");
        line.push(0x80); // Invalid UTF-8 byte

        let matches: Vec<_> = extractor.extract_from_line(&line).collect();

        // Should still extract ASCII domain despite binary junk
        let domains: Vec<&str> = matches
            .iter()
            .filter_map(|m| match m.item {
                ExtractedItem::Domain(d) => Some(d),
                _ => None,
            })
            .collect();

        assert!(
            domains.contains(&"evil.com"),
            "Should extract ASCII domain from binary log"
        );
    }

    #[test]
    fn test_invalid_utf8_in_domain_rejected() {
        let extractor = PatternExtractor::new().unwrap();

        // Line with invalid UTF-8 sequence where domain would be
        let mut line = Vec::new();
        line.extend_from_slice(b"Visit ");
        line.push(0xFF); // Invalid UTF-8
        line.push(0xC0); // Invalid UTF-8
        line.extend_from_slice(b".com");

        let matches: Vec<_> = extractor.extract_from_line(&line).collect();

        // Should NOT extract domain with invalid UTF-8
        let domains: Vec<&str> = matches
            .iter()
            .filter_map(|m| match m.item {
                ExtractedItem::Domain(_) => Some("found"),
                _ => None,
            })
            .collect();

        assert_eq!(domains.len(), 0, "Should reject domain with invalid UTF-8");
    }

    #[test]
    fn test_false_positive_rejection() {
        let extractor = PatternExtractor::new().unwrap();

        // "blah.community" contains ".com" but shouldn't match as domain
        let line = b"This is blah.community stuff";
        let matches: Vec<_> = extractor.extract_from_line(line).collect();

        let domains: Vec<&str> = matches
            .iter()
            .filter_map(|m| match m.item {
                ExtractedItem::Domain(d) => Some(d),
                _ => None,
            })
            .collect();

        // Should NOT extract "blah.com" - our boundary check should prevent this
        assert!(
            !domains.iter().any(|d| d.ends_with(".com")),
            "Should not extract .com from .community"
        );
    }

    #[test]
    fn test_key_value_pair_extraction() {
        let extractor = PatternExtractor::new().unwrap();

        // Common log format with key=value pairs
        let line = b"Request: host=api.example.com method=GET path=/test";
        let matches: Vec<_> = extractor.extract_from_line(line).collect();

        let domains: Vec<&str> = matches
            .iter()
            .filter_map(|m| match m.item {
                ExtractedItem::Domain(d) => Some(d),
                _ => None,
            })
            .collect();

        // Should extract just the domain, not including the "host=" prefix
        assert_eq!(domains.len(), 1);
        assert_eq!(domains[0], "api.example.com");
        // Verify it doesn't include the = sign
        assert!(!domains[0].contains('='));
    }

    #[test]
    fn test_ipv4_invalid() {
        let extractor = PatternExtractor::new().unwrap();

        // Invalid IPs should not match
        let line = b"Not IPs: 256.1.1.1 1.2.3.999 1.2.3";
        let matches: Vec<_> = extractor.extract_from_line(line).collect();

        let ips: Vec<Ipv4Addr> = matches
            .iter()
            .filter_map(|m| match m.item {
                ExtractedItem::Ipv4(ip) => Some(ip),
                _ => None,
            })
            .collect();

        assert_eq!(ips.len(), 0);
    }

    #[test]
    fn test_mixed_extraction() {
        let extractor = PatternExtractor::new().unwrap();

        // Mix of domains and IPs
        let line = b"Request from 10.1.2.3 to api.example.com at 192.168.1.100";
        let matches: Vec<_> = extractor.extract_from_line(line).collect();

        let ips: Vec<Ipv4Addr> = matches
            .iter()
            .filter_map(|m| match m.item {
                ExtractedItem::Ipv4(ip) => Some(ip),
                _ => None,
            })
            .collect();

        let domains: Vec<&str> = matches
            .iter()
            .filter_map(|m| match m.item {
                ExtractedItem::Domain(d) => Some(d),
                _ => None,
            })
            .collect();

        assert_eq!(ips.len(), 2);
        assert_eq!(domains.len(), 1);
        assert_eq!(domains[0], "api.example.com");
    }

    #[test]
    fn test_email_extraction_basic() {
        let extractor = PatternExtractor::new().unwrap();

        let line = b"Contact user@example.com for info";
        let matches: Vec<_> = extractor.extract_from_line(line).collect();

        let emails: Vec<&str> = matches
            .iter()
            .filter_map(|m| match m.item {
                ExtractedItem::Email(e) => Some(e),
                _ => None,
            })
            .collect();

        assert_eq!(emails.len(), 1);
        assert_eq!(emails[0], "user@example.com");
    }

    #[test]
    fn test_email_extraction_multiple() {
        let extractor = PatternExtractor::new().unwrap();

        let line = b"Email alice@test.com or bob@company.org";
        let matches: Vec<_> = extractor.extract_from_line(line).collect();

        let emails: Vec<&str> = matches
            .iter()
            .filter_map(|m| match m.item {
                ExtractedItem::Email(e) => Some(e),
                _ => None,
            })
            .collect();

        assert_eq!(emails.len(), 2);
        assert_eq!(emails[0], "alice@test.com");
        assert_eq!(emails[1], "bob@company.org");
    }

    #[test]
    fn test_email_with_plus() {
        let extractor = PatternExtractor::new().unwrap();

        let line = b"Send to user+tag@example.com";
        let matches: Vec<_> = extractor.extract_from_line(line).collect();

        let emails: Vec<&str> = matches
            .iter()
            .filter_map(|m| match m.item {
                ExtractedItem::Email(e) => Some(e),
                _ => None,
            })
            .collect();

        assert_eq!(emails.len(), 1);
        assert_eq!(emails[0], "user+tag@example.com");
    }

    #[test]
    fn test_full_extraction() {
        let extractor = PatternExtractor::new().unwrap();

        // Realistic log line with everything
        let line = b"2024-01-15 user@example.com from 10.1.2.3 accessed api.test.com";
        let matches: Vec<_> = extractor.extract_from_line(line).collect();

        let emails: Vec<&str> = matches
            .iter()
            .filter_map(|m| match m.item {
                ExtractedItem::Email(e) => Some(e),
                _ => None,
            })
            .collect();

        let ips: Vec<Ipv4Addr> = matches
            .iter()
            .filter_map(|m| match m.item {
                ExtractedItem::Ipv4(ip) => Some(ip),
                _ => None,
            })
            .collect();

        let domains: Vec<&str> = matches
            .iter()
            .filter_map(|m| match m.item {
                ExtractedItem::Domain(d) => Some(d),
                _ => None,
            })
            .collect();

        assert_eq!(emails.len(), 1);
        assert_eq!(ips.len(), 1);
        assert_eq!(domains.len(), 2); // Both example.com (from email) and api.test.com

        assert_eq!(emails[0], "user@example.com");
        assert_eq!(ips[0].to_string(), "10.1.2.3");
        // Domains extracted from both email and standalone
        assert!(domains.contains(&"example.com"));
        assert!(domains.contains(&"api.test.com"));
    }
}
