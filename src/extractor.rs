//! Fast extraction of structured patterns from log lines and text data.
//!
//! This module provides high-speed extraction of domains, IP addresses (IPv4/IPv6),
//! and emails from arbitrary text using Aho-Corasick anchor pattern matching followed
//! by fast boundary scanning.

use crate::error::ParaglobError;
use crate::glob::MatchMode;
use crate::paraglob_offset::Paraglob;
use std::net::{Ipv4Addr, Ipv6Addr};

/// Builder for PatternExtractor
pub struct PatternExtractorBuilder {
    extract_domains: bool,
    extract_emails: bool,
    extract_ipv4: bool,
    extract_ipv6: bool,
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
        // Use trusted mode since TLD_AUTOMATON is compiled into the binary
        let tld_matcher = if self.extract_domains {
            let paraglob = crate::serialization::from_bytes_trusted(
                TLD_AUTOMATON,
                MatchMode::CaseInsensitive,
            )?;
            Some(paraglob)
        } else {
            None
        };
        
        // Pre-build memchr finder for :: (IPv6)
        let double_colon_finder = memchr::memmem::Finder::new(b"::");

        Ok(PatternExtractor {
            extract_domains: self.extract_domains,
            extract_emails: self.extract_emails,
            extract_ipv4: self.extract_ipv4,
            extract_ipv6: self.extract_ipv6,
            min_domain_labels: self.min_domain_labels,
            require_word_boundaries: self.require_word_boundaries,
            tld_matcher,
            double_colon_finder,
            tld_match_buffer: std::cell::RefCell::new(Vec::with_capacity(16)),
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
    min_domain_labels: usize,
    require_word_boundaries: bool,
    /// TLD matcher (Paraglob with all public suffixes)
    tld_matcher: Option<Paraglob>,
    /// Pre-built memchr finder for :: (IPv6 compression)
    double_colon_finder: memchr::memmem::Finder<'static>,
    /// Reusable buffer for TLD matching (avoids per-line allocation)
    tld_match_buffer: std::cell::RefCell<Vec<(usize, u32)>>,
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
    
    /// Extract patterns from a chunk (multiple lines) in one pass
    ///
    /// This is MUCH faster than processing line-by-line because:
    /// - One memchr/memmem scan for all anchor patterns (::, @, .)
    /// - Better cache locality and SIMD efficiency
    /// - Amortized initialization overhead
    ///
    /// Returns matches with absolute byte positions in the chunk.
    ///
    /// # Example
    /// ```ignore
    /// let chunk = b"line1\nline2\nline3";
    /// let matches = extractor.extract_from_chunk(chunk);
    /// ```
    pub fn extract_from_chunk<'a>(&'a self, chunk: &'a [u8]) -> Vec<Match<'a>> {
        let mut matches = Vec::new();
        
        // Extract IPv6 (::) in one pass over entire chunk
        if self.extract_ipv6 {
            self.extract_ipv6_chunk(chunk, &mut matches);
        }
        
        // Extract IPv4 (.) in one pass
        if self.extract_ipv4 {
            self.extract_ipv4_chunk(chunk, &mut matches);
        }
        
        // Extract emails (@) in one pass
        if self.extract_emails {
            self.extract_emails_chunk(chunk, &mut matches);
        }
        
        // Domains still use AC per-line for now (more complex)
        if self.extract_domains {
            // Fall back to line-by-line for domains
            // TODO: Could optimize this too with chunk-wide AC
            for line in chunk.split(|&b| b == b'\n') {
                self.extract_domains_internal(line, &mut matches);
            }
        }
        
        matches
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
        // OPTIMIZATION: Reuse buffer across lines to avoid per-line allocation
        let mut tld_buffer = self.tld_match_buffer.borrow_mut();
        tld_matcher.find_matches_with_positions_bytes_into(line, &mut tld_buffer);

        for &(tld_end, _pattern_id) in tld_buffer.iter() {
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
                
                // Reject bare TLDs (e.g., ".app", ".com")
                // A valid domain must have at least one label before the TLD
                if domain_bytes[0] == b'.' {
                    continue;
                }

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

    /// Expand backwards from TLD end to find domain start using fast lookup table
    /// Scans backwards using branch-free boundary detection for optimal performance
    fn expand_domain_backwards(&self, line: &[u8], tld_end: usize) -> Option<(usize, usize)> {
        if tld_end == 0 {
            return None;
        }

        // DNS standard max length is 253 chars; use this as scan limit
        const MAX_DOMAIN_LEN: usize = 253;
        let scan_limit = tld_end.saturating_sub(MAX_DOMAIN_LEN);
        let mut start = tld_end;

        // OPTIMIZED: Single pass with whitelist lookup table
        // Only accept valid domain characters (alphanumeric, hyphen, dot, UTF-8)
        while start > scan_limit {
            let b = line[start - 1];

            // Use whitelist: only continue if it's a valid domain char
            // This rejects % and other invalid chars like in "Kagi%20Assistant.app"
            if !is_domain_char_fast(b) {
                break;
            }

            start -= 1;
        }

        // Check word boundary at end if required (also uses fast lookup)
        if self.require_word_boundaries && tld_end < line.len() && !is_boundary_fast(line[tld_end])
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

            // Find actual end (only digits and dots)
            let mut candidate_end = start;
            while candidate_end < line.len() && (line[candidate_end].is_ascii_digit() || line[candidate_end] == b'.') {
                candidate_end += 1;
            }
            
            let candidate = &line[start..candidate_end];
            
            // Early validation before expensive parsing:
            
            // 1. Must have exactly 3 dots (4 octets)
            let dot_count = memchr::memchr_iter(b'.', candidate).count();
            if dot_count != 3 {
                last_end = candidate_end;
                continue;
            }
            
            // 2. Can't have consecutive dots (e.g., "26.0..26.0")
            if candidate.windows(2).any(|w| w == b"..") {
                last_end = candidate_end;
                continue;
            }
            
            // 3. Can't start or end with dot
            if candidate.starts_with(b".") || candidate.ends_with(b".") {
                last_end = candidate_end;
                continue;
            }
            
            // 4. Each octet must be 1-3 digits
            // Walk through and count digits between dots
            // Filters: "2025.36.0.72591908" (4 and 8 digit octets), "460.1.1.2" (3 digits but >255)
            let mut octet_len = 0;
            let mut valid_octets = true;
            for &b in candidate {
                if b == b'.' {
                    // End of octet
                    if octet_len == 0 || octet_len > 3 {
                        valid_octets = false;
                        break;
                    }
                    octet_len = 0;
                } else {
                    octet_len += 1;
                }
            }
            // Check final octet
            if octet_len == 0 || octet_len > 3 {
                valid_octets = false;
            }
            if !valid_octets {
                last_end = candidate_end;
                continue;
            }

            // Now try full parse from the start of this number sequence
            if let Some((ip, end)) = self.try_parse_ipv4(line, start) {
                matches.push(Match {
                    item: ExtractedItem::Ipv4(ip),
                    span: (start, end),
                });
                last_end = end;
            } else {
                // Failed validation - skip dots in this failed region
                last_end = candidate_end;
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

        let local_part = &line[start..at_pos];
        let domain_part = &line[at_pos + 1..end];
        
        // Validate local part:
        // 1. No consecutive dots (e.g., "s...@")
        if local_part.windows(2).any(|w| w == b"..") {
            return None;
        }
        
        // 2. Must have at least one letter (not just dots/numbers/symbols)
        //    Filters: ".@..", "34480FE2-5610-4973-AA09-3ABB60D38D55@" is OK
        let has_letter = local_part.iter().any(|&b| b.is_ascii_alphabetic());
        if !has_letter {
            return None;
        }
        
        // Validate domain part:
        // 1. Must have at least one dot
        if !domain_part.contains(&b'.') {
            return None;
        }
        
        // 2. Must have a valid TLD from the public suffix list
        //    This rejects IP addresses ("192.168.1.222") and fake TLDs ("Uv3.peer")
        if let Some(tld_matcher) = self.tld_matcher.as_ref() {
            let tld_matches = tld_matcher.find_matches_with_positions_bytes(domain_part);
            // Must have at least one TLD match that ends at the domain boundary
            let has_valid_tld = tld_matches.iter().any(|(end_pos, _)| {
                *end_pos == domain_part.len() && 
                (*end_pos >= domain_part.len() || !is_domain_char(domain_part[*end_pos]))
            });
            if !has_valid_tld {
                return None;
            }
        }

        Some((start, end))
    }

    /// Extract IPv6 addresses: only look for :: (double colon compression)
    /// 
    /// Strategy: >95% of real IPv6 uses :: compression. This is the sweet spot:
    /// - High signal (rarely appears in non-IPv6 text)
    /// - Blazing fast (memchr finds :: in microseconds)
    /// - Simple (no regex overhead, no false positives)
    /// 
    /// Filters out loopback (::1) and link-local (fe80::/10) addresses before parsing.
    fn extract_ipv6_internal<'a>(&self, line: &'a [u8], matches: &mut Vec<Match<'a>>) {
        // Only look for :: (double colon) - present in >95% of real IPv6
        // Use pre-built finder to avoid repeated initialization
        let mut last_end = 0;
        
        for double_colon_pos in self.double_colon_finder.find_iter(line) {
            if double_colon_pos < last_end {
                continue;
            }
            
            // Quick validation: must have hex digit before OR after ::
            let has_hex_before = double_colon_pos > 0 && line[double_colon_pos - 1].is_ascii_hexdigit();
            let has_hex_after = double_colon_pos + 2 < line.len() && line[double_colon_pos + 2].is_ascii_hexdigit();
            
            if !has_hex_before && !has_hex_after {
                last_end = double_colon_pos + 2;
                continue;
            }
            
            // Find start of candidate by scanning backwards
            let mut start = double_colon_pos;
            while start > 0 {
                let c = line[start - 1];
                if !c.is_ascii_hexdigit() && c != b':' {
                    break;
                }
                start -= 1;
            }
            
            // Find end by scanning forwards
            let mut end = double_colon_pos + 2;
            while end < line.len() {
                let c = line[end];
                if !c.is_ascii_hexdigit() && c != b':' {
                    break;
                }
                end += 1;
            }
            
            let candidate = &line[start..end];
            
            // Minimum length check - reject short addresses like ::1, a::b
            if candidate.len() < 8 {
                last_end = end;
                continue;
            }
            
            // FAST PRE-FILTER: Reject loopback and link-local by prefix before parsing
            // This avoids expensive parse for common non-routable addresses
            if is_ipv6_loopback_or_linklocal(candidate) {
                last_end = end;
                continue;
            }
            
            // Try to parse
            if let Ok(candidate_str) = std::str::from_utf8(candidate) {
                if let Ok(ip) = candidate_str.parse::<Ipv6Addr>() {
                    matches.push(Match {
                        item: ExtractedItem::Ipv6(ip),
                        span: (start, end),
                    });
                    last_end = end;
                    continue;
                }
            }
            
            // Skip past this :: to avoid rechecking
            last_end = double_colon_pos + 2;
        }
    }
    
    // ===== CHUNK-BASED EXTRACTION METHODS =====
    // These process entire chunks (multiple lines) in one pass for better performance
    
    /// Extract IPv6 addresses from entire chunk in one pass
    fn extract_ipv6_chunk<'a>(&'a self, chunk: &'a [u8], matches: &mut Vec<Match<'a>>) {
        let mut last_end = 0;
        
        // Single scan for all :: in the chunk
        for double_colon_pos in self.double_colon_finder.find_iter(chunk) {
            if double_colon_pos < last_end {
                continue;
            }
            
            // Quick validation
            let has_hex_before = double_colon_pos > 0 && chunk[double_colon_pos - 1].is_ascii_hexdigit();
            let has_hex_after = double_colon_pos + 2 < chunk.len() && chunk[double_colon_pos + 2].is_ascii_hexdigit();
            
            if !has_hex_before && !has_hex_after {
                last_end = double_colon_pos + 2;
                continue;
            }
            
            // Find boundaries
            let mut start = double_colon_pos;
            while start > 0 {
                let c = chunk[start - 1];
                if !c.is_ascii_hexdigit() && c != b':' {
                    break;
                }
                start -= 1;
            }
            
            let mut end = double_colon_pos + 2;
            while end < chunk.len() {
                let c = chunk[end];
                if !c.is_ascii_hexdigit() && c != b':' {
                    break;
                }
                end += 1;
            }
            
            let candidate = &chunk[start..end];
            
            if candidate.len() < 8 {
                last_end = end;
                continue;
            }
            
            // FAST PRE-FILTER: Reject loopback and link-local by prefix before parsing
            if is_ipv6_loopback_or_linklocal(candidate) {
                last_end = end;
                continue;
            }
            
            // Try to parse
            if let Ok(candidate_str) = std::str::from_utf8(candidate) {
                if let Ok(ip) = candidate_str.parse::<Ipv6Addr>() {
                    matches.push(Match {
                        item: ExtractedItem::Ipv6(ip),
                        span: (start, end),
                    });
                    last_end = end;
                    continue;
                }
            }
            
            last_end = double_colon_pos + 2;
        }
    }
    
    /// Extract IPv4 addresses from entire chunk in one pass
    fn extract_ipv4_chunk<'a>(&'a self, chunk: &'a [u8], matches: &mut Vec<Match<'a>>) {
        use memchr::memchr_iter;
        
        let mut last_end = 0;
        
        // Single scan for all dots in the chunk
        for dot_pos in memchr_iter(b'.', chunk) {
            if dot_pos == 0 || dot_pos + 6 > chunk.len() {
                continue;
            }
            
            // Quick check: digit.digit
            if !chunk[dot_pos - 1].is_ascii_digit() || !chunk[dot_pos + 1].is_ascii_digit() {
                continue;
            }
            
            // Count dots in window
            let window_start = dot_pos.saturating_sub(3);
            let window_end = (dot_pos + 12).min(chunk.len());
            let window = &chunk[window_start..window_end];
            let dot_count = memchr_iter(b'.', window).count();
            
            if dot_count < 3 {
                continue;
            }
            
            // Find start
            let mut start = dot_pos;
            while start > 0 && (chunk[start - 1].is_ascii_digit() || chunk[start - 1] == b'.') {
                start -= 1;
            }
            
            if start < last_end {
                continue;
            }
            
            // Try parse using existing helper
            if let Some((ip, end)) = self.try_parse_ipv4(chunk, start) {
                matches.push(Match {
                    item: ExtractedItem::Ipv4(ip),
                    span: (start, end),
                });
                last_end = end;
            }
        }
    }
    
    /// Extract emails from entire chunk in one pass
    fn extract_emails_chunk<'a>(&'a self, chunk: &'a [u8], matches: &mut Vec<Match<'a>>) {
        use memchr::memchr_iter;
        
        // Single scan for all @ in the chunk
        for at_pos in memchr_iter(b'@', chunk) {
            if let Some(email_span) = self.extract_email_at(chunk, at_pos) {
                if let Ok(email_str) = std::str::from_utf8(&chunk[email_span.0..email_span.1]) {
                    matches.push(Match {
                        item: ExtractedItem::Email(email_str),
                        span: email_span,
                    });
                }
            }
        }
    }

}

/// Fast pre-filter for IPv6 loopback and link-local addresses
/// 
/// Checks byte prefixes to reject before expensive parsing:
/// - Loopback: ::1 (appears as "::1" with length 3)
/// - Link-local: fe80::/10 (starts with "fe8" or "fe9" or "fea" or "feb")
/// 
/// This is much faster than parsing and then checking is_loopback()/is_link_local().
#[inline]
fn is_ipv6_loopback_or_linklocal(candidate: &[u8]) -> bool {
    // Check for ::1 (loopback) - exact match
    if candidate.len() == 3 && candidate == b"::1" {
        return true;
    }
    
    // Check for link-local fe80::/10
    // Link-local addresses start with: fe80, fe81, ..., febf
    // In practice, most use fe80, so check that first
    if candidate.len() >= 4 {
        let prefix = &candidate[0..4];
        
        // Fast path: fe80 (most common link-local prefix)
        if prefix.eq_ignore_ascii_case(b"fe80") {
            return true;
        }
        
        // Check fe8x, fe9x, feax, febx (full fe80::/10 range)
        if candidate.len() >= 3 {
            let first_three = &candidate[0..3];
            if first_three.eq_ignore_ascii_case(b"fe8") ||
               first_three.eq_ignore_ascii_case(b"fe9") ||
               first_three.eq_ignore_ascii_case(b"fea") ||
               first_three.eq_ignore_ascii_case(b"feb") {
                return true;
            }
        }
    }
    
    false
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

        // Extract IPv6 addresses
        if extractor.extract_ipv6 {
            extractor.extract_ipv6_internal(line, &mut matches);
        }

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
// Aligned wrapper ensures ACNode reads are naturally aligned
// ACNode requires 8-byte alignment (repr(C) with 32-byte size)
#[repr(align(8))]
struct AlignedTldData([u8; include_bytes!("data/tld_automaton.ac").len()]);

static TLD_AUTOMATON_ALIGNED: AlignedTldData =
    AlignedTldData(*include_bytes!("data/tld_automaton.ac"));

const TLD_AUTOMATON: &[u8] = &TLD_AUTOMATON_ALIGNED.0;

/// Compile-time boundary character lookup table for O(1) checking
/// This replaces the branch-heavy is_word_boundary() function with a single array lookup.
/// Marked as boundary: whitespace, punctuation commonly found in logs
static BOUNDARY_LOOKUP: [bool; 256] = {
    let mut table = [false; 256];
    // Whitespace characters
    table[b' ' as usize] = true;
    table[b'\t' as usize] = true;
    table[b'\n' as usize] = true;
    table[b'\r' as usize] = true;
    // Punctuation and delimiters
    table[b'/' as usize] = true;
    table[b',' as usize] = true;
    table[b';' as usize] = true;
    table[b':' as usize] = true;
    table[b'(' as usize] = true;
    table[b')' as usize] = true;
    table[b'[' as usize] = true;
    table[b']' as usize] = true;
    table[b'{' as usize] = true;
    table[b'}' as usize] = true;
    table[b'<' as usize] = true;
    table[b'>' as usize] = true;
    table[b'"' as usize] = true;
    table[b'\'' as usize] = true;
    table[b'@' as usize] = true;  // Stop domain extraction at @ (emails)
    table[b'=' as usize] = true;  // Stop at = (key-value pairs: domain=example.com)
    table
};

/// Domain character whitelist - only alphanumeric, hyphen, dot, and high UTF-8 bytes
/// Used for fast backward scanning from TLD matches
static DOMAIN_CHAR_LOOKUP: [bool; 256] = {
    let mut table = [false; 256];
    // Digits: 0-9
    let mut i = b'0';
    while i <= b'9' {
        table[i as usize] = true;
        i += 1;
    }
    // Lowercase: a-z
    i = b'a';
    while i <= b'z' {
        table[i as usize] = true;
        i += 1;
    }
    // Uppercase: A-Z
    i = b'A';
    while i <= b'Z' {
        table[i as usize] = true;
        i += 1;
    }
    // Special chars
    table[b'-' as usize] = true;  // Hyphen in labels
    table[b'.' as usize] = true;  // Dot separator
    
    // High bytes (0x80-0xFF) for IDN domains (UTF-8 continuation bytes)
    i = 0x80;
    while i < 0xFF {
        table[i as usize] = true;
        i += 1;
    }
    table[0xFF] = true;
    table
};

/// Fast boundary check using lookup table (branch-free, O(1))
#[inline(always)]
fn is_boundary_fast(b: u8) -> bool {
    // SAFETY: b is u8, so it's always a valid index into [0..256)
    unsafe { *BOUNDARY_LOOKUP.get_unchecked(b as usize) }
}

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
    // Delegate to fast lookup table
    is_boundary_fast(b)
}

/// Fast domain character check using lookup table (branch-free, O(1))
/// Returns true for valid domain chars: 0-9, a-z, A-Z, hyphen, dot, UTF-8 high bytes
#[inline(always)]
fn is_domain_char_fast(b: u8) -> bool {
    // SAFETY: b is u8, so it's always a valid index into [0..256)
    unsafe { *DOMAIN_CHAR_LOOKUP.get_unchecked(b as usize) }
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

    #[test]
    fn test_ipv6_extraction_basic() {
        let extractor = PatternExtractor::new().unwrap();

        // Use compressed notation (::) which is present in >95% of real IPv6 addresses
        let line = b"Server at 2001:db8:85a3::8a2e:370:7334 responded";
        let matches: Vec<_> = extractor.extract_from_line(line).collect();

        let ips: Vec<Ipv6Addr> = matches
            .iter()
            .filter_map(|m| match m.item {
                ExtractedItem::Ipv6(ip) => Some(ip),
                _ => None,
            })
            .collect();

        assert_eq!(ips.len(), 1);
        assert_eq!(ips[0].to_string(), "2001:db8:85a3::8a2e:370:7334");
    }

    #[test]
    fn test_ipv6_extraction_compressed() {
        let extractor = PatternExtractor::new().unwrap();

        let line = b"Connecting to 2001:db8::1";
        let matches: Vec<_> = extractor.extract_from_line(line).collect();

        let ips: Vec<Ipv6Addr> = matches
            .iter()
            .filter_map(|m| match m.item {
                ExtractedItem::Ipv6(ip) => Some(ip),
                _ => None,
            })
            .collect();

        assert_eq!(ips.len(), 1);
        assert_eq!(ips[0].to_string(), "2001:db8::1");
    }

    #[test]
    fn test_ipv6_extraction_realistic() {
        let extractor = PatternExtractor::new().unwrap();

        // Use realistic global unicast addresses with :: compression (not loopback/link-local)
        let line = b"Address 2001:0db8::1 connects to 2606:2800:220:1::248";
        let matches: Vec<_> = extractor.extract_from_line(line).collect();

        let ips: Vec<Ipv6Addr> = matches
            .iter()
            .filter_map(|m| match m.item {
                ExtractedItem::Ipv6(ip) => Some(ip),
                _ => None,
            })
            .collect();

        // Should extract both global unicast addresses
        assert_eq!(ips.len(), 2);
        assert_eq!(ips[0].to_string(), "2001:db8::1");
        assert_eq!(ips[1].to_string(), "2606:2800:220:1::248");
    }

    #[test]
    fn test_ipv6_extraction_multiple() {
        let extractor = PatternExtractor::new().unwrap();

        let line = b"Traffic from 2001:db8::1 to 2001:db8::2";
        let matches: Vec<_> = extractor.extract_from_line(line).collect();

        let ips: Vec<Ipv6Addr> = matches
            .iter()
            .filter_map(|m| match m.item {
                ExtractedItem::Ipv6(ip) => Some(ip),
                _ => None,
            })
            .collect();

        assert_eq!(ips.len(), 2);
        assert_eq!(ips[0].to_string(), "2001:db8::1");
        assert_eq!(ips[1].to_string(), "2001:db8::2");
    }

    #[test]
    fn test_mixed_ipv4_ipv6_extraction() {
        let extractor = PatternExtractor::new().unwrap();

        let line = b"IPv4: 192.168.1.1 IPv6: 2001:db8::1";
        let matches: Vec<_> = extractor.extract_from_line(line).collect();

        let ipv4s: Vec<Ipv4Addr> = matches
            .iter()
            .filter_map(|m| match m.item {
                ExtractedItem::Ipv4(ip) => Some(ip),
                _ => None,
            })
            .collect();

        let ipv6s: Vec<Ipv6Addr> = matches
            .iter()
            .filter_map(|m| match m.item {
                ExtractedItem::Ipv6(ip) => Some(ip),
                _ => None,
            })
            .collect();

        assert_eq!(ipv4s.len(), 1);
        assert_eq!(ipv6s.len(), 1);
        assert_eq!(ipv4s[0].to_string(), "192.168.1.1");
        assert_eq!(ipv6s[0].to_string(), "2001:db8::1");
    }

    // Tests for prefiltered invalid patterns (from comment examples)

    #[test]
    fn test_reject_ipv4_with_4_and_8_digit_octets() {
        let extractor = PatternExtractor::new().unwrap();

        // Line 423 filter: "2025.36.0.72591908" (4 and 8 digit octets)
        let line = b"Invalid IP: 2025.36.0.72591908";
        let matches: Vec<_> = extractor.extract_from_line(line).collect();

        let ips: Vec<Ipv4Addr> = matches
            .iter()
            .filter_map(|m| match m.item {
                ExtractedItem::Ipv4(ip) => Some(ip),
                _ => None,
            })
            .collect();

        assert_eq!(ips.len(), 0, "Should reject IPv4 with 4 and 8 digit octets");
    }

    #[test]
    fn test_reject_ipv4_with_octet_over_255() {
        let extractor = PatternExtractor::new().unwrap();

        // Line 423 filter: "460.1.1.2" (3 digits but >255)
        let line = b"Invalid IP: 460.1.1.2";
        let matches: Vec<_> = extractor.extract_from_line(line).collect();

        let ips: Vec<Ipv4Addr> = matches
            .iter()
            .filter_map(|m| match m.item {
                ExtractedItem::Ipv4(ip) => Some(ip),
                _ => None,
            })
            .collect();

        assert_eq!(ips.len(), 0, "Should reject IPv4 with octet > 255");
    }

    #[test]
    fn test_reject_ipv4_with_consecutive_dots() {
        let extractor = PatternExtractor::new().unwrap();

        // Line 410 filter: "26.0..26.0" (consecutive dots)
        let line = b"Invalid IP: 26.0..26.0";
        let matches: Vec<_> = extractor.extract_from_line(line).collect();

        let ips: Vec<Ipv4Addr> = matches
            .iter()
            .filter_map(|m| match m.item {
                ExtractedItem::Ipv4(ip) => Some(ip),
                _ => None,
            })
            .collect();

        assert_eq!(ips.len(), 0, "Should reject IPv4 with consecutive dots");
    }

    #[test]
    fn test_reject_email_with_consecutive_dots_in_local() {
        let extractor = PatternExtractor::new().unwrap();

        // Line 578 filter: "s...@" (consecutive dots in local part)
        let line = b"Invalid email: s...@example.com";
        let matches: Vec<_> = extractor.extract_from_line(line).collect();

        let emails: Vec<&str> = matches
            .iter()
            .filter_map(|m| match m.item {
                ExtractedItem::Email(e) => Some(e),
                _ => None,
            })
            .collect();

        assert_eq!(emails.len(), 0, "Should reject email with consecutive dots in local part");
    }

    #[test]
    fn test_reject_email_without_letter_in_local() {
        let extractor = PatternExtractor::new().unwrap();

        // Line 578 filter: ".@.." (no letter in local part)
        let line = b"Invalid email: .@example.com";
        let matches: Vec<_> = extractor.extract_from_line(line).collect();

        let emails: Vec<&str> = matches
            .iter()
            .filter_map(|m| match m.item {
                ExtractedItem::Email(e) => Some(e),
                _ => None,
            })
            .collect();

        assert_eq!(emails.len(), 0, "Should reject email without letter in local part");
    }

    #[test]
    fn test_accept_email_with_uuid_in_local() {
        let extractor = PatternExtractor::new().unwrap();

        // Line 578 comment: "34480FE2-5610-4973-AA09-3ABB60D38D55@" is OK
        let line = b"Valid email: 34480FE2-5610-4973-AA09-3ABB60D38D55@example.com";
        let matches: Vec<_> = extractor.extract_from_line(line).collect();

        let emails: Vec<&str> = matches
            .iter()
            .filter_map(|m| match m.item {
                ExtractedItem::Email(e) => Some(e),
                _ => None,
            })
            .collect();

        assert_eq!(emails.len(), 1, "Should accept email with UUID containing letters");
        assert_eq!(emails[0], "34480FE2-5610-4973-AA09-3ABB60D38D55@example.com");
    }

    #[test]
    fn test_reject_email_with_ip_address_domain() {
        let extractor = PatternExtractor::new().unwrap();

        // Line 591 filter: "192.168.1.222" (IP address as domain)
        let line = b"Invalid email: user@192.168.1.222";
        let matches: Vec<_> = extractor.extract_from_line(line).collect();

        let emails: Vec<&str> = matches
            .iter()
            .filter_map(|m| match m.item {
                ExtractedItem::Email(e) => Some(e),
                _ => None,
            })
            .collect();

        assert_eq!(emails.len(), 0, "Should reject email with IP address as domain");
    }

    #[test]
    fn test_reject_email_with_fake_tld() {
        let extractor = PatternExtractor::new().unwrap();

        // Line 591 filter: "Uv3.peer" (fake TLD)
        let line = b"Invalid email: test@Uv3.peer";
        let matches: Vec<_> = extractor.extract_from_line(line).collect();

        let emails: Vec<&str> = matches
            .iter()
            .filter_map(|m| match m.item {
                ExtractedItem::Email(e) => Some(e),
                _ => None,
            })
            .collect();

        assert_eq!(emails.len(), 0, "Should reject email with fake TLD");
    }

    #[test]
    fn test_reject_tiny_ipv6_addresses() {
        let extractor = PatternExtractor::new().unwrap();

        // Line 654 filters: "e::f" (4 bytes), "ce::A" (5 bytes), "e::add" (6 bytes)
        let test_cases = [
            b"Tiny IPv6: e::f" as &[u8],
            b"Tiny IPv6: ce::A" as &[u8],
            b"Tiny IPv6: e::add" as &[u8],
        ];

        for line in test_cases {
            let matches: Vec<_> = extractor.extract_from_line(line).collect();

            let ips: Vec<Ipv6Addr> = matches
                .iter()
                .filter_map(|m| match m.item {
                    ExtractedItem::Ipv6(ip) => Some(ip),
                    _ => None,
                })
                .collect();

            assert_eq!(ips.len(), 0, "Should reject tiny IPv6 addresses (< 8 bytes)");
        }
    }

    #[test]
    fn test_reject_ipv6_with_12_digit_segment() {
        let extractor = PatternExtractor::new().unwrap();

        // Line 689 filter: "FEC0050519FB::c" (12-digit segment)
        let line = b"Invalid IPv6: FEC0050519FB::c";
        let matches: Vec<_> = extractor.extract_from_line(line).collect();

        let ips: Vec<Ipv6Addr> = matches
            .iter()
            .filter_map(|m| match m.item {
                ExtractedItem::Ipv6(ip) => Some(ip),
                _ => None,
            })
            .collect();

        assert_eq!(ips.len(), 0, "Should reject IPv6 with segment > 4 hex digits");
    }

    #[test]
    fn test_reject_ipv6_with_8_digit_segment() {
        let extractor = PatternExtractor::new().unwrap();

        // Line 689 filter: "7::31BD71E4" (8-digit segment)
        let line = b"Invalid IPv6: 7::31BD71E4";
        let matches: Vec<_> = extractor.extract_from_line(line).collect();

        let ips: Vec<Ipv6Addr> = matches
            .iter()
            .filter_map(|m| match m.item {
                ExtractedItem::Ipv6(ip) => Some(ip),
                _ => None,
            })
            .collect();

        assert_eq!(ips.len(), 0, "Should reject IPv6 with segment > 4 hex digits");
    }

    #[test]
    fn test_reject_domain_with_percent_encoding() {
        let extractor = PatternExtractor::new().unwrap();

        // Line 274 comment: "Kagi%20Assistant.app" (% is invalid in domain chars)
        let line = b"Invalid domain: Kagi%20Assistant.app";
        let matches: Vec<_> = extractor.extract_from_line(line).collect();

        let domains: Vec<&str> = matches
            .iter()
            .filter_map(|m| match m.item {
                ExtractedItem::Domain(d) => Some(d),
                _ => None,
            })
            .collect();

        // Should only extract "Assistant.app" after the %20, not the full string
        assert!(
            !domains.iter().any(|d| d.contains('%')),
            "Should not extract domain with percent encoding"
        );
    }

    #[test]
    fn test_reject_bare_tld() {
        let extractor = PatternExtractor::new().unwrap();

        // Line 240 filter: bare TLDs like ".app", ".com"
        let line = b"Visit .app or .com for info";
        let matches: Vec<_> = extractor.extract_from_line(line).collect();

        let domains: Vec<&str> = matches
            .iter()
            .filter_map(|m| match m.item {
                ExtractedItem::Domain(d) => Some(d),
                _ => None,
            })
            .collect();

        // Should not extract bare TLDs
        assert!(
            !domains.iter().any(|d| d.starts_with('.')),
            "Should not extract bare TLDs"
        );
        assert_eq!(domains.len(), 0, "Should reject bare TLDs");
    }

    #[test]
    fn test_reject_link_local_ipv6() {
        let extractor = PatternExtractor::new().unwrap();

        // Line 713 filter: fe80::/10 link-local addresses
        let line = b"Link-local address: fe80::1 and fe80::dead:beef";
        let matches: Vec<_> = extractor.extract_from_line(line).collect();

        let ips: Vec<Ipv6Addr> = matches
            .iter()
            .filter_map(|m| match m.item {
                ExtractedItem::Ipv6(ip) => Some(ip),
                _ => None,
            })
            .collect();

        assert_eq!(ips.len(), 0, "Should reject link-local IPv6 addresses (fe80::/10)");
    }
}
