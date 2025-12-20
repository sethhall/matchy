//! IPv4 address extraction.

use std::net::Ipv4Addr;

use crate::finders::{Finder, FinderResults};
use crate::types::{ExtractedItem, Match};
use crate::util::is_word_boundary;

use super::PatternExtractor;

pub struct Ipv4Extractor {
    pub require_word_boundaries: bool,
}

impl Ipv4Extractor {
    pub fn new(require_word_boundaries: bool) -> Self {
        Self {
            require_word_boundaries,
        }
    }

    fn try_parse_ipv4(&self, line: &[u8], start: usize) -> Option<(Ipv4Addr, usize)> {
        let mut pos = start;
        let mut octets = [0u8; 4];

        if self.require_word_boundaries && start > 0 && !is_word_boundary(line[start - 1]) {
            return None;
        }

        for (octet_idx, octet) in octets.iter_mut().enumerate() {
            let mut octet_value: u16 = 0;
            let mut digit_count = 0;
            let octet_start = pos;

            while pos < line.len() && line[pos].is_ascii_digit() && digit_count < 3 {
                let digit = u16::from(line[pos] - b'0');
                octet_value = octet_value * 10 + digit;
                pos += 1;
                digit_count += 1;
            }

            if digit_count == 0 {
                return None;
            }

            if digit_count > 1 && line[octet_start] == b'0' {
                return None;
            }

            *octet = u8::try_from(octet_value).ok()?;

            if octet_idx < 3 {
                if pos >= line.len() || line[pos] != b'.' {
                    return None;
                }
                pos += 1;
            }
        }

        if self.require_word_boundaries && pos < line.len() && !is_word_boundary(line[pos]) {
            return None;
        }

        let ip = Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]);
        Some((ip, pos))
    }
}

impl PatternExtractor for Ipv4Extractor {
    fn required_finders(&self) -> &'static [Finder] {
        &[Finder::Dots]
    }

    fn extract<'a>(&self, results: &FinderResults<'a>, matches: &mut Vec<Match<'a>>) {
        let chunk = results.chunk;
        let dots = results.dots();

        let mut last_end = 0;

        for (i, &dot_pos) in dots.iter().enumerate() {
            if dot_pos == 0 || dot_pos + 6 > chunk.len() {
                continue;
            }

            if !chunk[dot_pos - 1].is_ascii_digit() || !chunk[dot_pos + 1].is_ascii_digit() {
                continue;
            }

            let mut start = dot_pos;
            while start > 0 && (chunk[start - 1].is_ascii_digit() || chunk[start - 1] == b'.') {
                start -= 1;
            }

            if start < last_end {
                continue;
            }

            let end_search = (start + 15).min(chunk.len());
            let dots_in_range = dots[i..]
                .iter()
                .take_while(|&&pos| pos < end_search)
                .count();

            if dots_in_range < 3 {
                continue;
            }

            if let Some((ip, end)) = self.try_parse_ipv4(chunk, start) {
                matches.push(Match::new(ExtractedItem::Ipv4(ip), start, end));
                last_end = end;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn extract_ipv4s(input: &[u8]) -> Vec<Ipv4Addr> {
        let extractor = Ipv4Extractor::new(true);
        let mut results = FinderResults::new(input);
        results.ensure(Finder::Dots);
        let mut matches = Vec::new();
        extractor.extract(&results, &mut matches);
        matches
            .iter()
            .filter_map(|m| match &m.item {
                ExtractedItem::Ipv4(ip) => Some(*ip),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn test_ipv4_extraction_basic() {
        let ips = extract_ipv4s(b"Server at 192.168.1.1 responded");
        assert_eq!(ips.len(), 1);
        assert_eq!(ips[0].to_string(), "192.168.1.1");
    }

    #[test]
    fn test_ipv4_extraction_multiple() {
        let ips = extract_ipv4s(b"Traffic from 10.0.0.5 to 172.16.0.10");
        assert_eq!(ips.len(), 2);
        assert_eq!(ips[0].to_string(), "10.0.0.5");
        assert_eq!(ips[1].to_string(), "172.16.0.10");
    }

    #[test]
    fn test_ipv4_invalid() {
        let ips = extract_ipv4s(b"Not IPs: 256.1.1.1 1.2.3.999 1.2.3");
        assert!(ips.is_empty());
    }

    #[test]
    fn test_ipv4_reject_leading_zeros() {
        let ips = extract_ipv4s(b"Invalid: 192.168.01.1");
        assert!(ips.is_empty());
    }

    #[test]
    fn test_ipv4_reject_4_digit_octets() {
        let ips = extract_ipv4s(b"Invalid IP: 2025.36.0.72591908");
        assert!(ips.is_empty());
    }

    #[test]
    fn test_ipv4_reject_consecutive_dots() {
        let ips = extract_ipv4s(b"Invalid IP: 26.0..26.0");
        assert!(ips.is_empty());
    }
}
