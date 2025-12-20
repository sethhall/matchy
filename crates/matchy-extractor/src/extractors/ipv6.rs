//! IPv6 address extraction.

use std::net::Ipv6Addr;

use crate::finders::{Finder, FinderResults};
use crate::types::{ExtractedItem, Match};

use super::PatternExtractor;

pub struct Ipv6Extractor;

impl Ipv6Extractor {
    pub fn new() -> Self {
        Self
    }
}

impl Default for Ipv6Extractor {
    fn default() -> Self {
        Self::new()
    }
}

impl PatternExtractor for Ipv6Extractor {
    fn required_finders(&self) -> &'static [Finder] {
        &[Finder::DoubleColons]
    }

    fn extract<'a>(&self, results: &FinderResults<'a>, matches: &mut Vec<Match<'a>>) {
        let chunk = results.chunk;
        let double_colons = results.double_colons();

        let mut last_end = 0;

        for &double_colon_pos in double_colons {
            if double_colon_pos < last_end {
                continue;
            }

            let has_hex_before =
                double_colon_pos > 0 && chunk[double_colon_pos - 1].is_ascii_hexdigit();
            let has_hex_after = double_colon_pos + 2 < chunk.len()
                && chunk[double_colon_pos + 2].is_ascii_hexdigit();

            if !has_hex_before && !has_hex_after {
                last_end = double_colon_pos + 2;
                continue;
            }

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

            if candidate.starts_with(b"::") || candidate.ends_with(b"::") {
                last_end = end;
                continue;
            }

            if is_ipv6_loopback_or_linklocal(candidate) {
                last_end = end;
                continue;
            }

            if let Ok(candidate_str) = std::str::from_utf8(candidate) {
                if let Ok(ip) = candidate_str.parse::<Ipv6Addr>() {
                    matches.push(Match::new(ExtractedItem::Ipv6(ip), start, end));
                    last_end = end;
                    continue;
                }
            }

            last_end = double_colon_pos + 2;
        }
    }
}

#[inline]
fn is_ipv6_loopback_or_linklocal(candidate: &[u8]) -> bool {
    if candidate.len() == 3 && candidate == b"::1" {
        return true;
    }

    if candidate.len() >= 4 {
        let prefix = &candidate[0..4];

        if prefix.eq_ignore_ascii_case(b"fe80") {
            return true;
        }

        if candidate.len() >= 3 {
            let first_three = &candidate[0..3];
            if first_three.eq_ignore_ascii_case(b"fe8")
                || first_three.eq_ignore_ascii_case(b"fe9")
                || first_three.eq_ignore_ascii_case(b"fea")
                || first_three.eq_ignore_ascii_case(b"feb")
            {
                return true;
            }
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn extract_ipv6s(input: &[u8]) -> Vec<Ipv6Addr> {
        let extractor = Ipv6Extractor::new();
        let mut results = FinderResults::new(input);
        results.ensure(Finder::DoubleColons);
        let mut matches = Vec::new();
        extractor.extract(&results, &mut matches);
        matches
            .iter()
            .filter_map(|m| match &m.item {
                ExtractedItem::Ipv6(ip) => Some(*ip),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn test_ipv6_extraction_basic() {
        let ips = extract_ipv6s(b"Server at 2001:db8:85a3::8a2e:370:7334 responded");
        assert_eq!(ips.len(), 1);
        assert_eq!(ips[0].to_string(), "2001:db8:85a3::8a2e:370:7334");
    }

    #[test]
    fn test_ipv6_extraction_compressed() {
        let ips = extract_ipv6s(b"Connecting to 2001:db8::1");
        assert_eq!(ips.len(), 1);
        assert_eq!(ips[0].to_string(), "2001:db8::1");
    }

    #[test]
    fn test_ipv6_extraction_multiple() {
        let ips = extract_ipv6s(b"Traffic from 2001:db8::1 to 2001:db8::2");
        assert_eq!(ips.len(), 2);
    }

    #[test]
    fn test_ipv6_reject_tiny() {
        let ips = extract_ipv6s(b"Tiny IPv6: e::f");
        assert!(ips.is_empty());
    }

    #[test]
    fn test_ipv6_reject_link_local() {
        let ips = extract_ipv6s(b"Link-local address: fe80::1 and fe80::dead:beef");
        assert!(ips.is_empty());
    }

    #[test]
    fn test_ipv6_reject_12_digit_segment() {
        let ips = extract_ipv6s(b"Invalid IPv6: FEC0050519FB::c");
        assert!(ips.is_empty());
    }
}
