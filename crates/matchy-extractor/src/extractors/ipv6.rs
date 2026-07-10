//! IPv6 address extraction.

use std::net::Ipv6Addr;

use crate::finders::{Finder, FinderResults};
use crate::types::{ExtractedItem, Match};

use super::PatternExtractor;

const UNCOMPRESSED_COLON_COUNT: usize = 7;
const COLON_DENSITY_BLOCK_SIZE: usize = 16;
const COLON_DENSITY_WINDOW_BLOCKS: usize = 3;
const BYTE_LOW_BITS: u128 = 0x7f7f_7f7f_7f7f_7f7f_7f7f_7f7f_7f7f_7f7f;
const BYTE_HIGH_BITS: u128 = 0x8080_8080_8080_8080_8080_8080_8080_8080;
const COLON_BYTES: u128 = 0x3a3a_3a3a_3a3a_3a3a_3a3a_3a3a_3a3a_3a3a;
const FIRST_BYTE_HIGH_BIT: u128 = 1 << 7;
const LAST_BYTE_HIGH_BIT: u128 = 1 << 127;

/// Extracts compressed and uncompressed IPv6 addresses from byte slices.
pub struct Ipv6Extractor {
    double_colon_finder: memchr::memmem::Finder<'static>,
}

impl Ipv6Extractor {
    /// Creates an IPv6 extractor.
    #[must_use]
    pub fn new() -> Self {
        Self {
            double_colon_finder: memchr::memmem::Finder::new(b"::"),
        }
    }
}

impl Default for Ipv6Extractor {
    fn default() -> Self {
        Self::new()
    }
}

impl PatternExtractor for Ipv6Extractor {
    fn required_finders(&self) -> &'static [Finder] {
        &[]
    }

    fn extract<'a>(&self, results: &FinderResults<'a>, matches: &mut Vec<Match<'a>>) {
        let chunk = results.chunk;
        if memchr::memchr(b':', chunk).is_none() {
            return;
        }

        let ipv6_match_start = matches.len();
        let double_colons: Vec<_> = self.double_colon_finder.find_iter(chunk).collect();
        let mut skip_until = 0;
        for &double_colon_pos in &double_colons {
            if double_colon_pos < skip_until {
                continue;
            }
            skip_until = extract_compressed_candidate(chunk, double_colon_pos, matches);
        }

        let compressed_match_end = matches.len();
        extract_uncompressed_candidates(chunk, matches);

        if compressed_match_end > ipv6_match_start && matches.len() > compressed_match_end {
            matches[ipv6_match_start..].sort_unstable_by_key(|matched| matched.span.0);
        }
    }
}

fn extract_uncompressed_candidates<'a>(chunk: &'a [u8], matches: &mut Vec<Match<'a>>) {
    let mut active_range = None;
    let block_count = chunk.len().div_ceil(COLON_DENSITY_BLOCK_SIZE);
    let mut density_counts = [0; COLON_DENSITY_WINDOW_BLOCKS];
    let mut previous_mask = 0;
    let mut current_mask = colon_mask(block_at(chunk, 0));
    let mut next_mask = colon_mask(block_at(chunk, 1));

    for block_index in 0..block_count {
        density_counts[block_index % COLON_DENSITY_WINDOW_BLOCKS] =
            single_colon_count(current_mask, previous_mask, next_mask);

        if density_counts.iter().sum::<usize>() >= UNCOMPRESSED_COLON_COUNT {
            // The first and seventh separators of an uncompressed address are
            // at most 30 bytes apart. Therefore all seven must fit in some
            // three-block (48-byte) window, regardless of alignment.
            let first_block = block_index.saturating_sub(COLON_DENSITY_WINDOW_BLOCKS - 1);
            let block_start = first_block * COLON_DENSITY_BLOCK_SIZE;
            let block_end = ((block_index + 1) * COLON_DENSITY_BLOCK_SIZE).min(chunk.len());
            merge_candidate_range(
                &mut active_range,
                block_start.saturating_sub(4),
                (block_end + 4).min(chunk.len()),
                chunk,
                matches,
            );
        }

        previous_mask = current_mask;
        current_mask = next_mask;
        next_mask = colon_mask(block_at(chunk, block_index + 2));
    }

    if let Some((start, end)) = active_range {
        scan_uncompressed_range(chunk, start, end, matches);
    }
}

fn merge_candidate_range<'a>(
    active_range: &mut Option<(usize, usize)>,
    start: usize,
    end: usize,
    chunk: &'a [u8],
    matches: &mut Vec<Match<'a>>,
) {
    match active_range {
        Some((_, active_end)) if start <= *active_end => {
            *active_end = (*active_end).max(end);
        }
        Some((active_start, active_end)) => {
            scan_uncompressed_range(chunk, *active_start, *active_end, matches);
            *active_start = start;
            *active_end = end;
        }
        None => *active_range = Some((start, end)),
    }
}

fn scan_uncompressed_range<'a>(
    chunk: &'a [u8],
    range_start: usize,
    range_end: usize,
    matches: &mut Vec<Match<'a>>,
) {
    let mut colon_window = [0; UNCOMPRESSED_COLON_COUNT];
    let mut colon_window_len = 0;
    let mut skip_until = 0;

    for relative_colon_pos in memchr::memchr_iter(b':', &chunk[range_start..range_end]) {
        let colon_pos = range_start + relative_colon_pos;
        if colon_pos < skip_until {
            continue;
        }

        if chunk.get(colon_pos + 1) == Some(&b':') {
            skip_until = colon_pos + 2;
            colon_window_len = 0;
            continue;
        }

        let continues_window = colon_window_len > 0
            && is_hextet(&chunk[colon_window[colon_window_len - 1] + 1..colon_pos]);

        if !continues_window {
            colon_window[0] = colon_pos;
            colon_window_len = 1;
            continue;
        }

        if colon_window_len < UNCOMPRESSED_COLON_COUNT {
            colon_window[colon_window_len] = colon_pos;
            colon_window_len += 1;
        } else {
            colon_window.copy_within(1..UNCOMPRESSED_COLON_COUNT, 0);
            colon_window[UNCOMPRESSED_COLON_COUNT - 1] = colon_pos;
        }

        if colon_window_len != UNCOMPRESSED_COLON_COUNT {
            continue;
        }

        match parse_uncompressed_candidate(
            chunk,
            colon_window[0],
            colon_window[UNCOMPRESSED_COLON_COUNT - 1],
        ) {
            FullCandidate::Match { ip, start, end } => {
                matches.push(Match::new(ExtractedItem::Ipv6(ip), start, end));
            }
            FullCandidate::Reject => {}
        }
    }
}

#[inline(always)]
fn block_at(chunk: &[u8], block_index: usize) -> &[u8] {
    let start = block_index.saturating_mul(COLON_DENSITY_BLOCK_SIZE);
    let end = start
        .saturating_add(COLON_DENSITY_BLOCK_SIZE)
        .min(chunk.len());
    chunk.get(start..end).unwrap_or_default()
}

#[inline]
fn colon_mask(block: &[u8]) -> u128 {
    if let Ok(bytes) = <[u8; COLON_DENSITY_BLOCK_SIZE]>::try_from(block) {
        // Safe SWAR byte comparison: each matching colon leaves only its
        // byte's high bit set, giving a compact 16-position mask without
        // architecture-specific intrinsics or unsafe loads.
        let different = u128::from_le_bytes(bytes) ^ COLON_BYTES;
        return !((different & BYTE_LOW_BITS).wrapping_add(BYTE_LOW_BITS)
            | different
            | BYTE_LOW_BITS)
            & BYTE_HIGH_BITS;
    }

    block
        .iter()
        .enumerate()
        .filter(|(_, byte)| **byte == b':')
        .fold(0, |mask, (index, _)| mask | (1 << (index * 8 + 7)))
}

#[inline]
fn single_colon_count(mask: u128, previous_mask: u128, next_mask: u128) -> usize {
    // Compression markers do not contribute to the seven-single-colon gate.
    // Remove both bytes of every internal or cross-block `::` pair.
    let second_colons = mask & (mask << 8);
    let mut single_colons = mask & !(second_colons | (second_colons >> 8));

    if previous_mask & LAST_BYTE_HIGH_BIT != 0 {
        single_colons &= !FIRST_BYTE_HIGH_BIT;
    }
    if next_mask & FIRST_BYTE_HIGH_BIT != 0 {
        single_colons &= !LAST_BYTE_HIGH_BIT;
    }

    single_colons.count_ones() as usize
}

enum FullCandidate {
    Match {
        ip: Ipv6Addr,
        start: usize,
        end: usize,
    },
    Reject,
}

#[inline]
fn is_hextet(bytes: &[u8]) -> bool {
    (1..=4).contains(&bytes.len()) && bytes.iter().all(u8::is_ascii_hexdigit)
}

fn parse_uncompressed_candidate(
    chunk: &[u8],
    first_colon: usize,
    last_colon: usize,
) -> FullCandidate {
    let mut start = first_colon;
    let mut first_hextet_len = 0;

    while start > 0 && first_hextet_len < 4 && chunk[start - 1].is_ascii_hexdigit() {
        start -= 1;
        first_hextet_len += 1;
    }

    if first_hextet_len == 0 || (start > 0 && chunk[start - 1].is_ascii_hexdigit()) {
        return FullCandidate::Reject;
    }

    let last_hextet_start = last_colon + 1;
    let mut end = last_hextet_start;
    while end < chunk.len() && end - last_hextet_start < 4 && chunk[end].is_ascii_hexdigit() {
        end += 1;
    }

    if end == last_hextet_start || (end < chunk.len() && chunk[end].is_ascii_hexdigit()) {
        return FullCandidate::Reject;
    }

    let Some(ip) = parse_uncompressed_ipv6(&chunk[start..end]) else {
        return FullCandidate::Reject;
    };

    if is_excluded_ipv6(ip) {
        return FullCandidate::Reject;
    }

    FullCandidate::Match { ip, start, end }
}

fn extract_compressed_candidate<'a>(
    chunk: &'a [u8],
    double_colon_pos: usize,
    matches: &mut Vec<Match<'a>>,
) -> usize {
    let mut start = double_colon_pos;
    while start > 0 {
        let byte = chunk[start - 1];
        if !byte.is_ascii_hexdigit() && byte != b':' {
            break;
        }
        start -= 1;
    }

    let mut end = double_colon_pos + 2;
    while end < chunk.len() {
        let byte = chunk[end];
        if !byte.is_ascii_hexdigit() && byte != b':' {
            break;
        }
        end += 1;
    }

    let attached_to_word =
        start > 0 && (chunk[start - 1].is_ascii_alphanumeric() || chunk[start - 1] == b'_');

    if attached_to_word
        && push_first_compressed_suffix(chunk, start, end, double_colon_pos, matches)
    {
        return end;
    }

    if push_compressed_variants(chunk, start, end, double_colon_pos, matches) {
        return end;
    }

    if !attached_to_word {
        push_first_compressed_suffix(chunk, start, end, double_colon_pos, matches);
    }

    end
}

fn push_first_compressed_suffix<'a>(
    chunk: &'a [u8],
    start: usize,
    end: usize,
    double_colon_pos: usize,
    matches: &mut Vec<Match<'a>>,
) -> bool {
    for relative_colon in memchr::memchr_iter(b':', &chunk[start..double_colon_pos]) {
        let candidate_start = start + relative_colon + 1;
        if push_compressed_variants(chunk, candidate_start, end, double_colon_pos, matches) {
            return true;
        }
    }

    false
}

fn push_compressed_variants<'a>(
    chunk: &'a [u8],
    start: usize,
    end: usize,
    double_colon_pos: usize,
    matches: &mut Vec<Match<'a>>,
) -> bool {
    if push_compressed_match(chunk, start, end, matches) {
        return true;
    }

    // A bare port can make an otherwise valid compressed address fail as a
    // whole token. Only fall back to the rightmost prefix after whole-token
    // parsing fails; when the whole token is itself valid, its final hextet is
    // inherently indistinguishable from a port and remains part of the match.
    let suffix_start = double_colon_pos + 2;
    if let Some(relative_colon) = memchr::memrchr(b':', &chunk[suffix_start..end]) {
        let prefix_end = suffix_start + relative_colon;
        return push_compressed_match(chunk, start, prefix_end, matches);
    }

    false
}

fn push_compressed_match<'a>(
    chunk: &'a [u8],
    start: usize,
    end: usize,
    matches: &mut Vec<Match<'a>>,
) -> bool {
    let candidate = &chunk[start..end];
    if candidate.len() < 8 || candidate.starts_with(b"::") || candidate.ends_with(b"::") {
        return false;
    }

    let Some(ip) = std::str::from_utf8(candidate)
        .ok()
        .and_then(|candidate| candidate.parse::<Ipv6Addr>().ok())
    else {
        return false;
    };

    if is_excluded_ipv6(ip) {
        return false;
    }

    matches.push(Match::new(ExtractedItem::Ipv6(ip), start, end));
    true
}

fn parse_uncompressed_ipv6(candidate: &[u8]) -> Option<Ipv6Addr> {
    let mut segments = [0u16; 8];
    let mut pos = 0;

    for (segment_index, segment) in segments.iter_mut().enumerate() {
        let mut value = 0u16;
        let mut digits = 0;

        while pos < candidate.len() && candidate[pos] != b':' {
            if digits == 4 {
                return None;
            }
            // Four hex digits fit exactly in u16, and the digit limit is
            // checked before this multiply.
            value = value * 16 + hex_value(candidate[pos])?;
            pos += 1;
            digits += 1;
        }

        if digits == 0 {
            return None;
        }
        *segment = value;

        if segment_index < 7 {
            if candidate.get(pos) != Some(&b':') {
                return None;
            }
            pos += 1;
        } else if pos != candidate.len() {
            return None;
        }
    }

    Some(Ipv6Addr::new(
        segments[0],
        segments[1],
        segments[2],
        segments[3],
        segments[4],
        segments[5],
        segments[6],
        segments[7],
    ))
}

#[inline]
fn hex_value(byte: u8) -> Option<u16> {
    match byte {
        b'0'..=b'9' => Some(u16::from(byte - b'0')),
        b'a'..=b'f' => Some(u16::from(byte - b'a' + 10)),
        b'A'..=b'F' => Some(u16::from(byte - b'A' + 10)),
        _ => None,
    }
}

#[inline]
fn is_excluded_ipv6(ip: Ipv6Addr) -> bool {
    ip.is_unspecified() || ip.is_loopback() || ip.segments()[0] & 0xffc0 == 0xfe80
}

#[cfg(test)]
mod tests {
    use super::*;

    fn extract_ipv6_matches(input: &[u8]) -> Vec<Match<'_>> {
        let extractor = Ipv6Extractor::new();
        let results = FinderResults::new(input);
        let mut matches = Vec::new();
        extractor.extract(&results, &mut matches);
        matches
    }

    fn extract_ipv6s(input: &[u8]) -> Vec<Ipv6Addr> {
        extract_ipv6_matches(input)
            .iter()
            .filter_map(|matched| match &matched.item {
                ExtractedItem::Ipv6(ip) => Some(*ip),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn extracts_fully_padded_ipv6_with_exact_span() {
        let input = b"Server at 2001:0db8:85a3:0000:0000:8a2e:0370:7334 responded";
        let expected = "2001:0db8:85a3:0000:0000:8a2e:0370:7334";
        let matches = extract_ipv6_matches(input);

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].as_str(input), expected);
        assert_eq!(matches[0].span, (10, 10 + expected.len()));
        assert_eq!(matches[0].item.as_value(), "2001:db8:85a3::8a2e:370:7334");
    }

    #[test]
    fn extracts_uncompressed_ipv6_with_short_hextets() {
        let ips = extract_ipv6s(b"Connecting to 1:2:3:4:5:6:7:8 now");
        assert_eq!(ips, ["1:2:3:4:5:6:7:8".parse::<Ipv6Addr>().unwrap()]);
    }

    #[test]
    fn extracts_compressed_ipv6() {
        let ips = extract_ipv6s(b"Connecting to 2001:db8::1");
        assert_eq!(ips, ["2001:db8::1".parse::<Ipv6Addr>().unwrap()]);
    }

    #[test]
    fn extracts_compressed_ipv6_attached_to_hex_ending_label() {
        let input = b"source:2001:db8::1";
        let matches = extract_ipv6_matches(input);

        assert_eq!(matches.len(), 1);
        assert!(matches
            .iter()
            .any(|matched| matched.as_str(input) == "2001:db8::1"));
    }

    #[test]
    fn extracts_compressed_and_uncompressed_ipv6() {
        let ips =
            extract_ipv6s(b"Traffic from 2001:db8::1 to 2606:4700:4700:0000:0000:0000:0000:1111");
        assert_eq!(ips.len(), 2);
        assert_eq!(ips[0], "2001:db8::1".parse::<Ipv6Addr>().unwrap());
        assert_eq!(ips[1], "2606:4700:4700::1111".parse::<Ipv6Addr>().unwrap());
    }

    #[test]
    fn preserves_source_order_across_ipv6_forms() {
        let ips = extract_ipv6s(b"First 2606:4700:4700:0000:0000:0000:0000:1111 then 2001:db8::1");
        assert_eq!(ips.len(), 2);
        assert_eq!(ips[0], "2606:4700:4700::1111".parse::<Ipv6Addr>().unwrap());
        assert_eq!(ips[1], "2001:db8::1".parse::<Ipv6Addr>().unwrap());
    }

    #[test]
    fn extracts_uncompressed_ipv6_at_every_block_alignment() {
        let address = b"2606:4700:4700:0000:0000:0000:0000:1111";

        for prefix_len in 0..COLON_DENSITY_BLOCK_SIZE * 2 {
            let mut input = vec![b' '; prefix_len];
            input.extend_from_slice(address);
            input.push(b' ');

            let matches = extract_ipv6_matches(&input);
            assert_eq!(matches.len(), 1, "missed alignment {prefix_len}");
            assert_eq!(matches[0].span, (prefix_len, prefix_len + address.len()));
        }
    }

    #[test]
    fn extracts_eui64_shaped_valid_ipv6() {
        let input = b"identifier 00:11:22:33:44:55:66:77 observed";
        let matches = extract_ipv6_matches(input);

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].as_str(input), "00:11:22:33:44:55:66:77");
    }

    #[test]
    fn extracts_uncompressed_ipv6_before_bare_port() {
        let input = b"peer=2001:0db8:85a3:0000:0000:8a2e:0370:7334:443 denied";
        let matches = extract_ipv6_matches(input);

        assert!(matches
            .iter()
            .any(|matched| matched.as_str(input) == "2001:0db8:85a3:0000:0000:8a2e:0370:7334"));
    }

    #[test]
    fn extracts_bracketed_uncompressed_ipv6_before_port() {
        let input = b"peer=[2001:0db8:85a3:0000:0000:8a2e:0370:7334]:443";
        let matches = extract_ipv6_matches(input);

        assert_eq!(matches.len(), 1);
        assert_eq!(
            matches[0].as_str(input),
            "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
        );
    }

    #[test]
    fn extracts_ipv6_after_colon_delimited_label_even_when_windows_overlap() {
        let input = b"source:2001:0db8:85a3:0000:0000:8a2e:0370:7334";
        let matches = extract_ipv6_matches(input);

        assert!(matches
            .iter()
            .any(|matched| matched.as_str(input) == "2001:0db8:85a3:0000:0000:8a2e:0370:7334"));
    }

    #[test]
    fn rejects_non_ipv6_colon_noise() {
        let ips = extract_ipv6s(b"12:34:56 key:value aa:bb:cc:dd:ee:ff and 1:2:3:4:5:6:7");
        assert!(ips.is_empty());
    }

    #[test]
    fn rejects_malformed_uncompressed_ipv6() {
        for input in [
            b"12345:2:3:4:5:6:7:8".as_slice(),
            b"1:2:3:4:5:6:7:gggg".as_slice(),
        ] {
            assert!(extract_ipv6s(input).is_empty(), "accepted {input:?}");
        }
    }

    #[test]
    fn extracts_valid_prefix_from_ambiguous_ninth_hextet() {
        let input = b"peer=1:2:3:4:5:6:7:8:abcd";
        let matches = extract_ipv6_matches(input);

        let matched_text: Vec<_> = matches
            .iter()
            .map(|matched| matched.as_str(input))
            .collect();
        assert_eq!(matched_text, ["1:2:3:4:5:6:7:8", "2:3:4:5:6:7:8:abcd"]);
    }

    #[test]
    fn extracts_compressed_prefix_when_bare_port_makes_whole_token_invalid() {
        let input = b"peer=2001:db8:1:2:3:4::5:443";
        let matches = extract_ipv6_matches(input);

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].as_str(input), "2001:db8:1:2:3:4::5");
    }

    #[test]
    fn keeps_ambiguous_bare_compressed_port_as_valid_whole_address() {
        let input = b"peer=2001:db8::1:443";
        let matches = extract_ipv6_matches(input);

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].as_str(input), "2001:db8::1:443");
    }

    #[test]
    fn rejects_expanded_special_addresses() {
        let ips = extract_ipv6s(
            b"0000:0000:0000:0000:0000:0000:0000:0000 \
              0000:0000:0000:0000:0000:0000:0000:0001 \
              fe80:0000:0000:0000:0000:0000:0000:0001",
        );
        assert!(ips.is_empty());
    }

    #[test]
    fn rejects_tiny_ipv6() {
        let ips = extract_ipv6s(b"Tiny IPv6: e::f");
        assert!(ips.is_empty());
    }

    #[test]
    fn rejects_link_local_ipv6() {
        let ips = extract_ipv6s(b"Link-local address: fe80::1 and fe80::dead:beef");
        assert!(ips.is_empty());
    }

    #[test]
    fn extracts_fe8_prefix_that_is_not_link_local() {
        let ips = extract_ipv6s(b"Routability aside, fe8::1234 is valid IPv6 syntax");
        assert_eq!(ips, ["fe8::1234".parse::<Ipv6Addr>().unwrap()]);
    }

    #[test]
    fn rejects_overlong_compressed_segment() {
        let ips = extract_ipv6s(b"Invalid IPv6: FEC0050519FB::c");
        assert!(ips.is_empty());
    }
}
