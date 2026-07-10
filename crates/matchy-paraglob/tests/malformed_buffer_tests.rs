//! Regression tests for safely handling malformed serialized Paraglob data.
//!
//! The mutations in this file operate on valid buffers produced by the public
//! builder. Malformed section envelopes must be rejected while corruptions that
//! are validated lazily must remain safe when queried through the public API.

use matchy_data_format::DataValue;
use matchy_paraglob::offset_format::{
    ACEdge, ACNodeHot, CharClassItemEncoded, GlobSegmentHeader, GlobSegmentIndex, ParaglobHeader,
    PatternDataMapping, PatternEntry,
};
use matchy_paraglob::{error::ParaglobError, MatchMode, Paraglob};
use std::mem::{offset_of, size_of};
use std::panic::{catch_unwind, AssertUnwindSafe};

const ACLH_HEADER_SIZE: usize = 24;
const ACLH_ENTRY_SIZE: usize = 16;
const ACLH_ENTRY_COUNT_OFFSET: usize = 8;
const ACLH_TABLE_SIZE_OFFSET: usize = 12;
const ACLH_PATTERNS_OFFSET_OFFSET: usize = 16;
const ACLH_PATTERNS_SIZE_OFFSET: usize = 20;
const ACLH_ENTRY_LITERAL_ID_OFFSET: usize = 0;
const ACLH_ENTRY_PATTERNS_OFFSET: usize = 4;
const ACLH_ENTRY_PATTERN_COUNT_OFFSET: usize = 8;
const ACLH_EMPTY_SLOT: u32 = u32::MAX;

const RICH_PATTERNS: &[&str] = &[
    "aa_alpha_long",
    "ab_bravo_long",
    "ac_charlie_long",
    "zulu_long",
];

fn rich_buffer() -> Vec<u8> {
    Paraglob::build_from_patterns(RICH_PATTERNS, MatchMode::CaseSensitive)
        .expect("test fixture should build")
        .buffer()
        .to_vec()
}

fn archived_v5_one_root_buffer() -> Vec<u8> {
    let hex: String = include_str!("fixtures/paraglob_v5_one_root.hex")
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect();
    assert!(hex.len().is_multiple_of(2), "fixture hex must be paired");

    hex.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digits = std::str::from_utf8(pair).expect("fixture hex must be ASCII");
            u8::from_str_radix(digits, 16).expect("fixture must contain valid hex")
        })
        .collect()
}

fn pattern_data_buffer() -> Vec<u8> {
    let data = [Some(DataValue::String("ok".to_string()))];
    Paraglob::build_from_patterns_with_data(
        &["*.corrupt.test"],
        Some(&data),
        MatchMode::CaseSensitive,
    )
    .expect("pattern data fixture should build")
    .buffer()
    .to_vec()
}

fn read_u32(buffer: &[u8], offset: usize) -> u32 {
    let bytes = buffer
        .get(offset..offset + size_of::<u32>())
        .expect("test fixture field should be in bounds");
    u32::from_le_bytes(bytes.try_into().expect("u32 fields are four bytes"))
}

fn write_u32(buffer: &mut [u8], offset: usize, value: u32) {
    buffer
        .get_mut(offset..offset + size_of::<u32>())
        .expect("test fixture field should be in bounds")
        .copy_from_slice(&value.to_le_bytes());
}

fn write_u16(buffer: &mut [u8], offset: usize, value: u16) {
    buffer
        .get_mut(offset..offset + size_of::<u16>())
        .expect("test fixture field should be in bounds")
        .copy_from_slice(&value.to_le_bytes());
}

fn header_u32(buffer: &[u8], field_offset: usize) -> u32 {
    read_u32(buffer, field_offset)
}

fn set_header_u32(buffer: &mut [u8], field_offset: usize, value: u32) {
    write_u32(buffer, field_offset, value);
}

fn ac_start(buffer: &[u8]) -> usize {
    header_u32(buffer, offset_of!(ParaglobHeader, ac_nodes_offset)) as usize
}

fn ac_size(buffer: &[u8]) -> usize {
    header_u32(buffer, offset_of!(ParaglobHeader, ac_edges_size)) as usize
}

fn ac_node_count(buffer: &[u8]) -> usize {
    header_u32(buffer, offset_of!(ParaglobHeader, ac_node_count)) as usize
}

fn ac_node_relative_offset(index: usize) -> usize {
    index * size_of::<ACNodeHot>()
}

fn ac_node_absolute_offset(buffer: &[u8], index: usize) -> usize {
    ac_start(buffer) + ac_node_relative_offset(index)
}

fn node_indices_with_kind(buffer: &[u8], state_kind: u8) -> Vec<usize> {
    (0..ac_node_count(buffer))
        .filter(|&index| buffer[ac_node_absolute_offset(buffer, index)] == state_kind)
        .collect()
}

fn terminal_node_indices(buffer: &[u8]) -> Vec<usize> {
    (0..ac_node_count(buffer))
        .filter(|&index| {
            buffer[ac_node_absolute_offset(buffer, index) + offset_of!(ACNodeHot, pattern_count)]
                > 0
        })
        .collect()
}

fn ac_literal_hash_start(buffer: &[u8]) -> usize {
    header_u32(buffer, offset_of!(ParaglobHeader, ac_literal_map_offset)) as usize
}

fn first_occupied_aclh_entry(buffer: &[u8]) -> usize {
    let hash_start = ac_literal_hash_start(buffer);
    let table_size = read_u32(buffer, hash_start + ACLH_TABLE_SIZE_OFFSET) as usize;

    (0..table_size)
        .map(|slot| hash_start + ACLH_HEADER_SIZE + slot * ACLH_ENTRY_SIZE)
        .find(|&entry_offset| {
            read_u32(buffer, entry_offset + ACLH_ENTRY_LITERAL_ID_OFFSET) != ACLH_EMPTY_SLOT
        })
        .expect("fixture should contain an occupied AC literal hash entry")
}

fn assert_load_rejected(buffer: Vec<u8>, case: &str) {
    let load = catch_unwind(|| Paraglob::from_buffer(buffer, MatchMode::CaseSensitive));
    let result = load.unwrap_or_else(|_| panic!("{case}: loading malformed data must not panic"));
    assert!(result.is_err(), "{case}: malformed data was accepted");
}

fn assert_rejected_or_safe_empty_query(buffer: Vec<u8>, query: &str, case: &str) {
    let load = catch_unwind(|| Paraglob::from_buffer(buffer, MatchMode::CaseSensitive));
    let result = load.unwrap_or_else(|_| panic!("{case}: loading malformed data must not panic"));

    let Ok(paraglob) = result else {
        return;
    };

    let query_result = catch_unwind(AssertUnwindSafe(|| paraglob.find_all(query)))
        .unwrap_or_else(|_| panic!("{case}: querying accepted malformed data must not panic"));
    assert!(
        query_result.is_empty(),
        "{case}: corrupt index data must not produce matches"
    );
}

#[test]
fn result_bearing_pattern_data_lookup_preserves_valid_behavior() {
    let data = [Some(DataValue::String("present".to_string())), None];
    let paraglob = Paraglob::build_from_patterns_with_data(
        &["first", "second"],
        Some(&data),
        MatchMode::CaseSensitive,
    )
    .expect("valid pattern data should build");

    assert_eq!(
        paraglob.try_get_pattern_data(0).unwrap(),
        Some(DataValue::String("present".to_string()))
    );
    assert_eq!(paraglob.try_get_pattern_data(1).unwrap(), None);
    assert_eq!(paraglob.try_get_pattern_data(u32::MAX).unwrap(), None);
}

#[test]
fn result_bearing_pattern_data_lookup_reports_corrupt_values() {
    let mut buffer = pattern_data_buffer();
    let data_start = header_u32(&buffer, offset_of!(ParaglobHeader, data_section_offset)) as usize;

    // A string with payload 31 requires three additional size bytes. The valid
    // fixture has only the original two-byte string payload after this control
    // byte, so decoding must fail within the bounded data section.
    buffer[data_start] = 0x5f;

    let paraglob = Paraglob::from_buffer(buffer, MatchMode::CaseSensitive)
        .expect("lazy data corruption should not prevent matcher loading");
    let error = paraglob
        .try_get_pattern_data(0)
        .expect_err("corrupt matched data must be reported");

    assert!(matches!(
        error,
        matchy_paraglob::error::ParaglobError::Format(_)
    ));
    assert_eq!(
        paraglob.get_pattern_data(0),
        None,
        "the compatibility shim must retain its historical Option behavior"
    );

    let mut oversized_mapping = pattern_data_buffer();
    let mapping_start = header_u32(
        &oversized_mapping,
        offset_of!(ParaglobHeader, mapping_table_offset),
    ) as usize;
    write_u32(
        &mut oversized_mapping,
        mapping_start + offset_of!(PatternDataMapping, data_size),
        u32::MAX,
    );
    let paraglob = Paraglob::from_buffer(oversized_mapping, MatchMode::CaseSensitive)
        .expect("lazy mapping corruption should not prevent matcher loading");
    assert!(matches!(
        paraglob.try_get_pattern_data(0),
        Err(matchy_paraglob::error::ParaglobError::Validation(_))
    ));

    let mut implicit_sized_mapping = pattern_data_buffer();
    let mapping_start = header_u32(
        &implicit_sized_mapping,
        offset_of!(ParaglobHeader, mapping_table_offset),
    ) as usize;
    write_u32(
        &mut implicit_sized_mapping,
        mapping_start + offset_of!(PatternDataMapping, data_size),
        0,
    );
    let paraglob = Paraglob::from_buffer(implicit_sized_mapping, MatchMode::CaseSensitive)
        .expect("legacy implicit-sized mappings should remain loadable");
    assert_eq!(
        paraglob.try_get_pattern_data(0).unwrap(),
        Some(DataValue::String("ok".to_string()))
    );
}

#[test]
fn rejects_truncated_ac_envelopes_without_panicking() {
    let mut one_byte = rich_buffer();
    set_header_u32(&mut one_byte, offset_of!(ParaglobHeader, ac_edges_size), 1);
    assert_load_rejected(one_byte, "one-byte AC section");

    let mut range_past_end = rich_buffer();
    let buffer_len = range_past_end.len();
    set_header_u32(
        &mut range_past_end,
        offset_of!(ParaglobHeader, ac_nodes_offset),
        u32::try_from(buffer_len - 1).expect("fixture should fit in u32"),
    );
    set_header_u32(
        &mut range_past_end,
        offset_of!(ParaglobHeader, ac_edges_size),
        2,
    );
    assert_load_rejected(range_past_end, "AC section ending past the buffer");

    let mut physically_truncated = rich_buffer();
    let truncate_at = ac_start(&physically_truncated) + 1;
    physically_truncated.truncate(truncate_at);
    set_header_u32(
        &mut physically_truncated,
        offset_of!(ParaglobHeader, ac_edges_size),
        1,
    );
    set_header_u32(
        &mut physically_truncated,
        offset_of!(ParaglobHeader, total_buffer_size),
        u32::try_from(truncate_at).expect("fixture should fit in u32"),
    );
    assert_load_rejected(physically_truncated, "physically truncated AC section");
}

#[test]
fn loads_archived_v5_one_root_fixture() {
    let buffer = archived_v5_one_root_buffer();
    assert_eq!(buffer.len(), 610, "archived fixture size changed");
    assert_eq!(buffer[ac_start(&buffer)], 1, "fixture root must be One");

    let paraglob = Paraglob::from_buffer(buffer, MatchMode::CaseSensitive)
        .expect("archived v5 One-root fixture should remain readable");
    assert_eq!(paraglob.find_all("a needle in text"), vec![0]);
    assert!(paraglob.find_all("absent").is_empty());
}

#[test]
fn accepts_legacy_v5_one_root_encoding() {
    let mut buffer = Paraglob::build_from_patterns(&["legacy-root"], MatchMode::CaseSensitive)
        .expect("test fixture should build")
        .buffer()
        .to_vec();
    let root_offset = ac_node_absolute_offset(&buffer, 0);
    let dense_lookup = ac_start(&buffer)
        + read_u32(&buffer, root_offset + offset_of!(ACNodeHot, edges_offset)) as usize;
    let first_target = read_u32(&buffer, dense_lookup + usize::from(b'l') * size_of::<u32>());
    assert_ne!(first_target, 0, "fixture should contain an l transition");

    buffer[root_offset + offset_of!(ACNodeHot, state_kind)] = 1;
    buffer[root_offset + offset_of!(ACNodeHot, one_char)] = b'l';
    buffer[root_offset + offset_of!(ACNodeHot, edge_count)] = 0;
    write_u32(
        &mut buffer,
        root_offset + offset_of!(ACNodeHot, one_target),
        first_target,
    );
    write_u32(
        &mut buffer,
        root_offset + offset_of!(ACNodeHot, edges_offset),
        first_target,
    );

    let paraglob = Paraglob::from_buffer(buffer, MatchMode::CaseSensitive)
        .expect("legacy v5 One root should remain readable");
    assert_eq!(paraglob.find_all("legacy-root"), vec![0]);
}

#[test]
fn corrupt_ac_node_links_remain_safe_to_query() {
    for (label, invalid_offset) in [
        ("misaligned failure link", 1_u32),
        (
            "failure link outside the node array",
            u32::try_from(ac_node_count(&rich_buffer()) * size_of::<ACNodeHot>())
                .expect("fixture should fit in u32"),
        ),
    ] {
        let mut buffer = rich_buffer();
        for index in 1..ac_node_count(&buffer) {
            let field_offset =
                ac_node_absolute_offset(&buffer, index) + offset_of!(ACNodeHot, failure_offset);
            write_u32(&mut buffer, field_offset, invalid_offset);
        }
        assert_rejected_or_safe_empty_query(buffer, "a! z!", label);
    }

    for (label, invalid_offset) in [
        ("misaligned ONE target", 1_u32),
        (
            "ONE target outside the node array",
            u32::try_from(ac_node_count(&rich_buffer()) * size_of::<ACNodeHot>())
                .expect("fixture should fit in u32"),
        ),
    ] {
        let mut buffer = rich_buffer();
        let one_nodes = node_indices_with_kind(&buffer, 1);
        assert!(!one_nodes.is_empty(), "fixture should contain ONE nodes");
        for index in one_nodes {
            let field_offset =
                ac_node_absolute_offset(&buffer, index) + offset_of!(ACNodeHot, edges_offset);
            write_u32(&mut buffer, field_offset, invalid_offset);
        }
        assert_rejected_or_safe_empty_query(buffer, "zulu_long", label);
    }
}

#[test]
fn cyclic_ac_failure_links_terminate_safely() {
    let mut buffer = rich_buffer();
    let root_offset = ac_node_absolute_offset(&buffer, 0);
    let lookup_relative =
        read_u32(&buffer, root_offset + offset_of!(ACNodeHot, edges_offset)) as usize;
    let lookup_absolute = ac_start(&buffer) + lookup_relative;
    let a_node = read_u32(
        &buffer,
        lookup_absolute + usize::from(b'a') * size_of::<u32>(),
    ) as usize;
    let z_node = read_u32(
        &buffer,
        lookup_absolute + usize::from(b'z') * size_of::<u32>(),
    ) as usize;
    assert_ne!(a_node, 0, "fixture root should contain an 'a' transition");
    assert_ne!(z_node, 0, "fixture root should contain a 'z' transition");

    let ac_absolute = ac_start(&buffer);
    write_u32(
        &mut buffer,
        ac_absolute + a_node + offset_of!(ACNodeHot, failure_offset),
        u32::try_from(z_node).expect("fixture should fit in u32"),
    );
    write_u32(
        &mut buffer,
        ac_absolute + z_node + offset_of!(ACNodeHot, failure_offset),
        u32::try_from(a_node).expect("fixture should fit in u32"),
    );

    // `a!` enters the `a` state, then forces failure traversal through the
    // malicious a -> z -> a cycle. The query must terminate without a match.
    let paraglob = Paraglob::from_buffer(buffer, MatchMode::CaseSensitive)
        .expect("lazy failure-link corruption should remain loadable");
    assert!(
        paraglob.find_all("a!").is_empty(),
        "legacy lookup must still terminate safely"
    );
    assert!(matches!(
        paraglob.try_find_all_bounded("a!", 1, 2),
        Err(ParaglobError::ResourceLimitExceeded(_))
    ));
}

#[test]
fn bounded_matching_rejects_malformed_sparse_fanout_by_work_budget() {
    let mut buffer = rich_buffer();
    let root_offset = ac_node_absolute_offset(&buffer, 0);
    let lookup_relative =
        read_u32(&buffer, root_offset + offset_of!(ACNodeHot, edges_offset)) as usize;
    let lookup_absolute = ac_start(&buffer) + lookup_relative;
    let a_node = read_u32(
        &buffer,
        lookup_absolute + usize::from(b'a') * size_of::<u32>(),
    ) as usize;
    assert_ne!(a_node, 0, "fixture root should contain an 'a' transition");
    let a_node_absolute = ac_start(&buffer) + a_node;
    assert_eq!(
        buffer[a_node_absolute + offset_of!(ACNodeHot, state_kind)],
        2,
        "fixture a-state should use sparse transitions"
    );
    buffer[a_node_absolute + offset_of!(ACNodeHot, edge_count)] = u8::MAX;

    let paraglob = Paraglob::from_buffer(buffer, MatchMode::CaseSensitive)
        .expect("lazy sparse-edge corruption should remain loadable");
    assert!(
        paraglob.find_all("a!").is_empty(),
        "legacy lookup must fail closed"
    );
    assert!(matches!(
        paraglob.try_find_all_bounded("a!", 1, 2),
        Err(ParaglobError::ResourceLimitExceeded(_))
    ));
}

#[test]
fn corrupt_ac_transition_ranges_and_targets_remain_safe_to_query() {
    for (label, invalid_offset) in [
        ("misaligned sparse edge range", 1_u32),
        (
            "sparse edge range past the AC section",
            u32::try_from(ac_size(&rich_buffer())).expect("fixture should fit in u32"),
        ),
    ] {
        let mut buffer = rich_buffer();
        let sparse_nodes = node_indices_with_kind(&buffer, 2);
        assert!(
            !sparse_nodes.is_empty(),
            "fixture should contain sparse nodes"
        );
        for index in sparse_nodes {
            let field_offset =
                ac_node_absolute_offset(&buffer, index) + offset_of!(ACNodeHot, edges_offset);
            write_u32(&mut buffer, field_offset, invalid_offset);
        }
        assert_rejected_or_safe_empty_query(buffer, "aa_alpha_long", label);
    }

    for (label, invalid_offset) in [
        ("misaligned dense lookup range", 1_u32),
        (
            "dense lookup range past the AC section",
            u32::try_from(ac_size(&rich_buffer())).expect("fixture should fit in u32"),
        ),
    ] {
        let mut buffer = rich_buffer();
        let dense_nodes = node_indices_with_kind(&buffer, 3);
        assert!(
            !dense_nodes.is_empty(),
            "fixture should contain dense nodes"
        );
        for index in dense_nodes {
            let field_offset =
                ac_node_absolute_offset(&buffer, index) + offset_of!(ACNodeHot, edges_offset);
            write_u32(&mut buffer, field_offset, invalid_offset);
        }
        assert_rejected_or_safe_empty_query(buffer, "aa_alpha_long", label);
    }

    let mut sparse_targets = rich_buffer();
    let sparse_nodes = node_indices_with_kind(&sparse_targets, 2);
    assert!(
        !sparse_nodes.is_empty(),
        "fixture should contain sparse nodes"
    );
    for index in sparse_nodes {
        let node_offset = ac_node_absolute_offset(&sparse_targets, index);
        let edge_count = sparse_targets[node_offset + offset_of!(ACNodeHot, edge_count)] as usize;
        let edges_relative = read_u32(
            &sparse_targets,
            node_offset + offset_of!(ACNodeHot, edges_offset),
        ) as usize;
        for edge_index in 0..edge_count {
            let target_offset = ac_start(&sparse_targets)
                + edges_relative
                + edge_index * size_of::<ACEdge>()
                + offset_of!(ACEdge, target_offset);
            write_u32(&mut sparse_targets, target_offset, 1);
        }
    }
    assert_rejected_or_safe_empty_query(
        sparse_targets,
        "aa_alpha_long",
        "misaligned sparse edge targets",
    );

    let mut dense_targets = rich_buffer();
    let root_offset = ac_node_absolute_offset(&dense_targets, 0);
    let lookup_relative = read_u32(
        &dense_targets,
        root_offset + offset_of!(ACNodeHot, edges_offset),
    ) as usize;
    let lookup_absolute = ac_start(&dense_targets) + lookup_relative;
    let mut nonzero_targets = 0;
    for character in 0..=u8::MAX {
        let target_offset = lookup_absolute + usize::from(character) * size_of::<u32>();
        if read_u32(&dense_targets, target_offset) != 0 {
            write_u32(&mut dense_targets, target_offset, 1);
            nonzero_targets += 1;
        }
    }
    assert!(
        nonzero_targets > 0,
        "fixture root should contain transitions"
    );
    assert_rejected_or_safe_empty_query(
        dense_targets,
        "aa_alpha_long zulu_long",
        "misaligned dense lookup targets",
    );
}

#[test]
fn corrupt_ac_pattern_lists_remain_safe_to_query() {
    for (label, invalid_offset) in [
        ("misaligned AC pattern list", 1_u32),
        (
            "truncated AC pattern list",
            u32::try_from(ac_size(&rich_buffer()) - 1).expect("fixture should fit in u32"),
        ),
    ] {
        let mut buffer = rich_buffer();
        let terminal_nodes = terminal_node_indices(&buffer);
        assert!(
            !terminal_nodes.is_empty(),
            "fixture should contain terminal nodes"
        );
        for index in terminal_nodes {
            let field_offset =
                ac_node_absolute_offset(&buffer, index) + offset_of!(ACNodeHot, patterns_offset);
            write_u32(&mut buffer, field_offset, invalid_offset);
        }
        assert_rejected_or_safe_empty_query(
            buffer,
            "aa_alpha_long ab_bravo_long ac_charlie_long zulu_long",
            label,
        );
    }
}

#[test]
fn rejects_truncated_pattern_entry_table_without_panicking() {
    let mut buffer = rich_buffer();
    let buffer_len = buffer.len();
    set_header_u32(
        &mut buffer,
        offset_of!(ParaglobHeader, patterns_offset),
        u32::try_from(buffer_len - size_of::<PatternEntry>() + 1)
            .expect("fixture should fit in u32"),
    );
    assert_load_rejected(buffer, "truncated pattern entry table");
}

#[test]
fn malformed_glob_segment_ranges_fail_safely() {
    let mut buffer = Paraglob::build_from_patterns(&["longanchor?"], MatchMode::CaseSensitive)
        .expect("test fixture should build")
        .buffer()
        .to_vec();
    let index_offset =
        header_u32(&buffer, offset_of!(ParaglobHeader, glob_segments_offset)) as usize;
    write_u16(
        &mut buffer,
        index_offset + offset_of!(GlobSegmentIndex, segment_count),
        u16::MAX,
    );
    assert_rejected_or_safe_empty_query(
        buffer,
        "longanchorx",
        "oversized serialized glob segment count",
    );

    let mut truncated = Paraglob::build_from_patterns(&["longanchor?"], MatchMode::CaseSensitive)
        .expect("test fixture should build")
        .buffer()
        .to_vec();
    let index_offset =
        header_u32(&truncated, offset_of!(ParaglobHeader, glob_segments_offset)) as usize;
    let truncated_offset = u32::try_from(truncated.len() - 1).expect("fixture should fit in u32");
    write_u32(
        &mut truncated,
        index_offset + offset_of!(GlobSegmentIndex, first_segment_offset),
        truncated_offset,
    );
    write_u16(
        &mut truncated,
        index_offset + offset_of!(GlobSegmentIndex, segment_count),
        1,
    );
    assert_rejected_or_safe_empty_query(
        truncated,
        "longanchorx",
        "truncated serialized glob segment range",
    );
}

#[test]
#[cfg_attr(
    miri,
    ignore = "65,535-segment parser loop is prohibitively slow under interpretation"
)]
fn supports_the_full_u16_serialized_glob_segment_count_without_recursion() {
    let segment_count = usize::from(u16::MAX);
    let pattern = "?".repeat(segment_count);
    let text = "x".repeat(segment_count);
    let paraglob = Paraglob::build_from_patterns(&[pattern.as_str()], MatchMode::CaseSensitive)
        .expect("every u16-representable segment count should be buildable");

    assert_eq!(paraglob.find_all(&text), vec![0]);
    assert!(paraglob.find_all(&text[..text.len() - 1]).is_empty());
}

#[test]
fn glob_segment_headers_cannot_escape_the_declared_glob_data_region() {
    let mut buffer = Paraglob::build_from_patterns(&["?"], MatchMode::CaseInsensitive)
        .expect("test fixture should build")
        .buffer()
        .to_vec();
    let index_offset =
        header_u32(&buffer, offset_of!(ParaglobHeader, glob_segments_offset)) as usize;

    // The match-mode field begins with byte 1 in this fixture. Interpreting it
    // as a one-segment glob header therefore turns it into a trailing `*`,
    // which used to produce a false positive for every query.
    write_u32(
        &mut buffer,
        index_offset + offset_of!(GlobSegmentIndex, first_segment_offset),
        u32::try_from(offset_of!(ParaglobHeader, match_mode)).expect("header offset fits in u32"),
    );
    write_u16(
        &mut buffer,
        index_offset + offset_of!(GlobSegmentIndex, segment_count),
        1,
    );

    assert_rejected_or_safe_empty_query(
        buffer,
        "not-one-character",
        "glob segment header points into the file header",
    );
}

#[test]
fn glob_payloads_cannot_escape_the_declared_glob_data_region() {
    let mut literal_buffer = Paraglob::build_from_patterns(&["anchor?"], MatchMode::CaseSensitive)
        .expect("test fixture should build")
        .buffer()
        .to_vec();
    let literal_index = header_u32(
        &literal_buffer,
        offset_of!(ParaglobHeader, glob_segments_offset),
    ) as usize;
    let literal_header = read_u32(
        &literal_buffer,
        literal_index + offset_of!(GlobSegmentIndex, first_segment_offset),
    ) as usize;
    let pattern_string = header_u32(
        &literal_buffer,
        offset_of!(ParaglobHeader, pattern_strings_offset),
    );
    write_u32(
        &mut literal_buffer,
        literal_header + offset_of!(GlobSegmentHeader, data_offset),
        pattern_string,
    );
    write_u32(
        &mut literal_buffer,
        literal_header + offset_of!(GlobSegmentHeader, data_len),
        7,
    );
    assert_rejected_or_safe_empty_query(
        literal_buffer,
        "anchor?x",
        "literal payload points into pattern strings",
    );

    let mut class_buffer =
        Paraglob::build_from_patterns(&["longanchor[a]"], MatchMode::CaseSensitive)
            .expect("test fixture should build")
            .buffer()
            .to_vec();
    let class_index = header_u32(
        &class_buffer,
        offset_of!(ParaglobHeader, glob_segments_offset),
    ) as usize;
    let first_header = read_u32(
        &class_buffer,
        class_index + offset_of!(GlobSegmentIndex, first_segment_offset),
    ) as usize;
    let class_header = first_header + size_of::<GlobSegmentHeader>();
    let pattern_string = header_u32(
        &class_buffer,
        offset_of!(ParaglobHeader, pattern_strings_offset),
    ) as usize;

    // Encode a valid single-character class item for `b` outside the glob
    // section, then point the class payload at it.
    class_buffer[pattern_string..pattern_string + 4].copy_from_slice(&[0; 4]);
    write_u32(&mut class_buffer, pattern_string + 4, u32::from('b'));
    write_u32(&mut class_buffer, pattern_string + 8, 0);
    write_u32(
        &mut class_buffer,
        class_header + offset_of!(GlobSegmentHeader, data_offset),
        u32::try_from(pattern_string).expect("fixture offset fits in u32"),
    );
    write_u32(
        &mut class_buffer,
        class_header + offset_of!(GlobSegmentHeader, data_len),
        12,
    );
    assert_rejected_or_safe_empty_query(
        class_buffer,
        "longanchorb",
        "character-class payload points into pattern strings",
    );
}

#[test]
fn malformed_negated_character_classes_cannot_match_by_default() {
    fn class_header_offset(buffer: &[u8]) -> usize {
        let index_offset =
            header_u32(buffer, offset_of!(ParaglobHeader, glob_segments_offset)) as usize;
        let first_header = read_u32(
            buffer,
            index_offset + offset_of!(GlobSegmentIndex, first_segment_offset),
        ) as usize;
        first_header + size_of::<GlobSegmentHeader>()
    }

    let mut partial_item = Paraglob::build_from_patterns(&["anchor[!a]"], MatchMode::CaseSensitive)
        .expect("test fixture should build")
        .buffer()
        .to_vec();
    let class_header = class_header_offset(&partial_item);
    write_u32(
        &mut partial_item,
        class_header + offset_of!(GlobSegmentHeader, data_len),
        1,
    );
    assert_rejected_or_safe_empty_query(
        partial_item,
        "anchora",
        "negated class with a partial encoded item",
    );

    let mut unknown_item = Paraglob::build_from_patterns(&["anchor[!a]"], MatchMode::CaseSensitive)
        .expect("test fixture should build")
        .buffer()
        .to_vec();
    let class_header = class_header_offset(&unknown_item);
    let class_data = read_u32(
        &unknown_item,
        class_header + offset_of!(GlobSegmentHeader, data_offset),
    ) as usize;
    unknown_item[class_data + offset_of!(CharClassItemEncoded, item_type)] = u8::MAX;
    assert_rejected_or_safe_empty_query(
        unknown_item,
        "anchora",
        "negated class with an unknown item type",
    );

    let mut corrupt_suffix =
        Paraglob::build_from_patterns(&["anchor[ab]"], MatchMode::CaseSensitive)
            .expect("test fixture should build")
            .buffer()
            .to_vec();
    let class_header = class_header_offset(&corrupt_suffix);
    let class_data = read_u32(
        &corrupt_suffix,
        class_header + offset_of!(GlobSegmentHeader, data_offset),
    ) as usize;
    corrupt_suffix[class_data
        + size_of::<CharClassItemEncoded>()
        + offset_of!(CharClassItemEncoded, item_type)] = u8::MAX;
    assert_rejected_or_safe_empty_query(
        corrupt_suffix,
        "anchora",
        "class with a matching valid item before an unknown item",
    );

    let mut reversed_range =
        Paraglob::build_from_patterns(&["anchor[!a-z]"], MatchMode::CaseSensitive)
            .expect("test fixture should build")
            .buffer()
            .to_vec();
    let class_header = class_header_offset(&reversed_range);
    let class_data = read_u32(
        &reversed_range,
        class_header + offset_of!(GlobSegmentHeader, data_offset),
    ) as usize;
    write_u32(
        &mut reversed_range,
        class_data + offset_of!(CharClassItemEncoded, char1),
        u32::from('z'),
    );
    write_u32(
        &mut reversed_range,
        class_data + offset_of!(CharClassItemEncoded, char2),
        u32::from('a'),
    );
    assert_rejected_or_safe_empty_query(
        reversed_range,
        "anchora",
        "negated class with a reversed range",
    );
}

#[test]
fn impossible_literal_and_character_class_encodings_fail_closed() {
    let mut empty_literal = Paraglob::build_from_patterns(&["anchor*"], MatchMode::CaseSensitive)
        .expect("test fixture should build")
        .buffer()
        .to_vec();
    let index_offset = header_u32(
        &empty_literal,
        offset_of!(ParaglobHeader, glob_segments_offset),
    ) as usize;
    let literal_header = read_u32(
        &empty_literal,
        index_offset + offset_of!(GlobSegmentIndex, first_segment_offset),
    ) as usize;
    write_u32(
        &mut empty_literal,
        literal_header + offset_of!(GlobSegmentHeader, data_len),
        0,
    );
    assert_rejected_or_safe_empty_query(
        empty_literal,
        "anchoranything",
        "zero-length serialized literal",
    );

    let mut invalid_utf8 = Paraglob::build_from_patterns(&["*anchor*"], MatchMode::CaseSensitive)
        .expect("test fixture should build")
        .buffer()
        .to_vec();
    let index_offset = header_u32(
        &invalid_utf8,
        offset_of!(ParaglobHeader, glob_segments_offset),
    ) as usize;
    let first_header = read_u32(
        &invalid_utf8,
        index_offset + offset_of!(GlobSegmentIndex, first_segment_offset),
    ) as usize;
    let literal_header = first_header + size_of::<GlobSegmentHeader>();
    let literal_data = read_u32(
        &invalid_utf8,
        literal_header + offset_of!(GlobSegmentHeader, data_offset),
    ) as usize;
    invalid_utf8[literal_data] = u8::MAX;
    assert_rejected_or_safe_empty_query(
        invalid_utf8,
        "prefixanchorsuffix",
        "invalid UTF-8 literal on the contains fast path",
    );

    let mut unknown_class_flags =
        Paraglob::build_from_patterns(&["anchor[a]"], MatchMode::CaseSensitive)
            .expect("test fixture should build")
            .buffer()
            .to_vec();
    let index_offset = header_u32(
        &unknown_class_flags,
        offset_of!(ParaglobHeader, glob_segments_offset),
    ) as usize;
    let first_header = read_u32(
        &unknown_class_flags,
        index_offset + offset_of!(GlobSegmentIndex, first_segment_offset),
    ) as usize;
    let class_header = first_header + size_of::<GlobSegmentHeader>();
    unknown_class_flags[class_header + offset_of!(GlobSegmentHeader, flags)] = 0b10;
    assert_rejected_or_safe_empty_query(
        unknown_class_flags,
        "anchora",
        "serialized character class with unknown flag bits",
    );
}

#[test]
fn rejects_invalid_ac_literal_hash_envelopes_without_panicking() {
    let mut zero_table = rich_buffer();
    let hash_start = ac_literal_hash_start(&zero_table);
    write_u32(&mut zero_table, hash_start + ACLH_ENTRY_COUNT_OFFSET, 0);
    write_u32(&mut zero_table, hash_start + ACLH_TABLE_SIZE_OFFSET, 0);
    assert_load_rejected(zero_table, "zero-size AC literal hash table");

    let mut patterns_before_table_end = rich_buffer();
    let hash_start = ac_literal_hash_start(&patterns_before_table_end);
    let table_size = read_u32(
        &patterns_before_table_end,
        hash_start + ACLH_TABLE_SIZE_OFFSET,
    ) as usize;
    let table_end = ACLH_HEADER_SIZE + table_size * ACLH_ENTRY_SIZE;
    write_u32(
        &mut patterns_before_table_end,
        hash_start + ACLH_PATTERNS_OFFSET_OFFSET,
        u32::try_from(table_end - 1).expect("fixture should fit in u32"),
    );
    assert_load_rejected(
        patterns_before_table_end,
        "AC literal hash patterns overlap the table",
    );

    let mut patterns_past_end = rich_buffer();
    let hash_start = ac_literal_hash_start(&patterns_past_end);
    let hash_section_end = header_u32(
        &patterns_past_end,
        offset_of!(ParaglobHeader, glob_segments_offset),
    ) as usize;
    let hash_section_len = hash_section_end - hash_start;
    write_u32(
        &mut patterns_past_end,
        hash_start + ACLH_PATTERNS_OFFSET_OFFSET,
        u32::try_from(hash_section_len - 2).expect("fixture should fit in u32"),
    );
    write_u32(
        &mut patterns_past_end,
        hash_start + ACLH_PATTERNS_SIZE_OFFSET,
        4,
    );
    assert_load_rejected(
        patterns_past_end,
        "AC literal hash patterns end past the section",
    );

    let mut oversized_table = rich_buffer();
    let hash_start = ac_literal_hash_start(&oversized_table);
    write_u32(
        &mut oversized_table,
        hash_start + ACLH_TABLE_SIZE_OFFSET,
        u32::MAX,
    );
    assert_load_rejected(oversized_table, "oversized AC literal hash table");

    let mut too_many_entries = rich_buffer();
    let hash_start = ac_literal_hash_start(&too_many_entries);
    let table_size = read_u32(&too_many_entries, hash_start + ACLH_TABLE_SIZE_OFFSET);
    write_u32(
        &mut too_many_entries,
        hash_start + ACLH_ENTRY_COUNT_OFFSET,
        table_size + 1,
    );
    assert_load_rejected(
        too_many_entries,
        "AC literal hash entry count exceeds table size",
    );
}

#[test]
fn corrupt_ac_literal_hash_pattern_range_remains_safe_to_query() {
    let mut buffer = rich_buffer();
    let hash_start = ac_literal_hash_start(&buffer);
    let entry_offset = first_occupied_aclh_entry(&buffer);
    assert!(
        read_u32(&buffer, entry_offset + ACLH_ENTRY_PATTERN_COUNT_OFFSET) > 0,
        "fixture hash entry should reference patterns"
    );

    write_u32(&mut buffer, hash_start + ACLH_PATTERNS_SIZE_OFFSET, 0);
    write_u32(&mut buffer, entry_offset + ACLH_ENTRY_PATTERNS_OFFSET, 0);
    assert_rejected_or_safe_empty_query(
        buffer,
        "aa_alpha_long ab_bravo_long ac_charlie_long zulu_long",
        "AC literal hash entry exceeds declared pattern bytes",
    );
}
