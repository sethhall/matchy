#![cfg(feature = "bench-diagnostics")]

use matchy_paraglob::{LookupDiagnostics, MatchMode, Paraglob};

#[test]
fn diagnostics_count_literal_candidates_without_glob_verification() {
    let patterns = vec!["literal"];
    let pg = Paraglob::build_from_patterns(&patterns, MatchMode::CaseSensitive).unwrap();

    let (matches, diagnostics) = pg.find_all_with_diagnostics("literal");

    assert_eq!(matches, vec![0]);
    assert_eq!(diagnostics.query_bytes_scanned, "literal".len());
    assert_eq!(diagnostics.ac_literal_hits, 1);
    assert_eq!(diagnostics.candidate_pattern_ids, 1);
    assert_eq!(diagnostics.pure_wildcard_checks, 0);
    assert_eq!(diagnostics.glob_verification_attempts, 0);
    assert_eq!(diagnostics.successful_glob_verifications, 0);
}

#[test]
fn diagnostics_count_selected_anchor_and_glob_verification() {
    let patterns = vec!["*shared*needle", "*shared*absent"];
    let pg = Paraglob::build_from_patterns(&patterns, MatchMode::CaseSensitive).unwrap();

    let (matches, diagnostics) = pg.find_all_with_diagnostics("shared needle");

    assert_eq!(matches, vec![0]);
    assert_eq!(diagnostics.query_bytes_scanned, "shared needle".len());
    assert_eq!(diagnostics.ac_literal_hits, 1);
    assert_eq!(diagnostics.candidate_pattern_ids, 1);
    assert_eq!(diagnostics.pure_wildcard_checks, 0);
    assert_eq!(diagnostics.glob_verification_attempts, 1);
    assert_eq!(diagnostics.successful_glob_verifications, 1);
    assert!(diagnostics.serialized_glob_segment_steps > 0);
    assert!(diagnostics.star_backtracking_attempts > 0);
}

#[test]
fn lookup_diagnostics_default_is_empty() {
    assert_eq!(LookupDiagnostics::default(), LookupDiagnostics::default());
}

#[test]
fn diagnostics_show_star_jumps_to_following_literal() {
    let patterns = vec!["*needle?"];
    let pg = Paraglob::build_from_patterns(&patterns, MatchMode::CaseSensitive).unwrap();
    let query = format!("{}needleX", "a".repeat(128));

    let (matches, diagnostics) = pg.find_all_with_diagnostics(&query);

    assert_eq!(matches, vec![0]);
    assert!(
        diagnostics.star_backtracking_attempts <= 2,
        "star before a literal should jump to literal occurrences, got {} attempts",
        diagnostics.star_backtracking_attempts
    );
}

fn assert_simple_glob_uses_fast_path(pattern: &str, query: &str, expected_matches: &[u32]) {
    assert_simple_glob_uses_fast_path_with_mode(
        pattern,
        query,
        MatchMode::CaseSensitive,
        expected_matches,
    );
}

fn assert_simple_glob_uses_fast_path_with_mode(
    pattern: &str,
    query: &str,
    mode: MatchMode,
    expected_matches: &[u32],
) {
    let patterns = vec![pattern];
    let pg = Paraglob::build_from_patterns(&patterns, mode).unwrap();

    let (matches, diagnostics) = pg.find_all_with_diagnostics(query);

    assert_eq!(matches, expected_matches);
    assert_eq!(diagnostics.raw_candidate_pattern_ids, 1);
    assert_eq!(diagnostics.candidate_pattern_ids, 1);
    assert_eq!(diagnostics.glob_verification_attempts, 1);
    assert_eq!(
        diagnostics.literal_order_precheck_attempts, 0,
        "simple glob {pattern:?} should not run the literal-order precheck"
    );
    assert_eq!(
        diagnostics.serialized_glob_segment_steps, 0,
        "simple glob {pattern:?} should not use the general segment walker"
    );
    assert_eq!(
        diagnostics.star_backtracking_attempts, 0,
        "simple glob {pattern:?} should not backtrack through star matching"
    );
}

#[test]
fn diagnostics_fast_path_simple_suffix_glob() {
    assert_simple_glob_uses_fast_path("*.evil.com", "cdn.evil.com", &[0]);
}

#[test]
fn diagnostics_fast_path_simple_prefix_glob() {
    assert_simple_glob_uses_fast_path("evil.*", "evil.example", &[0]);
}

#[test]
fn diagnostics_fast_path_simple_contains_glob() {
    assert_simple_glob_uses_fast_path("*.evil.*", "cdn.evil.example", &[0]);
}

#[test]
fn diagnostics_fast_path_simple_suffix_glob_case_insensitive() {
    assert_simple_glob_uses_fast_path_with_mode(
        "*.Evil.COM",
        "cdn.evil.com",
        MatchMode::CaseInsensitive,
        &[0],
    );
}

#[test]
fn diagnostics_fast_path_simple_suffix_rejects_non_suffix_match() {
    assert_simple_glob_uses_fast_path("*.evil.com", "cdn.evil.com.example", &[]);
}

#[test]
fn diagnostics_fast_path_suffix_window_with_question() {
    assert_simple_glob_uses_fast_path("*.evil.?om", "cdn.evil.com", &[0]);
}

#[test]
fn diagnostics_fast_path_suffix_window_with_char_class() {
    assert_simple_glob_uses_fast_path("*.evil.[co]om", "cdn.evil.com", &[0]);
}

#[test]
fn diagnostics_fast_path_suffix_window_with_char_class_range() {
    assert_simple_glob_uses_fast_path("*.evil.[a-d]om", "cdn.evil.com", &[0]);
}

#[test]
fn diagnostics_fast_path_suffix_window_with_negated_char_class() {
    assert_simple_glob_uses_fast_path("*.evil.[!x]om", "cdn.evil.com", &[0]);
}

#[test]
fn diagnostics_fast_path_suffix_window_with_char_class_case_insensitive() {
    assert_simple_glob_uses_fast_path_with_mode(
        "*.Evil.[CO]OM",
        "cdn.evil.com",
        MatchMode::CaseInsensitive,
        &[0],
    );
}

#[test]
fn diagnostics_fast_path_prefix_window_with_question() {
    assert_simple_glob_uses_fast_path("evil?.com*", "evil1.com/path", &[0]);
}

#[test]
fn diagnostics_fast_path_contains_window_with_char_class() {
    assert_simple_glob_uses_fast_path("*.evil.[co]om*", "cdn.evil.com/path", &[0]);
}

#[test]
fn diagnostics_fast_path_window_rejects_non_matching_char_class() {
    assert_simple_glob_uses_fast_path("*.evil.[ab]om", "cdn.evil.com", &[]);
}

#[test]
fn diagnostics_window_with_non_literal_start_uses_general_verifier() {
    let patterns = vec!["*?.evil.com"];
    let pg = Paraglob::build_from_patterns(&patterns, MatchMode::CaseSensitive).unwrap();

    let (matches, diagnostics) = pg.find_all_with_diagnostics("a.evil.com");

    assert_eq!(matches, vec![0]);
    assert_eq!(diagnostics.raw_candidate_pattern_ids, 1);
    assert_eq!(diagnostics.candidate_pattern_ids, 1);
    assert_eq!(diagnostics.literal_order_precheck_attempts, 1);
    assert_eq!(diagnostics.glob_verification_attempts, 1);
    assert!(diagnostics.serialized_glob_segment_steps > 0);
}

#[test]
fn diagnostics_do_not_enqueue_globs_from_unselected_common_literals() {
    let patterns: Vec<String> = (0..1000)
        .map(|i| format!("*shared*needle_{i:04}"))
        .collect();
    let pattern_refs: Vec<&str> = patterns.iter().map(String::as_str).collect();
    let pg = Paraglob::build_from_patterns(&pattern_refs, MatchMode::CaseSensitive).unwrap();

    let (matches, diagnostics) = pg.find_all_with_diagnostics("shared but no required suffix");

    assert!(matches.is_empty());
    assert_eq!(
        diagnostics.candidate_pattern_ids, 0,
        "a common literal should not enqueue globs anchored on longer required literals"
    );
    assert_eq!(diagnostics.glob_verification_attempts, 0);
}

#[test]
fn diagnostics_skip_verification_when_literal_segments_are_absent() {
    let patterns: Vec<String> = (0..1000).map(|i| format!("*anchor_{i:04}*x")).collect();
    let pattern_refs: Vec<&str> = patterns.iter().map(String::as_str).collect();
    let pg = Paraglob::build_from_patterns(&pattern_refs, MatchMode::CaseSensitive).unwrap();

    let (matches, diagnostics) = pg.find_all_with_diagnostics("anchor_0500 missing");

    assert!(matches.is_empty());
    assert_eq!(diagnostics.raw_candidate_pattern_ids, 1);
    assert_eq!(diagnostics.candidate_pattern_ids, 1);
    assert_eq!(diagnostics.literal_order_precheck_attempts, 1);
    assert_eq!(
        diagnostics.glob_verification_attempts, 0,
        "literal-order precheck should skip full verification for impossible candidates"
    );
}

#[test]
fn diagnostics_dedup_candidate_ids_before_verification() {
    let patterns = vec!["*alpha*beta"];
    let pg = Paraglob::build_from_patterns(&patterns, MatchMode::CaseSensitive).unwrap();

    let (matches, diagnostics) = pg.find_all_with_diagnostics("alpha beta");

    assert_eq!(matches, vec![0]);
    assert_eq!(
        diagnostics.raw_candidate_pattern_ids, 1,
        "a glob should be reachable through one selected literal anchor"
    );
    assert_eq!(diagnostics.candidate_pattern_ids, 1);
    assert_eq!(diagnostics.glob_verification_attempts, 1);
}

#[test]
fn diagnostics_anchor_globs_on_longer_required_literals() {
    let patterns: Vec<String> = (0..1000)
        .map(|i| format!("*shared*needle_{i:04}"))
        .collect();
    let pattern_refs: Vec<&str> = patterns.iter().map(String::as_str).collect();
    let pg = Paraglob::build_from_patterns(&pattern_refs, MatchMode::CaseSensitive).unwrap();

    let (matches, diagnostics) = pg.find_all_with_diagnostics("shared payload needle_0500");

    assert_eq!(matches, vec![500]);
    assert_eq!(diagnostics.ac_literal_hits, 1);
    assert_eq!(diagnostics.raw_candidate_pattern_ids, 1);
    assert_eq!(diagnostics.candidate_pattern_ids, 1);
    assert_eq!(diagnostics.glob_verification_attempts, 1);
    assert_eq!(diagnostics.successful_glob_verifications, 1);
}

#[test]
fn single_literal_globs_remain_indexed() {
    let patterns = vec!["*.evil.com"];
    let pg = Paraglob::build_from_patterns(&patterns, MatchMode::CaseSensitive).unwrap();

    let (matches, diagnostics) = pg.find_all_with_diagnostics("cdn.evil.com");

    assert_eq!(matches, vec![0]);
    assert_eq!(diagnostics.ac_literal_hits, 1);
    assert_eq!(diagnostics.candidate_pattern_ids, 1);
    assert_eq!(diagnostics.glob_verification_attempts, 1);
}
