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
fn diagnostics_count_candidate_fanout_and_glob_verification() {
    let patterns = vec!["*shared*needle", "*shared*absent", "??"];
    let pg = Paraglob::build_from_patterns(&patterns, MatchMode::CaseSensitive).unwrap();

    let (matches, diagnostics) = pg.find_all_with_diagnostics("shared needle");

    assert_eq!(matches, vec![0]);
    assert_eq!(diagnostics.query_bytes_scanned, "shared needle".len());
    assert_eq!(diagnostics.ac_literal_hits, 2);
    assert_eq!(diagnostics.candidate_pattern_ids, 2);
    assert_eq!(diagnostics.pure_wildcard_checks, 1);
    assert_eq!(diagnostics.glob_verification_attempts, 2);
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
    let patterns = vec!["*needle"];
    let pg = Paraglob::build_from_patterns(&patterns, MatchMode::CaseSensitive).unwrap();
    let query = format!("{}needle", "a".repeat(128));

    let (matches, diagnostics) = pg.find_all_with_diagnostics(&query);

    assert_eq!(matches, vec![0]);
    assert!(
        diagnostics.star_backtracking_attempts <= 2,
        "star before a literal should jump to literal occurrences, got {} attempts",
        diagnostics.star_backtracking_attempts
    );
}

#[test]
fn diagnostics_skip_verification_when_literal_segments_are_absent() {
    let patterns: Vec<String> = (0..1000)
        .map(|i| format!("*shared*needle_{i:04}"))
        .collect();
    let pattern_refs: Vec<&str> = patterns.iter().map(String::as_str).collect();
    let pg = Paraglob::build_from_patterns(&pattern_refs, MatchMode::CaseSensitive).unwrap();

    let (matches, diagnostics) = pg.find_all_with_diagnostics("shared but no required suffix");

    assert!(matches.is_empty());
    assert_eq!(diagnostics.candidate_pattern_ids, 1000);
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
        diagnostics.raw_candidate_pattern_ids, 2,
        "both literal anchors should produce the same candidate before deduplication"
    );
    assert_eq!(diagnostics.candidate_pattern_ids, 1);
    assert_eq!(diagnostics.glob_verification_attempts, 1);
}
