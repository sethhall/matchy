//! Integration tests for Paraglob pattern matching correctness
//!
//! These tests verify end-to-end functionality of the pattern matcher
//! including edge cases, complex patterns, and real-world scenarios.

use matchy_data_format::DataValue;
use matchy_paraglob::{error::ParaglobError, MatchMode, Paraglob, ParaglobBuilder};
use std::collections::HashMap;

#[test]
fn test_basic_wildcards() {
    let patterns = vec!["*.txt", "test*", "*file*"];
    let pg = Paraglob::build_from_patterns(&patterns, MatchMode::CaseSensitive).unwrap();

    let m1 = pg.find_all("document.txt");
    let m2 = pg.find_all("test_case");
    let m3 = pg.find_all("myfile.dat");
    let m4 = pg.find_all("nomatch");

    assert!(!m1.is_empty(), "*.txt should match document.txt");
    assert!(!m2.is_empty(), "test* should match test_case");
    assert!(!m3.is_empty(), "*file* should match myfile.dat");
    assert!(m4.is_empty(), "nothing should match nomatch");
}

#[test]
fn single_internal_star_fast_path_preserves_glob_semantics() {
    let patterns = vec!["prefix*suffix", "aba*aba", "π*λ"];
    let pg = Paraglob::build_from_patterns(&patterns, MatchMode::CaseSensitive).unwrap();

    assert_eq!(pg.find_all("prefixsuffix"), vec![0]);
    assert_eq!(pg.find_all("prefix-middle-suffix"), vec![0]);
    assert!(
        pg.find_all("aba").is_empty(),
        "adjacent literals cannot overlap"
    );
    assert_eq!(pg.find_all("abaaba"), vec![1]);
    assert_eq!(pg.find_all("π-middle-λ"), vec![2]);
    assert_eq!(
        pg.try_find_all_bounded("prefix-middle-suffix", 8, 1024)
            .unwrap(),
        vec![0]
    );
}

#[test]
fn single_internal_star_fast_path_respects_case_insensitive_mode() {
    let pg = Paraglob::build_from_patterns(&["PREFIX*SUFFIX"], MatchMode::CaseInsensitive).unwrap();

    assert_eq!(pg.find_all("prefix-Middle-suffix"), vec![0]);
}

#[test]
fn test_overlapping_glob_literal_candidates_case_sensitive() {
    let patterns = vec!["*aaa[b]*LONG", "*aa?LONG"];
    let pg = Paraglob::build_from_patterns(&patterns, MatchMode::CaseSensitive).unwrap();

    assert_eq!(
        pg.find_all("aaaabzzzLONG"),
        vec![0],
        "the general verifier must retry an overlapping literal candidate"
    );
    assert_eq!(
        pg.find_all("aaaYLONG"),
        vec![1],
        "the fixed-window verifier must retry an overlapping literal candidate"
    );
}

#[test]
fn test_overlapping_glob_literal_candidates_case_insensitive() {
    let patterns = vec!["*AAA[b]*LONG", "*AA?LONG"];
    let pg = Paraglob::build_from_patterns(&patterns, MatchMode::CaseInsensitive).unwrap();

    assert_eq!(pg.find_all("aaaaBzzzlong"), vec![0]);
    assert_eq!(pg.find_all("aaaYlong"), vec![1]);
}

#[test]
fn test_short_literal_glob_candidates_case_sensitive() {
    let pg = Paraglob::build_from_patterns(&["*aa?X"], MatchMode::CaseSensitive).unwrap();

    assert_eq!(pg.find_all("aaaYX"), vec![0]);
    assert!(pg.find_all("aaaYZ").is_empty());
}

#[test]
fn test_short_literal_glob_candidates_case_insensitive() {
    let pg = Paraglob::build_from_patterns(&["*AA?X"], MatchMode::CaseInsensitive).unwrap();

    assert_eq!(pg.find_all("aaaYx"), vec![0]);
    assert!(pg.find_all("aaaYz").is_empty());
}

#[test]
fn test_case_insensitive_char_class_preserves_raw_range_semantics() {
    let patterns = vec!["anchor[!Z-a]", "anchor[Z-a]"];
    let pg = Paraglob::build_from_patterns(&patterns, MatchMode::CaseInsensitive).unwrap();

    assert_eq!(
        pg.find_all("anchorm"),
        vec![0],
        "a raw-ordered range that normalizes to an empty interval must retain reference semantics"
    );
}

#[test]
fn test_exact_string_matching() {
    let patterns = vec!["hello", "world", "test"];
    let pg = Paraglob::build_from_patterns(&patterns, MatchMode::CaseSensitive).unwrap();

    let m1 = pg.find_all("hello");
    let m2 = pg.find_all("world");
    let m3 = pg.find_all("hello world");
    let m4 = pg.find_all("nomatch");

    assert_eq!(m1.len(), 1, "hello should match exactly once");
    assert_eq!(m2.len(), 1, "world should match exactly once");
    assert_eq!(m3.len(), 2, "hello world should match both hello and world");
    assert!(m4.is_empty(), "nomatch should not match anything");
}

#[test]
fn test_duplicate_pattern_deduplication() {
    let patterns = vec!["*test*", "*test*", "hello", "hello"];
    let pg = Paraglob::build_from_patterns(&patterns, MatchMode::CaseSensitive).unwrap();

    let m1 = pg.find_all("test123");
    let m2 = pg.find_all("hello");

    // Should deduplicate, so only 1 match each
    assert_eq!(
        m1.len(),
        1,
        "duplicate *test* patterns should be deduplicated"
    );
    assert_eq!(
        m2.len(),
        1,
        "duplicate hello patterns should be deduplicated"
    );
}

#[test]
fn test_multiple_patterns_matching_same_text() {
    let patterns = vec!["*.txt", "*file*", "test*"];
    let pg = Paraglob::build_from_patterns(&patterns, MatchMode::CaseSensitive).unwrap();

    let m1 = pg.find_all("testfile.txt");

    // Should match all 3 patterns
    assert_eq!(m1.len(), 3, "testfile.txt should match all three patterns");
    assert!(m1.contains(&0), "should match *.txt");
    assert!(m1.contains(&1), "should match *file*");
    assert!(m1.contains(&2), "should match test*");
}

#[test]
fn test_find_first_matches_find_all_ordering() {
    let patterns = vec!["*.txt", "*file*", "test*"];
    let pg = Paraglob::build_from_patterns(&patterns, MatchMode::CaseSensitive).unwrap();

    let all = pg.find_all("testfile.txt");

    assert_eq!(all.first().copied(), pg.find_first("testfile.txt"));
    assert_eq!(None, pg.find_first("nomatch"));
}

#[test]
fn bounded_matching_enforces_raw_candidate_and_match_caps() {
    let literal =
        Paraglob::build_from_patterns(&["a", "a?", "a??"], MatchMode::CaseSensitive).unwrap();

    assert!(matches!(
        literal.try_find_all_bounded("a", 3, 2),
        Err(ParaglobError::ResourceLimitExceeded(_))
    ));
    assert!(matches!(
        literal.try_find_first_bounded("a", 2),
        Err(ParaglobError::ResourceLimitExceeded(_))
    ));
    assert_eq!(literal.try_find_all_bounded("a", 3, 3).unwrap(), vec![0]);
    assert_eq!(literal.try_find_first_bounded("a", 3).unwrap(), Some(0));

    let wildcards = Paraglob::build_from_patterns(&["*", "?"], MatchMode::CaseSensitive).unwrap();
    assert!(matches!(
        wildcards.try_find_all_bounded("x", 1, 2),
        Err(ParaglobError::ResourceLimitExceeded(_))
    ));
    assert!(matches!(
        wildcards.try_find_all_bounded("x", 2, 1),
        Err(ParaglobError::ResourceLimitExceeded(_))
    ));
    assert_eq!(
        wildcards.try_find_all_bounded("x", 2, 2).unwrap(),
        vec![0, 1]
    );
}

#[test]
fn bounded_matching_caps_unique_ac_literal_hits() {
    let text = "abcdefgh";
    let mut patterns = Vec::new();
    for start in 0..text.len() {
        for end in start + 1..=text.len() {
            patterns.push(text[start..end].to_string());
        }
    }
    let pattern_refs: Vec<&str> = patterns.iter().map(String::as_str).collect();
    let pg = Paraglob::build_from_patterns(&pattern_refs, MatchMode::CaseSensitive).unwrap();

    assert!(matches!(
        pg.try_find_all_bounded(text, patterns.len(), text.len()),
        Err(ParaglobError::ResourceLimitExceeded(_))
    ));
    assert_eq!(
        pg.try_find_all_bounded(text, patterns.len(), patterns.len())
            .unwrap(),
        (0..u32::try_from(patterns.len()).unwrap()).collect::<Vec<_>>()
    );
}

#[test]
fn bounded_matching_caps_pure_wildcard_checks_before_iteration() {
    let patterns: Vec<String> = (1..=16)
        .map(|question_count| format!("{}*", "?".repeat(question_count)))
        .collect();
    let pattern_refs: Vec<&str> = patterns.iter().map(String::as_str).collect();
    let pg = Paraglob::build_from_patterns(&pattern_refs, MatchMode::CaseSensitive).unwrap();
    let text = "xxxxxxxxxxxxxxx";

    assert!(matches!(
        pg.try_find_all_bounded(text, patterns.len(), patterns.len() - 1),
        Err(ParaglobError::ResourceLimitExceeded(_))
    ));
    assert_eq!(
        pg.try_find_all_bounded(text, patterns.len(), 64).unwrap(),
        (0..u32::try_from(patterns.len() - 1).unwrap()).collect::<Vec<_>>()
    );
}

#[test]
fn bounded_case_insensitive_matching_caps_query_before_normalization() {
    let pg = Paraglob::build_from_patterns(&["needle"], MatchMode::CaseInsensitive).unwrap();
    let text = "X".repeat(1024);

    assert!(matches!(
        pg.try_find_all_bounded(&text, 1, 8),
        Err(ParaglobError::ResourceLimitExceeded(_))
    ));
    assert!(pg.find_all(&text).is_empty());
}

#[test]
fn bounded_matching_shares_work_across_many_false_glob_candidates() {
    let class_characters = "bcdefghijklmnopqrstuvwxyzBCDEFGH";
    let patterns: Vec<String> = class_characters
        .chars()
        .map(|character| format!("a[{character}]"))
        .collect();
    assert_eq!(patterns.len(), 32);
    let pattern_refs: Vec<&str> = patterns.iter().map(String::as_str).collect();
    let pg = Paraglob::build_from_patterns(&pattern_refs, MatchMode::CaseSensitive).unwrap();
    let text = "a".repeat(64);

    let legacy = pg.find_all(&text);
    assert!(legacy.is_empty(), "legacy lookup must be unchanged");
    assert_eq!(
        pg.try_find_all_bounded(&text, usize::MAX, usize::MAX)
            .unwrap(),
        legacy,
        "usize::MAX must retain the legacy matching path"
    );
    assert_eq!(
        pg.try_find_first_bounded(&text, usize::MAX).unwrap(),
        pg.find_first(&text)
    );
    assert!(matches!(
        pg.try_find_all_bounded(&text, patterns.len(), 64),
        Err(ParaglobError::ResourceLimitExceeded(_))
    ));
    assert!(pg
        .try_find_all_bounded(&text, patterns.len(), 256)
        .unwrap()
        .is_empty());
}

#[test]
fn bounded_matching_charges_overlapping_literal_comparison_bytes() {
    let repeated_literal = "A".repeat(128);
    let pattern = format!("*{repeated_literal}*Z");
    let pg =
        Paraglob::build_from_patterns(&[pattern.as_str()], MatchMode::CaseInsensitive).unwrap();
    let text = "a".repeat(256);

    assert!(
        pg.find_all(&text).is_empty(),
        "legacy lookup must be unchanged"
    );
    assert!(matches!(
        pg.try_find_all_bounded(&text, 1, text.len()),
        Err(ParaglobError::ResourceLimitExceeded(_))
    ));
    assert!(pg.try_find_all_bounded(&text, 1, 1024).unwrap().is_empty());
}

#[test]
fn test_case_sensitivity() {
    let patterns = vec!["Test*", "HELLO"];
    let pg = Paraglob::build_from_patterns(&patterns, MatchMode::CaseSensitive).unwrap();

    let m1 = pg.find_all("Test123");
    let m2 = pg.find_all("test123");
    let m3 = pg.find_all("HELLO");
    let m4 = pg.find_all("hello");

    assert!(!m1.is_empty(), "Test* should match Test123");
    assert!(
        m2.is_empty(),
        "Test* should NOT match test123 (case sensitive)"
    );
    assert!(!m3.is_empty(), "HELLO should match HELLO");
    assert!(
        m4.is_empty(),
        "HELLO should NOT match hello (case sensitive)"
    );
}

#[test]
fn test_case_insensitivity() {
    let patterns = vec!["Test*", "HELLO"];
    let pg = Paraglob::build_from_patterns(&patterns, MatchMode::CaseInsensitive).unwrap();

    let m1 = pg.find_all("Test123");
    let m2 = pg.find_all("test123");
    let m3 = pg.find_all("HELLO");
    let m4 = pg.find_all("hello");

    assert!(!m1.is_empty(), "Test* should match Test123");
    assert!(
        !m2.is_empty(),
        "Test* should match test123 (case insensitive)"
    );
    assert!(!m3.is_empty(), "HELLO should match HELLO");
    assert!(
        !m4.is_empty(),
        "HELLO should match hello (case insensitive)"
    );
}

#[test]
fn test_empty_string_queries() {
    let patterns = vec!["test"];
    let pg = Paraglob::build_from_patterns(&patterns, MatchMode::CaseSensitive).unwrap();

    let m1 = pg.find_all("");
    let m2 = pg.find_all("test");

    assert!(m1.is_empty(), "empty string should not match anything");
    assert_eq!(m2.len(), 1, "test should match test pattern");
}

#[test]
fn test_pure_literal_patterns() {
    let patterns = vec!["exact_match", "another_literal", "third"];
    let pg = Paraglob::build_from_patterns(&patterns, MatchMode::CaseSensitive).unwrap();

    let m1 = pg.find_all("exact_match");
    let m2 = pg.find_all("prefix_exact_match_suffix");
    let m3 = pg.find_all("nomatch");

    assert_eq!(m1.len(), 1, "exact_match should match exact_match pattern");
    assert_eq!(
        m2.len(),
        1,
        "prefix_exact_match_suffix should match exact_match pattern (substring)"
    );
    assert!(m3.is_empty(), "nomatch should not match anything");
}

#[test]
fn test_overlapping_literal_patterns() {
    let patterns = vec!["*test*", "test*", "*test"];
    let pg = Paraglob::build_from_patterns(&patterns, MatchMode::CaseSensitive).unwrap();

    let m1 = pg.find_all("test");
    let m2 = pg.find_all("testing");
    let m3 = pg.find_all("mytest");
    let m4 = pg.find_all("mytesting");

    // All 3 patterns have "test" as literal
    assert_eq!(m1.len(), 3, "test should match all 3 patterns");
    assert_eq!(m2.len(), 2, "testing should match *test* and test*");
    assert_eq!(m3.len(), 2, "mytest should match *test* and *test");
    assert_eq!(m4.len(), 1, "mytesting should match only *test*");
}

#[test]
fn test_real_world_file_patterns() {
    let patterns = vec!["*.rs", "*.toml", "Cargo.*", "src/*", "*.md"];
    let pg = Paraglob::build_from_patterns(&patterns, MatchMode::CaseSensitive).unwrap();

    let m1 = pg.find_all("main.rs");
    let m2 = pg.find_all("Cargo.toml");
    let m3 = pg.find_all("src/lib.rs");
    let m4 = pg.find_all("README.md");
    let m5 = pg.find_all("test.py");

    assert!(!m1.is_empty(), "main.rs should match *.rs");
    assert!(
        m2.len() >= 2,
        "Cargo.toml should match both *.toml and Cargo.*"
    );
    assert!(m3.len() >= 2, "src/lib.rs should match both *.rs and src/*");
    assert!(!m4.is_empty(), "README.md should match *.md");
    assert!(m5.is_empty(), "test.py should not match any pattern");
}

#[test]
fn test_large_pattern_set() {
    // Generate a large set of patterns to test scalability
    let mut patterns = Vec::new();
    for i in 0..1000 {
        patterns.push(format!("pattern_{i}_*"));
    }
    let pattern_refs: Vec<&str> = patterns.iter().map(String::as_str).collect();
    let pg = Paraglob::build_from_patterns(&pattern_refs, MatchMode::CaseSensitive).unwrap();

    // Test that we can find specific patterns in the large set
    let m1 = pg.find_all("pattern_500_test");
    let m2 = pg.find_all("pattern_999_data");
    let m3 = pg.find_all("nomatch");

    // Note: These will match multiple patterns due to substring matching
    // "pattern_500_test" contains "pattern_5", "pattern_50", and "pattern_500"
    assert!(
        !m1.is_empty(),
        "pattern_500_test should match at least pattern_500_*"
    );
    assert!(
        !m2.is_empty(),
        "pattern_999_data should match at least pattern_999_*"
    );
    assert!(m3.is_empty(), "nomatch should not match anything");

    // Verify it includes the expected primary matches
    assert!(m1.contains(&500), "should match pattern_500_*");
    assert!(m2.contains(&999), "should match pattern_999_*");
}

#[test]
fn test_combined_literal_and_glob_patterns() {
    // Mix of literal strings and glob patterns
    let patterns = vec!["hello", "*.txt", "test_*"];
    let pg = Paraglob::build_from_patterns(&patterns, MatchMode::CaseSensitive).unwrap();

    let m1 = pg.find_all("hello.txt");
    let m2 = pg.find_all("test_file.txt");

    // hello.txt should match both "hello" (substring) and "*.txt"
    assert_eq!(m1.len(), 2, "hello.txt should match hello and *.txt");
    assert!(m1.contains(&0), "should match hello");
    assert!(m1.contains(&1), "should match *.txt");

    // test_file.txt should match both "test_*" and "*.txt"
    assert_eq!(m2.len(), 2, "test_file.txt should match test_* and *.txt");
    assert!(m2.contains(&1), "should match *.txt");
    assert!(m2.contains(&2), "should match test_*");
}

#[test]
fn test_pure_wildcard_patterns() {
    let patterns = vec!["*", "?", "**"];
    let pg = Paraglob::build_from_patterns(&patterns, MatchMode::CaseSensitive).unwrap();

    let m1 = pg.find_all("test");
    let m2 = pg.find_all("a");
    let m3 = pg.find_all("");

    // "*" and "**" should match everything
    assert!(m1.len() >= 2, "test should match * and **");
    assert!(m2.len() >= 3, "single char should match *, ?, and **");

    // Empty string should only match "*" and "**", not "?"
    assert!(m3.len() >= 2, "empty string should match * and **");
}

// =============================================================================
// V2 FORMAT TESTS - Pattern matching with associated data
// =============================================================================

#[test]
fn test_v2_simple_pattern_with_data() {
    let patterns = vec!["*.evil.com", "malware.*"];

    // Build threat data
    let mut threat1 = HashMap::new();
    threat1.insert(
        "threat_level".to_string(),
        DataValue::String("high".to_string()),
    );
    threat1.insert(
        "category".to_string(),
        DataValue::String("phishing".to_string()),
    );

    let mut threat2 = HashMap::new();
    threat2.insert(
        "threat_level".to_string(),
        DataValue::String("critical".to_string()),
    );
    threat2.insert(
        "category".to_string(),
        DataValue::String("malware".to_string()),
    );

    let data_values = vec![Some(DataValue::Map(threat1)), Some(DataValue::Map(threat2))];

    let pg = Paraglob::build_from_patterns_with_data(
        &patterns,
        Some(&data_values),
        MatchMode::CaseSensitive,
    )
    .unwrap();

    // Verify v2 format
    assert!(pg.has_data_section(), "Should be v2 format with data");

    // Verify we can retrieve data
    let data0 = pg.get_pattern_data(0).expect("Pattern 0 should have data");
    let data1 = pg.get_pattern_data(1).expect("Pattern 1 should have data");

    // Check data values
    if let DataValue::Map(m) = data0 {
        assert_eq!(
            m.get("threat_level"),
            Some(&DataValue::String("high".to_string()))
        );
        assert_eq!(
            m.get("category"),
            Some(&DataValue::String("phishing".to_string()))
        );
    } else {
        panic!("Expected Map data for pattern 0");
    }

    if let DataValue::Map(m) = data1 {
        assert_eq!(
            m.get("threat_level"),
            Some(&DataValue::String("critical".to_string()))
        );
    } else {
        panic!("Expected Map data for pattern 1");
    }
}

#[test]
fn test_v2_backward_compatibility_v1_format() {
    // Build old-style v1 format (no data)
    let patterns = vec!["*.txt", "test*"];
    let pg = Paraglob::build_from_patterns(&patterns, MatchMode::CaseSensitive).unwrap();

    // Should NOT be v2 format
    assert!(
        !pg.has_data_section(),
        "V1 format should not have data section"
    );

    // Trying to get data should return None
    assert!(
        pg.get_pattern_data(0).is_none(),
        "V1 format should have no data"
    );
    assert!(
        pg.get_pattern_data(1).is_none(),
        "V1 format should have no data"
    );
}

#[test]
fn test_v2_data_deduplication() {
    let patterns = vec!["pattern1", "pattern2", "pattern3"];

    // All patterns get the SAME data
    let same_data = DataValue::String("shared_value".to_string());
    let data_values = vec![
        Some(same_data.clone()),
        Some(same_data.clone()),
        Some(same_data),
    ];

    let pg = Paraglob::build_from_patterns_with_data(
        &patterns,
        Some(&data_values),
        MatchMode::CaseSensitive,
    )
    .unwrap();

    // All patterns should have data
    assert!(pg.get_pattern_data(0).is_some());
    assert!(pg.get_pattern_data(1).is_some());
    assert!(pg.get_pattern_data(2).is_some());

    // Verify deduplication worked (all point to same data)
    let data0 = pg.get_pattern_data(0).unwrap();
    let data1 = pg.get_pattern_data(1).unwrap();
    let data2 = pg.get_pattern_data(2).unwrap();

    assert_eq!(data0, data1);
    assert_eq!(data1, data2);
}

#[test]
fn test_v2_roundtrip_serialization() {
    let patterns = vec!["*.evil.com", "malware.*", "test*"];

    let mut threat_data = HashMap::new();
    threat_data.insert("score".to_string(), DataValue::Uint32(95));
    threat_data.insert("active".to_string(), DataValue::Bool(true));

    let data_values = vec![
        Some(DataValue::Map(threat_data.clone())),
        Some(DataValue::Map(threat_data)),
        Some(DataValue::String("test_data".to_string())),
    ];

    let pg = Paraglob::build_from_patterns_with_data(
        &patterns,
        Some(&data_values),
        MatchMode::CaseSensitive,
    )
    .unwrap();

    // Serialize and deserialize
    let bytes = pg.buffer().to_vec();
    let pg2 = Paraglob::from_buffer(bytes, MatchMode::CaseSensitive).unwrap();

    // Verify format
    assert!(pg2.has_data_section(), "Deserialized should be v2 format");

    // Verify data preserved
    let data0 = pg2
        .get_pattern_data(0)
        .expect("Pattern 0 data should survive roundtrip");
    let data2 = pg2
        .get_pattern_data(2)
        .expect("Pattern 2 data should survive roundtrip");

    if let DataValue::Map(m) = data0 {
        assert_eq!(m.get("score"), Some(&DataValue::Uint32(95)));
        assert_eq!(m.get("active"), Some(&DataValue::Bool(true)));
    } else {
        panic!("Expected Map after roundtrip");
    }

    assert_eq!(data2, DataValue::String("test_data".to_string()));
}

#[test]
fn test_pattern_data_batch_preserves_order_and_missing_values() {
    let patterns = ["first", "second", "third"];
    let data = [
        Some(DataValue::String("one".to_string())),
        None,
        Some(DataValue::Uint32(3)),
    ];
    let paraglob =
        Paraglob::build_from_patterns_with_data(&patterns, Some(&data), MatchMode::CaseSensitive)
            .unwrap();

    assert_eq!(
        paraglob
            .try_get_pattern_data_many(&[2, 1, 0, 2, u32::MAX])
            .unwrap(),
        vec![
            Some(DataValue::Uint32(3)),
            None,
            Some(DataValue::String("one".to_string())),
            Some(DataValue::Uint32(3)),
            None,
        ]
    );
}

#[test]
#[cfg_attr(
    miri,
    ignore = "aggregate pattern-data allocation fixture is prohibitively slow under Miri"
)]
fn test_pattern_data_batch_shares_decode_budget() {
    let large = DataValue::String("x".repeat(20_000));
    let paraglob = Paraglob::build_from_patterns_with_data(
        &["large"],
        Some(&[Some(large)]),
        MatchMode::CaseSensitive,
    )
    .unwrap();

    assert!(paraglob.try_get_pattern_data(0).unwrap().is_some());
    let error = paraglob
        .try_get_pattern_data_many(&[0; 70])
        .expect_err("repeated values must share one aggregate allocation budget");
    assert!(matches!(error, ParaglobError::ResourceLimitExceeded(_)));
}

#[test]
fn test_v2_partial_data_coverage() {
    // Not all patterns need data
    let patterns = vec!["pattern1", "pattern2", "pattern3"];

    let data_values = vec![
        Some(DataValue::String("has_data".to_string())),
        None, // No data for pattern2
        Some(DataValue::Uint32(42)),
    ];

    let pg = Paraglob::build_from_patterns_with_data(
        &patterns,
        Some(&data_values),
        MatchMode::CaseSensitive,
    )
    .unwrap();

    // Should still be v2 format (has some data)
    assert!(pg.has_data_section());

    // Check individual patterns
    assert!(
        pg.get_pattern_data(0).is_some(),
        "Pattern 0 should have data"
    );
    assert!(
        pg.get_pattern_data(1).is_none(),
        "Pattern 1 should NOT have data"
    );
    assert!(
        pg.get_pattern_data(2).is_some(),
        "Pattern 2 should have data"
    );
}

#[test]
fn test_v2_complex_nested_data() {
    let patterns = vec!["threat.*"];

    // Build complex nested structure
    let mut indicators = HashMap::new();
    indicators.insert("ip_count".to_string(), DataValue::Uint32(42));
    indicators.insert("domain_count".to_string(), DataValue::Uint32(15));

    let mut threat_data = HashMap::new();
    threat_data.insert("level".to_string(), DataValue::String("high".to_string()));
    threat_data.insert("confidence".to_string(), DataValue::Float(0.95));
    threat_data.insert("first_seen".to_string(), DataValue::Uint64(1704067200));
    threat_data.insert("indicators".to_string(), DataValue::Map(indicators));
    threat_data.insert(
        "tags".to_string(),
        DataValue::Array(vec![
            DataValue::String("botnet".to_string()),
            DataValue::String("c2".to_string()),
        ]),
    );
    threat_data.insert("active".to_string(), DataValue::Bool(true));

    let data_values = vec![Some(DataValue::Map(threat_data))];

    let pg = Paraglob::build_from_patterns_with_data(
        &patterns,
        Some(&data_values),
        MatchMode::CaseSensitive,
    )
    .unwrap();

    // Retrieve and verify complex structure
    let data = pg.get_pattern_data(0).expect("Should have data");

    if let DataValue::Map(m) = data {
        assert_eq!(m.get("level"), Some(&DataValue::String("high".to_string())));
        assert_eq!(m.get("active"), Some(&DataValue::Bool(true)));

        // Check nested map
        if let Some(DataValue::Map(ind)) = m.get("indicators") {
            assert_eq!(ind.get("ip_count"), Some(&DataValue::Uint32(42)));
        } else {
            panic!("Expected nested indicators map");
        }

        // Check array
        if let Some(DataValue::Array(tags)) = m.get("tags") {
            assert_eq!(tags.len(), 2);
            assert!(tags.contains(&DataValue::String("botnet".to_string())));
        } else {
            panic!("Expected tags array");
        }
    } else {
        panic!("Expected Map data");
    }
}

#[test]
fn test_v2_matching_with_data_retrieval() {
    let patterns = vec!["*.evil.com", "malware.*", "test*"];

    let mut data1 = HashMap::new();
    data1.insert(
        "id".to_string(),
        DataValue::String("THREAT-001".to_string()),
    );

    let mut data2 = HashMap::new();
    data2.insert(
        "id".to_string(),
        DataValue::String("THREAT-002".to_string()),
    );

    let mut data3 = HashMap::new();
    data3.insert("id".to_string(), DataValue::String("TEST-001".to_string()));

    let data_values = vec![
        Some(DataValue::Map(data1)),
        Some(DataValue::Map(data2)),
        Some(DataValue::Map(data3)),
    ];

    let pg = Paraglob::build_from_patterns_with_data(
        &patterns,
        Some(&data_values),
        MatchMode::CaseSensitive,
    )
    .unwrap();

    // Find matches
    let matches = pg.find_all("test.evil.com");
    assert!(!matches.is_empty(), "Should match some patterns");

    // Retrieve data for matched patterns
    for &pattern_id in &matches {
        let data = pg.get_pattern_data(pattern_id);
        assert!(
            data.is_some(),
            "Matched pattern {pattern_id} should have data"
        );

        // Verify it's a map with an ID
        if let Some(DataValue::Map(m)) = data {
            assert!(m.contains_key("id"), "Data should have id field");
        }
    }
}

#[test]
fn test_v2_all_mmdb_data_types() {
    let patterns = vec!["test"];

    // Build data with all MMDB types
    let mut data = HashMap::new();
    data.insert("string".to_string(), DataValue::String("hello".to_string()));
    data.insert("uint16".to_string(), DataValue::Uint16(12345));
    data.insert("uint32".to_string(), DataValue::Uint32(0xDEADBEEF));
    data.insert("uint64".to_string(), DataValue::Uint64(0x123456789ABCDEF0));
    data.insert(
        "uint128".to_string(),
        DataValue::Uint128(0x0123456789ABCDEF0123456789ABCDEF),
    );
    data.insert("int32".to_string(), DataValue::Int32(-42));
    data.insert(
        "double".to_string(),
        DataValue::Double(std::f64::consts::PI),
    );
    data.insert("float".to_string(), DataValue::Float(std::f32::consts::E));
    data.insert("bool_true".to_string(), DataValue::Bool(true));
    data.insert("bool_false".to_string(), DataValue::Bool(false));
    data.insert(
        "bytes".to_string(),
        DataValue::Bytes(vec![0xDE, 0xAD, 0xBE, 0xEF]),
    );
    data.insert(
        "array".to_string(),
        DataValue::Array(vec![
            DataValue::String("a".to_string()),
            DataValue::Uint32(1),
        ]),
    );

    let data_values = vec![Some(DataValue::Map(data))];

    let pg = Paraglob::build_from_patterns_with_data(
        &patterns,
        Some(&data_values),
        MatchMode::CaseSensitive,
    )
    .unwrap();

    // Serialize and deserialize to test all types survive roundtrip
    let bytes = pg.buffer().to_vec();
    let pg2 = Paraglob::from_buffer(bytes, MatchMode::CaseSensitive).unwrap();

    let data = pg2.get_pattern_data(0).expect("Should have data");

    if let DataValue::Map(m) = data {
        assert_eq!(
            m.get("string"),
            Some(&DataValue::String("hello".to_string()))
        );
        assert_eq!(m.get("uint16"), Some(&DataValue::Uint16(12345)));
        assert_eq!(m.get("uint32"), Some(&DataValue::Uint32(0xDEADBEEF)));
        assert_eq!(m.get("int32"), Some(&DataValue::Int32(-42)));
        assert_eq!(m.get("bool_true"), Some(&DataValue::Bool(true)));
        assert_eq!(m.get("bool_false"), Some(&DataValue::Bool(false)));
        // Float comparison with tolerance
        if let Some(DataValue::Float(f)) = m.get("float") {
            assert!((f - std::f32::consts::E).abs() < 0.0001);
        }
    } else {
        panic!("Expected Map data");
    }
}

#[test]
fn test_v2_incremental_builder() {
    let mut builder = ParaglobBuilder::new(MatchMode::CaseSensitive);

    // Add patterns incrementally
    let id1 = builder.add_pattern("*.txt").unwrap();
    let id2 = builder.add_pattern("test_*").unwrap();

    // Add pattern with data
    let mut threat_data = HashMap::new();
    threat_data.insert("level".to_string(), DataValue::String("high".to_string()));
    threat_data.insert("score".to_string(), DataValue::Uint32(95));

    let id3 = builder
        .add_pattern_with_data("*.evil.com", Some(DataValue::Map(threat_data)))
        .unwrap();

    // Build state verified indirectly by successful adds above

    // Build final matcher
    let pg = builder.build().unwrap();

    // Test matching
    let matches = pg.find_all("test_file.txt");
    assert!(matches.contains(&id1));
    assert!(matches.contains(&id2));

    let matches2 = pg.find_all("phishing.evil.com");
    assert!(matches2.contains(&id3));

    // Verify data retrieval
    let data = pg
        .get_pattern_data(id3)
        .expect("Pattern 3 should have data");
    if let DataValue::Map(m) = data {
        assert_eq!(m.get("level"), Some(&DataValue::String("high".to_string())));
        assert_eq!(m.get("score"), Some(&DataValue::Uint32(95)));
    } else {
        panic!("Expected Map data");
    }
}

#[test]
fn test_v2_incremental_builder_duplicate_handling() {
    let mut builder = ParaglobBuilder::new(MatchMode::CaseSensitive);

    // Add same pattern twice
    let id1 = builder.add_pattern("*.txt").unwrap();
    let id2 = builder.add_pattern("*.txt").unwrap();

    // Should return the same ID (deduplication)
    assert_eq!(id1, id2);

    let pg = builder.build().unwrap();
    let matches = pg.find_all("file.txt");

    // Should only match once
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0], id1);
}
