//! Integration tests for Paraglob pattern matching correctness
//!
//! These tests verify end-to-end functionality of the pattern matcher
//! including edge cases, complex patterns, and real-world scenarios.

use paraglob_rs::glob::MatchMode;
use paraglob_rs::Paraglob;

#[test]
fn test_basic_wildcards() {
    let patterns = vec!["*.txt", "test*", "*file*"];
    let mut pg = Paraglob::build_from_patterns(&patterns, MatchMode::CaseSensitive).unwrap();
    
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
fn test_exact_string_matching() {
    let patterns = vec!["hello", "world", "test"];
    let mut pg = Paraglob::build_from_patterns(&patterns, MatchMode::CaseSensitive).unwrap();
    
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
    let mut pg = Paraglob::build_from_patterns(&patterns, MatchMode::CaseSensitive).unwrap();
    
    let m1 = pg.find_all("test123");
    let m2 = pg.find_all("hello");
    
    // Should deduplicate, so only 1 match each
    assert_eq!(m1.len(), 1, "duplicate *test* patterns should be deduplicated");
    assert_eq!(m2.len(), 1, "duplicate hello patterns should be deduplicated");
}

#[test]
fn test_multiple_patterns_matching_same_text() {
    let patterns = vec!["*.txt", "*file*", "test*"];
    let mut pg = Paraglob::build_from_patterns(&patterns, MatchMode::CaseSensitive).unwrap();
    
    let m1 = pg.find_all("testfile.txt");
    
    // Should match all 3 patterns
    assert_eq!(m1.len(), 3, "testfile.txt should match all three patterns");
    assert!(m1.contains(&0), "should match *.txt");
    assert!(m1.contains(&1), "should match *file*");
    assert!(m1.contains(&2), "should match test*");
}

#[test]
fn test_case_sensitivity() {
    let patterns = vec!["Test*", "HELLO"];
    let mut pg = Paraglob::build_from_patterns(&patterns, MatchMode::CaseSensitive).unwrap();
    
    let m1 = pg.find_all("Test123");
    let m2 = pg.find_all("test123");
    let m3 = pg.find_all("HELLO");
    let m4 = pg.find_all("hello");
    
    assert!(!m1.is_empty(), "Test* should match Test123");
    assert!(m2.is_empty(), "Test* should NOT match test123 (case sensitive)");
    assert!(!m3.is_empty(), "HELLO should match HELLO");
    assert!(m4.is_empty(), "HELLO should NOT match hello (case sensitive)");
}

#[test]
fn test_case_insensitivity() {
    let patterns = vec!["Test*", "HELLO"];
    let mut pg = Paraglob::build_from_patterns(&patterns, MatchMode::CaseInsensitive).unwrap();
    
    let m1 = pg.find_all("Test123");
    let m2 = pg.find_all("test123");
    let m3 = pg.find_all("HELLO");
    let m4 = pg.find_all("hello");
    
    assert!(!m1.is_empty(), "Test* should match Test123");
    assert!(!m2.is_empty(), "Test* should match test123 (case insensitive)");
    assert!(!m3.is_empty(), "HELLO should match HELLO");
    assert!(!m4.is_empty(), "HELLO should match hello (case insensitive)");
}

#[test]
fn test_empty_string_queries() {
    let patterns = vec!["test"];
    let mut pg = Paraglob::build_from_patterns(&patterns, MatchMode::CaseSensitive).unwrap();
    
    let m1 = pg.find_all("");
    let m2 = pg.find_all("test");
    
    assert!(m1.is_empty(), "empty string should not match anything");
    assert_eq!(m2.len(), 1, "test should match test pattern");
}

#[test]
fn test_pure_literal_patterns() {
    let patterns = vec!["exact_match", "another_literal", "third"];
    let mut pg = Paraglob::build_from_patterns(&patterns, MatchMode::CaseSensitive).unwrap();
    
    let m1 = pg.find_all("exact_match");
    let m2 = pg.find_all("prefix_exact_match_suffix");
    let m3 = pg.find_all("nomatch");
    
    assert_eq!(m1.len(), 1, "exact_match should match exact_match pattern");
    assert_eq!(m2.len(), 1, "prefix_exact_match_suffix should match exact_match pattern (substring)");
    assert!(m3.is_empty(), "nomatch should not match anything");
}

#[test]
fn test_overlapping_literal_patterns() {
    let patterns = vec!["*test*", "test*", "*test"];
    let mut pg = Paraglob::build_from_patterns(&patterns, MatchMode::CaseSensitive).unwrap();
    
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
    let mut pg = Paraglob::build_from_patterns(&patterns, MatchMode::CaseSensitive).unwrap();
    
    let m1 = pg.find_all("main.rs");
    let m2 = pg.find_all("Cargo.toml");
    let m3 = pg.find_all("src/lib.rs");
    let m4 = pg.find_all("README.md");
    let m5 = pg.find_all("test.py");
    
    assert!(!m1.is_empty(), "main.rs should match *.rs");
    assert!(m2.len() >= 2, "Cargo.toml should match both *.toml and Cargo.*");
    assert!(m3.len() >= 2, "src/lib.rs should match both *.rs and src/*");
    assert!(!m4.is_empty(), "README.md should match *.md");
    assert!(m5.is_empty(), "test.py should not match any pattern");
}

#[test]
fn test_large_pattern_set() {
    // Generate a large set of patterns to test scalability
    let mut patterns = Vec::new();
    for i in 0..1000 {
        patterns.push(format!("pattern_{}_*", i));
    }
    let pattern_refs: Vec<&str> = patterns.iter().map(|s| s.as_str()).collect();
    let mut pg = Paraglob::build_from_patterns(&pattern_refs, MatchMode::CaseSensitive).unwrap();
    
    // Test that we can find specific patterns in the large set
    let m1 = pg.find_all("pattern_500_test");
    let m2 = pg.find_all("pattern_999_data");
    let m3 = pg.find_all("nomatch");
    
    // Note: These will match multiple patterns due to substring matching
    // "pattern_500_test" contains "pattern_5", "pattern_50", and "pattern_500"
    assert!(!m1.is_empty(), "pattern_500_test should match at least pattern_500_*");
    assert!(!m2.is_empty(), "pattern_999_data should match at least pattern_999_*");
    assert!(m3.is_empty(), "nomatch should not match anything");
    
    // Verify it includes the expected primary matches
    assert!(m1.contains(&500), "should match pattern_500_*");
    assert!(m2.contains(&999), "should match pattern_999_*");
}

#[test]
fn test_combined_literal_and_glob_patterns() {
    // Mix of literal strings and glob patterns
    let patterns = vec!["hello", "*.txt", "test_*"];
    let mut pg = Paraglob::build_from_patterns(&patterns, MatchMode::CaseSensitive).unwrap();
    
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
    let mut pg = Paraglob::build_from_patterns(&patterns, MatchMode::CaseSensitive).unwrap();
    
    let m1 = pg.find_all("test");
    let m2 = pg.find_all("a");
    let m3 = pg.find_all("");
    
    // "*" and "**" should match everything
    assert!(m1.len() >= 2, "test should match * and **");
    assert!(m2.len() >= 3, "single char should match *, ?, and **");
    
    // Empty string should only match "*" and "**", not "?"
    assert!(m3.len() >= 2, "empty string should match * and **");
}
