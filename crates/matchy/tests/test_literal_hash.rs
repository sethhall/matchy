use matchy::{DataValue, Database, DatabaseBuilder, MatchMode, QueryResult};
use std::collections::HashMap;
use tempfile::NamedTempFile;

fn make_type_map<S: Into<String>>(type_value: S) -> HashMap<String, DataValue> {
    let mut map = HashMap::new();
    map.insert("type".to_string(), DataValue::String(type_value.into()));
    map
}

fn lookup_expect_result(db: &Database, key: &str) -> QueryResult {
    db.lookup(key)
        .unwrap_or_else(|e| panic!("lookup failed for '{}': {}", key, e))
        .unwrap_or_else(|| panic!("no result for lookup '{}'", key))
}

fn assert_pattern_with_type(result: QueryResult, expected_type: &str) {
    match result {
        QueryResult::Pattern {
            pattern_ids, data, ..
        } => {
            assert_eq!(pattern_ids.len(), 1);
            assert!(!data.is_empty());
            if let Some(DataValue::Map(map)) = &data[0] {
                assert_eq!(
                    map.get("type"),
                    Some(&DataValue::String(expected_type.to_string()))
                );
            }
        }
        _ => panic!("Expected Pattern result"),
    }
}

#[test]
fn test_literal_exact_match() {
    // Build database with literals
    let mut builder = DatabaseBuilder::new(MatchMode::CaseSensitive);

    let mut data = HashMap::new();
    data.insert("type".to_string(), DataValue::String("malware".to_string()));
    data.insert(
        "severity".to_string(),
        DataValue::String("high".to_string()),
    );

    builder.add_literal("evil.com", data.clone()).unwrap();
    builder.add_literal("bad.org", data.clone()).unwrap();
    builder.add_literal("threat.net", data).unwrap();

    // Build and save
    let db_bytes = builder.build().unwrap();
    let mut tmpfile = NamedTempFile::new().unwrap();
    std::io::Write::write_all(&mut tmpfile, &db_bytes).unwrap();

    // Load and test
    let db = Database::from(tmpfile.path().to_str().unwrap())
        .open()
        .unwrap();

    // Test exact match
    let result = lookup_expect_result(&db, "evil.com");
    assert_pattern_with_type(result, "malware");

    // Test no match
    let result = lookup_expect_result(&db, "notfound.com");
    assert!(matches!(result, QueryResult::NotFound));
}

#[test]
fn test_literal_and_glob_both_match() {
    // Build database with BOTH a literal and a glob that match the same query
    let mut builder = DatabaseBuilder::new(MatchMode::CaseSensitive);

    let mut literal_data = HashMap::new();
    literal_data.insert(
        "source".to_string(),
        DataValue::String("literal".to_string()),
    );
    literal_data.insert(
        "severity".to_string(),
        DataValue::String("high".to_string()),
    );

    let mut glob_data = HashMap::new();
    glob_data.insert("source".to_string(), DataValue::String("glob".to_string()));
    glob_data.insert(
        "severity".to_string(),
        DataValue::String("medium".to_string()),
    );

    // Add literal
    builder.add_literal("evil.com", literal_data).unwrap();

    // Add glob that also matches
    builder.add_glob("*.com", glob_data).unwrap();

    // Build and save
    let db_bytes = builder.build().unwrap();
    let mut tmpfile = NamedTempFile::new().unwrap();
    std::io::Write::write_all(&mut tmpfile, &db_bytes).unwrap();

    // Load and test
    let db = Database::from(tmpfile.path().to_str().unwrap())
        .open()
        .unwrap();

    // Query should match BOTH the literal AND the glob
    let result = lookup_expect_result(&db, "evil.com");
    match result {
        QueryResult::Pattern {
            pattern_ids, data, ..
        } => {
            // Should have 2 matches: one from literal, one from glob
            assert_eq!(pattern_ids.len(), 2, "Should match both literal and glob");

            // Verify we got data from both sources
            let sources: Vec<String> = data
                .iter()
                .filter_map(|d| {
                    if let Some(DataValue::Map(map)) = d {
                        if let Some(DataValue::String(s)) = map.get("source") {
                            return Some(s.clone());
                        }
                    }
                    None
                })
                .collect();

            assert!(sources.contains(&"literal".to_string()));
            assert!(sources.contains(&"glob".to_string()));
        }
        _ => panic!("Expected Pattern result"),
    }
}

#[test]
fn test_glob_only_match() {
    // Build database with only globs
    let mut builder = DatabaseBuilder::new(MatchMode::CaseSensitive);

    let data = make_type_map("phishing");

    builder.add_glob("*.phishing.com", data.clone()).unwrap();
    builder.add_glob("bad-*", data).unwrap();

    // Build and save
    let db_bytes = builder.build().unwrap();
    let mut tmpfile = NamedTempFile::new().unwrap();
    std::io::Write::write_all(&mut tmpfile, &db_bytes).unwrap();

    // Load and test
    let db = Database::from(tmpfile.path().to_str().unwrap())
        .open()
        .unwrap();

    // Test glob match
    let result = lookup_expect_result(&db, "test.phishing.com");
    match result {
        QueryResult::Pattern { pattern_ids, .. } => {
            assert_eq!(pattern_ids.len(), 1);
        }
        _ => panic!("Expected Pattern result"),
    }

    // Test another glob match
    let result = lookup_expect_result(&db, "bad-actor");
    match result {
        QueryResult::Pattern { pattern_ids, .. } => {
            assert_eq!(pattern_ids.len(), 1);
        }
        _ => panic!("Expected Pattern result"),
    }
}

#[test]
fn test_mixed_ip_literal_glob() {
    // Build database with IPs, literals, and globs
    let mut builder = DatabaseBuilder::new(MatchMode::CaseSensitive);

    let ip_data = make_type_map("ip_threat");
    let literal_data = make_type_map("domain_threat");
    let glob_data = make_type_map("pattern_threat");

    builder.add_ip("1.2.3.4", ip_data).unwrap();
    builder.add_literal("evil.com", literal_data).unwrap();
    builder.add_glob("*.bad.com", glob_data).unwrap();

    // Build and save
    let db_bytes = builder.build().unwrap();
    let mut tmpfile = NamedTempFile::new().unwrap();
    std::io::Write::write_all(&mut tmpfile, &db_bytes).unwrap();

    // Load and test
    let db = Database::from(tmpfile.path().to_str().unwrap())
        .open()
        .unwrap();

    // Test IP lookup
    let result = lookup_expect_result(&db, "1.2.3.4");
    assert!(matches!(result, QueryResult::Ip { .. }));

    // Test literal lookup
    let result = lookup_expect_result(&db, "evil.com");
    match result {
        QueryResult::Pattern { pattern_ids, .. } => {
            assert_eq!(pattern_ids.len(), 1);
        }
        _ => panic!("Expected Pattern result"),
    }

    // Test glob lookup
    let result = lookup_expect_result(&db, "test.bad.com");
    match result {
        QueryResult::Pattern { pattern_ids, .. } => {
            assert_eq!(pattern_ids.len(), 1);
        }
        _ => panic!("Expected Pattern result"),
    }
}

#[test]
fn test_literal_with_special_chars() {
    // Test that literals with glob-like characters work correctly
    let mut builder = DatabaseBuilder::new(MatchMode::CaseSensitive);

    let mut data = HashMap::new();
    data.insert(
        "note".to_string(),
        DataValue::String("has brackets".to_string()),
    );

    // These contain glob characters but should be treated as literals
    builder.add_literal("file[1].txt", data.clone()).unwrap();
    builder.add_literal("what?.com", data.clone()).unwrap();
    builder.add_literal("price*list", data).unwrap();

    // Build and save
    let db_bytes = builder.build().unwrap();
    let mut tmpfile = NamedTempFile::new().unwrap();
    std::io::Write::write_all(&mut tmpfile, &db_bytes).unwrap();

    // Load and test
    let db = Database::from(tmpfile.path().to_str().unwrap())
        .open()
        .unwrap();

    // These should match exactly
    assert!(matches!(
        lookup_expect_result(&db, "file[1].txt"),
        QueryResult::Pattern { .. }
    ));
    assert!(matches!(
        lookup_expect_result(&db, "what?.com"),
        QueryResult::Pattern { .. }
    ));
    assert!(matches!(
        lookup_expect_result(&db, "price*list"),
        QueryResult::Pattern { .. }
    ));

    // These should NOT match (they're not the exact string)
    assert!(matches!(
        lookup_expect_result(&db, "file2.txt"),
        QueryResult::NotFound
    ));
}

#[test]
fn test_builder_stats() {
    let mut builder = DatabaseBuilder::new(MatchMode::CaseSensitive);

    let data = HashMap::new();
    builder.add_ip("1.2.3.4", data.clone()).unwrap();
    builder.add_literal("evil.com", data.clone()).unwrap();
    builder.add_literal("bad.org", data.clone()).unwrap();
    builder.add_glob("*.phishing.com", data).unwrap();

    let stats = builder.stats();
    assert_eq!(stats.total_entries, 4);
    assert_eq!(stats.ip_entries, 1);
    assert_eq!(stats.literal_entries, 2);
    assert_eq!(stats.glob_entries, 1);
}
