//! Example: Incremental Builder with Associated Data
//!
//! This example demonstrates how to use the ParaglobBuilder to incrementally
//! add patterns with associated data, useful for building threat intelligence
//! databases or any pattern-matching system that needs to attach metadata.

use paraglob_rs::data_section::DataValue;
use paraglob_rs::glob::MatchMode;
use paraglob_rs::ParaglobBuilder;
use std::collections::HashMap;

fn main() {
    println!("=== Incremental Paraglob Builder Example ===\n");

    // Create a new builder
    let mut builder = ParaglobBuilder::new(MatchMode::CaseInsensitive);

    println!("Adding patterns incrementally...\n");

    // Add simple patterns without data
    let file_id = builder.add_pattern("*.txt").unwrap();
    println!("Added pattern '*.txt' with ID: {}", file_id);

    let test_id = builder.add_pattern("test_*").unwrap();
    println!("Added pattern 'test_*' with ID: {}", test_id);

    // Build threat intelligence data for malicious domains
    let mut phishing_data = HashMap::new();
    phishing_data.insert(
        "threat_type".to_string(),
        DataValue::String("phishing".to_string()),
    );
    phishing_data.insert(
        "threat_level".to_string(),
        DataValue::String("high".to_string()),
    );
    phishing_data.insert("confidence".to_string(), DataValue::Float(0.95));
    phishing_data.insert("first_seen".to_string(), DataValue::Uint64(1704067200));
    phishing_data.insert(
        "tags".to_string(),
        DataValue::Array(vec![
            DataValue::String("credential-theft".to_string()),
            DataValue::String("banking".to_string()),
        ]),
    );

    let phishing_id = builder
        .add_pattern_with_data("*.phishing.com", Some(DataValue::Map(phishing_data)))
        .unwrap();
    println!("Added pattern '*.phishing.com' with threat data, ID: {}", phishing_id);

    // Build malware data
    let mut malware_data = HashMap::new();
    malware_data.insert(
        "threat_type".to_string(),
        DataValue::String("malware".to_string()),
    );
    malware_data.insert(
        "threat_level".to_string(),
        DataValue::String("critical".to_string()),
    );
    malware_data.insert("confidence".to_string(), DataValue::Float(0.99));
    malware_data.insert("first_seen".to_string(), DataValue::Uint64(1701388800));
    malware_data.insert(
        "tags".to_string(),
        DataValue::Array(vec![
            DataValue::String("ransomware".to_string()),
            DataValue::String("trojan".to_string()),
        ]),
    );

    let malware_id = builder
        .add_pattern_with_data("malware-*", Some(DataValue::Map(malware_data)))
        .unwrap();
    println!("Added pattern 'malware-*' with threat data, ID: {}", malware_id);

    // Check builder state
    println!("\n--- Builder State ---");
    println!("Total patterns: {}", builder.pattern_count());
    println!("Contains '*.txt': {}", builder.contains_pattern("*.txt"));
    println!(
        "Contains 'nonexistent': {}",
        builder.contains_pattern("nonexistent")
    );

    // Build the final matcher
    println!("\nBuilding final Paraglob matcher...");
    let mut pg = builder.build().unwrap();

    println!("✓ Matcher built successfully!");
    println!("  Format: v{}", if pg.has_data_section() { "2 (with data)" } else { "1 (patterns only)" });

    // Test matching
    println!("\n=== Testing Pattern Matching ===\n");

    let test_cases = vec![
        "test_file.txt",
        "document.txt",
        "login.phishing.com",
        "malware-dropper.exe",
        "normal-site.com",
    ];

    for query in test_cases {
        println!("Query: \"{}\"", query);
        let matches = pg.find_all(query);

        if matches.is_empty() {
            println!("  → No matches");
        } else {
            println!("  → Matched {} pattern(s):", matches.len());
            for &pattern_id in &matches {
                // Try to get associated data
                if let Some(data) = pg.get_pattern_data(pattern_id) {
                    println!("    Pattern ID {}: has data", pattern_id);
                    if let DataValue::Map(m) = data {
                        if let Some(DataValue::String(threat_type)) = m.get("threat_type") {
                            println!("      Type: {}", threat_type);
                        }
                        if let Some(DataValue::String(level)) = m.get("threat_level") {
                            println!("      Level: {}", level);
                        }
                        if let Some(DataValue::Float(conf)) = m.get("confidence") {
                            println!("      Confidence: {:.0}%", conf * 100.0);
                        }
                        if let Some(DataValue::Array(tags)) = m.get("tags") {
                            print!("      Tags: ");
                            for tag in tags {
                                if let DataValue::String(s) = tag {
                                    print!("[{}] ", s);
                                }
                            }
                            println!();
                        }
                    }
                } else {
                    println!("    Pattern ID {}: no data", pattern_id);
                }
            }
        }
        println!();
    }

    // Demonstrate duplicate pattern handling
    println!("=== Duplicate Pattern Handling ===\n");
    let mut builder2 = ParaglobBuilder::new(MatchMode::CaseSensitive);

    let id1 = builder2.add_pattern("*.txt").unwrap();
    println!("First add of '*.txt': ID {}", id1);

    let id2 = builder2.add_pattern("*.txt").unwrap();
    println!("Second add of '*.txt': ID {}", id2);

    if id1 == id2 {
        println!("✓ Duplicate detection working - same ID returned!");
    }
    println!("Pattern count: {} (deduplicated)", builder2.pattern_count());

    println!("\n=== Example Complete ===");
}
