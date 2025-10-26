#![no_main]
use libfuzzer_sys::fuzz_target;
use matchy::{DatabaseBuilder, DataValue, MatchMode};
use std::collections::HashMap;
use std::cell::RefCell;

// Create a realistic threat database once with all pattern types
// Using thread_local! instead of static because Database contains RefCell (not Sync)
thread_local! {
    static THREAT_DB: RefCell<matchy::Database> = RefCell::new({
        let mut builder = DatabaseBuilder::new(MatchMode::CaseInsensitive);
        
        // Sample threat data
        let mut threat_data = HashMap::new();
        threat_data.insert("severity".to_string(), DataValue::String("high".to_string()));
        threat_data.insert("score".to_string(), DataValue::Uint32(95));
        
        let mut low_threat = HashMap::new();
        low_threat.insert("severity".to_string(), DataValue::String("low".to_string()));
        low_threat.insert("score".to_string(), DataValue::Uint32(20));
    
    // IP literals (IPv4 and IPv6)
    builder.add_entry("192.0.2.1", threat_data.clone()).unwrap();
    builder.add_entry("198.51.100.42", threat_data.clone()).unwrap();
    builder.add_entry("2001:db8::1", threat_data.clone()).unwrap();
    builder.add_entry("2001:db8:dead:beef::cafe", threat_data.clone()).unwrap();
    
    // CIDR ranges
    builder.add_entry("10.0.0.0/8", low_threat.clone()).unwrap();
    builder.add_entry("172.16.0.0/12", low_threat.clone()).unwrap();
    builder.add_entry("192.168.0.0/16", low_threat.clone()).unwrap();
    builder.add_entry("203.0.113.0/24", threat_data.clone()).unwrap();
    builder.add_entry("2001:db8::/32", threat_data.clone()).unwrap();
    builder.add_entry("fc00::/7", low_threat.clone()).unwrap();
    
    // String literals
    builder.add_entry("malware.example.com", threat_data.clone()).unwrap();
    builder.add_entry("evil.attacker.net", threat_data.clone()).unwrap();
    builder.add_entry("/etc/passwd", threat_data.clone()).unwrap();
    builder.add_entry("DROP TABLE users", threat_data.clone()).unwrap();
    
    // Glob patterns - wildcards
    builder.add_entry("*.malware.com", threat_data.clone()).unwrap();
    builder.add_entry("phish-*.example.org", threat_data.clone()).unwrap();
    builder.add_entry("*.*.badactor.net", threat_data.clone()).unwrap();
    builder.add_entry("tracker*", low_threat.clone()).unwrap();
    
    // Glob patterns - character classes
    builder.add_entry("admin[0-9].evil.com", threat_data.clone()).unwrap();
    builder.add_entry("test[abc].example.com", low_threat.clone()).unwrap();
    builder.add_entry("[!a-z]*.suspicious.org", threat_data.clone()).unwrap();
    
    // Glob patterns - mixed complexity
    builder.add_entry("*/admin/*", threat_data.clone()).unwrap();
    builder.add_entry("*.php?*", low_threat.clone()).unwrap();
    builder.add_entry("[0-9][0-9][0-9]-*.temp.org", low_threat.clone()).unwrap();
    
    // Edge case patterns
    builder.add_entry("*", low_threat.clone()).unwrap();  // Matches everything
    builder.add_entry("?", low_threat.clone()).unwrap();  // Single char
    builder.add_entry("[[]", low_threat.clone()).unwrap(); // Literal bracket
        
        let db_bytes = builder.build().expect("Failed to build threat database");
        matchy::Database::from_bytes(db_bytes).expect("Failed to load threat database")
    });
}

fuzz_target!(|data: &[u8]| {
    THREAT_DB.with(|db| {
        let db = db.borrow();
        
        // Test 1: Query as UTF-8 string (most common case)
        if let Ok(query) = std::str::from_utf8(data) {
            let _ = db.lookup(query);
        }
        
        // Test 2: Query raw bytes (non-UTF8 handling)
        // This tests that we don't panic on invalid UTF-8
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let query_str = String::from_utf8_lossy(data);
            let _ = db.lookup(&query_str);
        }));
        
        // Test 3: Split input into multiple queries (simulates batch processing)
        if data.len() >= 2 {
            let split_point = data[0] as usize % data.len();
            
            if let Ok(q1) = std::str::from_utf8(&data[..split_point]) {
                let _ = db.lookup(q1);
            }
            
            if let Ok(q2) = std::str::from_utf8(&data[split_point..]) {
                let _ = db.lookup(q2);
            }
        }
        
        // Test 4: Concatenate with known patterns (triggers specific code paths)
        if !data.is_empty() && data.len() < 100 {
            if let Ok(suffix) = std::str::from_utf8(data) {
                // Test glob matching edge cases
                let test_queries = vec![
                    format!("*.{}", suffix),           // Wildcard prefix
                    format!("{}.example.com", suffix), // Domain-like
                    format!("192.168.1.{}", suffix),   // IP-like
                    format!("[{}]", suffix),           // Character class
                    format!("*{}*", suffix),           // Surrounded by wildcards
                ];
                
                for query in test_queries {
                    let _ = db.lookup(&query);
                }
            }
        }
    });
});
