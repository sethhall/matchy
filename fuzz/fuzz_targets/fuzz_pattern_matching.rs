#![no_main]
use libfuzzer_sys::fuzz_target;
use matchy::{DatabaseBuilder, MatchMode};

fuzz_target!(|data: &[u8]| {
    // Split input into patterns and query
    if data.len() < 2 {
        return;
    }
    
    let split_point = (data[0] as usize).min(data.len() - 1);
    let pattern_data = &data[1..split_point];
    let query_data = &data[split_point..];
    
    // Try to extract patterns from first part
    if let Ok(pattern_str) = std::str::from_utf8(pattern_data) {
        let mut builder = DatabaseBuilder::new(MatchMode::CaseSensitive);
        
        // Add patterns (ignore errors - malformed patterns are fine)
        for pattern in pattern_str.split('\0').filter(|s| !s.is_empty()) {
            let _ = builder.add_entry(pattern, std::collections::HashMap::new());
        }
        
        // Try to build database
        if let Ok(db_bytes) = builder.build() {
            // Try to load it
            if let Ok(db) = matchy::Database::from_bytes(db_bytes) {
                // Try to query with second part (both valid and invalid UTF-8)
                if let Ok(query_str) = std::str::from_utf8(query_data) {
                    let _ = db.lookup(query_str);
                }
            }
        }
    }
});
