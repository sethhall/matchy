#![no_main]
use libfuzzer_sys::fuzz_target;
use matchy::{DatabaseBuilder, MatchMode};

fuzz_target!(|data: &[u8]| {
    // Test exact string matching (no wildcards)
    // This fuzzes the literal hash table implementation

    if data.is_empty() {
        return;
    }

    // Split into multiple strings using null bytes
    if let Ok(s) = std::str::from_utf8(data) {
        let mut builder = DatabaseBuilder::new(MatchMode::CaseSensitive);

        let strings: Vec<&str> = s.split('\0').filter(|s| !s.is_empty()).collect();

        // Add each string as an exact literal (no wildcards)
        // These should go into the literal hash table
        for (i, literal) in strings.iter().enumerate() {
            // Skip if it looks like a glob pattern
            if literal.contains('*') || literal.contains('?') || literal.contains('[') {
                continue;
            }

            let mut data = std::collections::HashMap::new();
            let id = u32::try_from(i).unwrap_or(u32::MAX);
            data.insert("id".to_string(), matchy::DataValue::Uint32(id));
            let _ = builder.add_entry(literal, data);
        }

        if let Ok(db_bytes) = builder.build() {
            if let Ok(db) = matchy::Database::from_bytes(db_bytes) {
                // Try to look up each literal
                for literal in &strings {
                    if !literal.contains('*') && !literal.contains('?') && !literal.contains('[') {
                        let _ = db.lookup_string(literal);
                    }
                }

                // Try some non-matching strings
                let _ = db.lookup_string("nonexistent");
                let _ = db.lookup_string("");

                // Try the original fuzzed data as well
                if let Ok(query) = std::str::from_utf8(data) {
                    let _ = db.lookup_string(query);
                }
            }
        }
    }
});
