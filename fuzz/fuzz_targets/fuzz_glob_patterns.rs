#![no_main]
use libfuzzer_sys::fuzz_target;
use matchy::{DatabaseBuilder, MatchMode};

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    
    // Use first byte to select case sensitivity
    let mode = if data[0] & 1 == 0 {
        MatchMode::CaseSensitive
    } else {
        MatchMode::CaseInsensitive
    };
    
    // Try to interpret rest as UTF-8
    if let Ok(s) = std::str::from_utf8(&data[1..]) {
        let mut builder = DatabaseBuilder::new(mode);
        
        // Try to use the fuzzed string as a glob pattern
        // This tests edge cases like:
        // - Multiple wildcards: ****
        // - Empty character classes: []
        // - Unclosed character classes: [a-z
        // - Negated empty classes: [!]
        // - Escaped characters at end: \
        // - Very long patterns
        let _ = builder.add_entry(s, std::collections::HashMap::new());
        
        // The fuzzer is allowed to skip pathological inputs that hit resource limits.
        // In production, the build() call will return an error that the caller must handle.
        match builder.build() {
            Ok(db_bytes) => {
                if let Ok(db) = matchy::Database::from_bytes(db_bytes) {
                    // Try to query against itself
                    let _ = db.lookup(s);
                    
                    // Try some test strings
                    let _ = db.lookup("test");
                    let _ = db.lookup("a.b.c.d.e");
                    let _ = db.lookup("");
                }
            }
            Err(_e) => {
                // ResourceLimitExceeded or other errors are acceptable in fuzzing.
                // The important thing is we don't panic or OOM.
                return;
            }
        }
    }
});
