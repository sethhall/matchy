#![no_main]
use libfuzzer_sys::fuzz_target;
use matchy::{DatabaseBuilder, MatchMode};
use std::net::IpAddr;

fuzz_target!(|data: &[u8]| {
    // Try to interpret data as IP address string
    if let Ok(s) = std::str::from_utf8(data) {
        // Build a simple database with a few IPs
        let mut builder = DatabaseBuilder::new(MatchMode::CaseSensitive);
        let _ = builder.add_entry("1.2.3.4", std::collections::HashMap::new());
        let _ = builder.add_entry("10.0.0.0/8", std::collections::HashMap::new());
        let _ = builder.add_entry("2001:db8::1", std::collections::HashMap::new());
        let _ = builder.add_entry("192.168.0.0/16", std::collections::HashMap::new());
        
        if let Ok(db_bytes) = builder.build() {
            if let Ok(db) = matchy::Database::from_bytes(db_bytes) {
                // Try to lookup the fuzzed string
                // This tests IP parsing edge cases, malformed IPs, etc.
                let _ = db.lookup(s);
                
                // If it parses as an IP, try that too
                if let Ok(ip) = s.parse::<IpAddr>() {
                    let _ = db.lookup_ip(ip);
                }
            }
        }
    }
});
