#![no_main]
use libfuzzer_sys::fuzz_target;
use matchy::{DataValue, Database, DatabaseBuilder, MatchMode};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

thread_local! {
    /// A deterministic, well-formed mixed database gives libFuzzer a path into
    /// query-time structures even on a fresh checkout with an empty corpus.
    static VALID_MIXED_DATABASE: Vec<u8> = {
        let mut builder = DatabaseBuilder::new(MatchMode::CaseSensitive);
        let mut metadata = HashMap::new();
        metadata.insert("source".to_string(), DataValue::String("fuzz-seed".to_string()));

        builder
            .add_entry("192.0.2.0/24", metadata.clone())
            .expect("valid IP seed");
        builder
            .add_entry("literal.example", metadata.clone())
            .expect("valid literal seed");
        builder
            .add_entry("*.malware.test", metadata)
            .expect("valid glob seed");
        builder.build().expect("valid mixed database seed")
    };
}

fn exercise_database(bytes: Vec<u8>, query_bytes: &[u8]) {
    // Loading and querying arbitrary bytes must never panic or access memory
    // outside the supplied database. Disable caching so every call reaches the
    // underlying index rather than reusing the result of an earlier query.
    let Ok(db) = Database::from_bytes_builder(bytes).no_cache().open() else {
        return;
    };

    // Exercise each database/index shape with values that reach the IP,
    // literal, and Paraglob lookup paths. Errors are valid fuzz outcomes;
    // panics are deliberately allowed to propagate to libFuzzer.
    for query in [
        "",
        "a",
        "test",
        "example.com",
        "malware.example.com",
        "literal.example",
        "payload.malware.test",
        "127.0.0.1",
        "192.0.2.1",
        "2001:db8::1",
    ] {
        let _ = db.lookup(query);
        let _ = db.lookup_string(query);

        if let Ok(result) = db.lookup_ref(query) {
            if result.found {
                let _ = db.decode_at_offset(result.data_offset);
            }
        }
    }

    // Let mutations influence the query as well as the serialized database.
    // Bounding this string keeps a large input from producing an avoidable
    // second large allocation in the harness itself.
    let query_bytes = &query_bytes[..query_bytes.len().min(256)];
    let query = String::from_utf8_lossy(query_bytes);
    let _ = db.lookup_string(&query);

    for address in [
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
    ] {
        let _ = db.lookup_ip(address);
    }
}

fuzz_target!(|data: &[u8]| {
    // Preserve raw arbitrary-byte coverage.
    exercise_database(data.to_vec(), data);

    // Also mutate a valid database so fuzzing reaches nested readers instead of
    // spending nearly all iterations in magic/header rejection. Zero-valued
    // mutations leave the seed intact, while other inputs explore near-valid
    // section offsets, counts, and payloads.
    VALID_MIXED_DATABASE.with(|seed| {
        let mut mutated = seed.clone();
        let mutated_len = mutated.len();
        for (index, &value) in data.iter().take(128).enumerate() {
            let position = (index.wrapping_mul(257) ^ usize::from(value)) % mutated_len;
            mutated[position] ^= value;
        }
        exercise_database(mutated, data);
    });
});
