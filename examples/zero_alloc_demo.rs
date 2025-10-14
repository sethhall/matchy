//! Demonstration of zero-allocation query APIs
//!
//! Shows all three query variants and their allocation characteristics.
//!
//! Run with DHAT profiling: cargo run --example zero_alloc_demo
//! The profiling will automatically generate dhat-heap.json for analysis.

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

use matchy::glob::MatchMode;
use matchy::Paraglob;
use std::hint::black_box;

fn main() {
    println!("=== Zero-Allocation Query API Demo ===\n");

    // Build database
    let patterns = vec!["*.com", "*.org", "test*", "*suffix", "literal.exact"];
    let mut pg = Paraglob::build_from_patterns(&patterns, MatchMode::CaseSensitive).unwrap();

    println!("Database built with {} patterns\n", patterns.len());

    // Test queries
    let queries = vec![
        "test.com",
        "example.org",
        "test_file",
        "endsuffix",
        "literal.exact",
        "nomatch",
    ];

    println!("--- API 1: find_all() - Allocates return Vec ---");
    for query in &queries {
        let results = pg.find_all(query);
        println!("  {:20} -> {} matches", query, results.len());
    }

    println!("\n--- API 2: find_all_ref() - ZERO allocation! ---");
    for query in &queries {
        let results = pg.find_all_ref(query);
        println!("  {:20} -> {} matches", query, results.len());
    }

    println!("\n--- API 3: find_all_into() - ZERO allocation (reuses buffer)! ---");
    let mut buffer = Vec::with_capacity(10);
    for query in &queries {
        pg.find_all_into(query, &mut buffer);
        println!("  {:20} -> {} matches", query, buffer.len());
    }

    println!("\n\n=== Running Allocation Benchmark ===\n");
    let _profiler = dhat::Profiler::new_heap();

    // Warmup
    for _ in 0..1000 {
        for query in &queries {
            let _ = pg.find_all_ref(black_box(query));
        }
    }

    // Benchmark zero-allocation API
    println!("Running 100,000 queries with find_all_ref()...");
    for _ in 0..100_000 {
        for query in &queries {
            let results = pg.find_all_ref(black_box(query));
            black_box(results);
        }
    }

    println!("\nIf allocations = 0, we achieved true zero-allocation queries!");
    println!("Profiling data written to dhat-heap.json");
}
