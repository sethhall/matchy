///! Performance test matching the C++ test_performance.cpp benchmark
///!
///! This replicates the exact test from the C++ implementation:
///! - 10K patterns with 10% match rate
///! - 20K queries with 10% containing "test"
///! - Fixed seed for reproducibility
use paraglob_rs::glob::MatchMode;
use paraglob_rs::Paraglob;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use std::time::Instant;

// Generate random string (matching C++ implementation)
fn random_string(length: usize, rng: &mut StdRng) -> String {
    const ALPHANUM: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

    (0..length)
        .map(|_| {
            let idx = rng.gen_range(0..ALPHANUM.len());
            ALPHANUM[idx] as char
        })
        .collect()
}

// Generate patterns with varying complexity (matching C++ implementation)
fn generate_patterns(count: usize, rng: &mut StdRng, match_percentage: i32) -> Vec<String> {
    (0..count)
        .map(|_| {
            let should_match = rng.gen_range(0..100) < match_percentage;

            if should_match {
                match rng.gen_range(0..4) {
                    0 => "*test*".to_string(),
                    1 => format!("*{}*", random_string(3, rng)),
                    2 => format!("test_{}*", random_string(3, rng)),
                    _ => format!("*{}?", random_string(2, rng)),
                }
            } else {
                format!("{}_{}", random_string(10, rng), random_string(5, rng))
            }
        })
        .collect()
}

// Generate query strings (matching C++ implementation)
fn generate_queries(count: usize, rng: &mut StdRng, match_percentage: i32) -> Vec<String> {
    (0..count)
        .map(|_| {
            if rng.gen_range(0..100) < match_percentage {
                format!("something_test_{}", random_string(5, rng))
            } else {
                random_string(15, rng)
            }
        })
        .collect()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Paraglob-RS Performance Benchmark (C++ Comparison) ===\n");

    // Test 1: 10K patterns, 20K queries (matching C++ test_performance_benchmark)
    {
        println!("Performance Benchmark: 10K patterns, 20K queries, 10% match rate");

        // Use fixed seed for reproducibility (matching C++ version)
        let mut rng = StdRng::seed_from_u64(42);

        // Generate patterns
        print!("  Generating 10,000 patterns... ");
        std::io::Write::flush(&mut std::io::stdout())?;
        let patterns = generate_patterns(10000, &mut rng, 10);
        println!("done");

        // Build Paraglob
        print!("  Building Paraglob... ");
        std::io::Write::flush(&mut std::io::stdout())?;
        let build_start = Instant::now();

        let pattern_refs: Vec<&str> = patterns.iter().map(|s| s.as_str()).collect();
        let mut pg = Paraglob::build_from_patterns(&pattern_refs, MatchMode::CaseSensitive)?;

        let build_ms = build_start.elapsed().as_millis();
        println!("done ({} ms)", build_ms);

        // VALIDATION: Build time must be fast (C++: < 500ms)
        const MAX_BUILD_MS: u128 = 500;
        if build_ms > MAX_BUILD_MS {
            println!(
                "  FAIL: Build took {} ms (expected < {} ms)",
                build_ms, MAX_BUILD_MS
            );
            std::process::exit(1);
        }

        // Generate queries
        print!("  Generating 20,000 queries... ");
        std::io::Write::flush(&mut std::io::stdout())?;
        let queries = generate_queries(20000, &mut rng, 10);
        println!("done");

        // Run queries and measure time
        print!("  Running 20,000 queries... ");
        std::io::Write::flush(&mut std::io::stdout())?;
        let query_start = Instant::now();

        let mut total_matches = 0;
        for query in &queries {
            let matches = pg.find_all(query);
            total_matches += matches.len();
        }

        let query_ms = query_start.elapsed().as_millis();

        println!("done ({} ms)", query_ms);
        println!("  Total matches: {}", total_matches);

        let queries_per_second = (20000.0 / query_ms as f64 * 1000.0) as i32;
        println!("  Queries per second: {}", queries_per_second);

        // CRITICAL VALIDATION 1: Total time must be reasonable (C++: < 3000ms)
        const MAX_TIME_MS: u128 = 3000;
        if query_ms > MAX_TIME_MS {
            println!(
                "  FAIL: Queries took {} ms (expected < {} ms)",
                query_ms, MAX_TIME_MS
            );
            println!("        Performance has regressed!");
            std::process::exit(1);
        }

        // CRITICAL VALIDATION 2: Minimum throughput requirement (C++: >= 100K qps)
        const MIN_QPS: i32 = 100000;
        if queries_per_second < MIN_QPS {
            println!(
                "  FAIL: Query throughput too low: {} qps",
                queries_per_second
            );
            println!("        Expected: >= {} qps", MIN_QPS);
            println!("        Performance has regressed!");
            std::process::exit(1);
        }

        println!("  PASS: Performance acceptable");
        println!(
            "        - Time: {} ms (limit: {} ms)",
            query_ms, MAX_TIME_MS
        );
        println!(
            "        - Throughput: {} qps (min: {} qps)",
            queries_per_second, MIN_QPS
        );
    }

    // Test 2: 50K patterns, 10K queries (matching C++ test_large_pattern_set_performance)
    println!("\nLarge Pattern Set: 50K patterns");
    {
        let mut rng = StdRng::seed_from_u64(123);

        print!("  Generating patterns... ");
        std::io::Write::flush(&mut std::io::stdout())?;
        let patterns = generate_patterns(50000, &mut rng, 5);
        println!("done");

        print!("  Building Paraglob... ");
        std::io::Write::flush(&mut std::io::stdout())?;
        let build_start = Instant::now();

        let pattern_refs: Vec<&str> = patterns.iter().map(|s| s.as_str()).collect();
        let mut pg = Paraglob::build_from_patterns(&pattern_refs, MatchMode::CaseSensitive)?;

        let build_ms = build_start.elapsed().as_millis();
        println!("done ({} ms)", build_ms);

        // VALIDATION: Large dataset build time (C++: < 3000ms)
        const MAX_LARGE_BUILD_MS: u128 = 3000;
        if build_ms > MAX_LARGE_BUILD_MS {
            println!(
                "  FAIL: Build took {} ms (expected < {} ms)",
                build_ms, MAX_LARGE_BUILD_MS
            );
            std::process::exit(1);
        }

        // Run performance queries
        print!("  Generating 10,000 queries... ");
        std::io::Write::flush(&mut std::io::stdout())?;
        let test_queries = generate_queries(10000, &mut rng, 5);
        println!("done");

        print!("  Running 10,000 queries... ");
        std::io::Write::flush(&mut std::io::stdout())?;
        let query_start = Instant::now();

        let mut total_matches = 0;
        for query in &test_queries {
            let matches = pg.find_all(query);
            total_matches += matches.len();
        }

        let query_ms = query_start.elapsed().as_millis();

        println!("done ({} ms)", query_ms);
        println!("  Total matches: {}", total_matches);

        let queries_per_second = (10000.0 / query_ms as f64 * 1000.0) as i32;
        println!("  Queries per second: {}", queries_per_second);

        // VALIDATION: Maintain high performance even with 50K patterns (C++: >= 100K qps)
        const MIN_QPS_LARGE: i32 = 100000;
        if queries_per_second < MIN_QPS_LARGE {
            println!(
                "  FAIL: Query throughput too low: {} qps",
                queries_per_second
            );
            println!("        Expected: >= {} qps", MIN_QPS_LARGE);
            std::process::exit(1);
        }

        println!("  PASS: Large pattern set performance acceptable");
        println!(
            "        - Throughput: {} qps (min: {} qps)",
            queries_per_second, MIN_QPS_LARGE
        );
    }

    println!("\n=== Results ===");
    println!("All tests passed! 🎉");
    println!("\nRust implementation meets or exceeds C++ performance requirements!");

    Ok(())
}
