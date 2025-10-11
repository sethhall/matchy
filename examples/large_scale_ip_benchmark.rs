//! Large-scale IP address database benchmark
//!
//! This example generates a massive number of unique IP addresses and inserts them
//! into a matchy MMDB database using the IP tree structure (like MaxMind).
//! Then benchmarks both database creation and query performance.
//!
//! Target: 1.5 billion IP addresses in the database
//! This tests the scalability of the IP trie structure.

use matchy::database::Database;
use matchy::glob::MatchMode;
use matchy::mmdb_builder::MmdbBuilder;
use memory_stats::memory_stats;
use std::collections::HashMap;
use std::time::Instant;

fn format_bytes(bytes: usize) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.2} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.2} MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.2} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

fn format_number(n: usize) -> String {
    let s = n.to_string();
    let mut result = String::new();
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.push(',');
        }
        result.push(c);
    }
    result.chars().rev().collect()
}

fn format_qps(qps: f64) -> String {
    if qps >= 1_000_000.0 {
        format!("{:.2}M", qps / 1_000_000.0)
    } else if qps >= 1_000.0 {
        format!("{:.2}K", qps / 1_000.0)
    } else {
        format!("{:.2}", qps)
    }
}

fn get_memory_usage() -> Option<(usize, usize)> {
    memory_stats().map(|usage| (usage.physical_mem, usage.virtual_mem))
}

fn print_memory_usage(label: &str) {
    if let Some((physical, virtual_mem)) = get_memory_usage() {
        println!(
            "  [Memory] {}: Physical={}, Virtual={}",
            label,
            format_bytes(physical),
            format_bytes(virtual_mem)
        );
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Matchy Large-Scale IP Database Benchmark ===\n");

    // Parse command line argument for IP count
    let args: Vec<String> = std::env::args().collect();
    let ip_count = if args.len() > 1 {
        args[1].parse::<usize>().unwrap_or(1_000_000)
    } else {
        1_000_000 // Default to 1M for reasonable test
    };

    let max_ipv4 = 4_294_967_296u64;

    println!("Configuration:");
    println!("  IP addresses to insert: {}", format_number(ip_count));
    println!("  IP generation: Sequential (0.0.0.0 onwards)");
    println!("  Data payload: Empty (minimal overhead)");
    println!(
        "  Max IPv4 space: {} (2^32)",
        format_number(max_ipv4 as usize)
    );

    if ip_count as u64 > max_ipv4 {
        println!("  WARNING: Count exceeds IPv4 space - will wrap around");
    }
    println!();

    // === Phase 1: Build Database ===
    println!("--- Phase 1: Database Construction ---");
    print_memory_usage("Before build");
    println!(
        "Building database with {} IP addresses...",
        format_number(ip_count)
    );

    let build_start = Instant::now();
    let mut builder = MmdbBuilder::new(MatchMode::CaseSensitive)
        .with_database_type("Large-Scale-IP-Test")
        .with_description("en", "Large scale IP database benchmark");

    // Empty data payload (minimal)
    let empty_data = HashMap::new();

    // Insert IPs with progress tracking
    for i in 0..ip_count {
        // Generate sequential unique IP
        let ip_num = i as u32;
        let octet1 = (ip_num >> 24) & 0xFF;
        let octet2 = (ip_num >> 16) & 0xFF;
        let octet3 = (ip_num >> 8) & 0xFF;
        let octet4 = ip_num & 0xFF;
        let ip_str = format!("{}.{}.{}.{}", octet1, octet2, octet3, octet4);

        // Insert with empty payload
        builder.add_ip(&ip_str, empty_data.clone())?;

        // Progress indicator
        if ip_count > 100_000 && (i + 1) % 1_000_000 == 0 {
            let elapsed = build_start.elapsed();
            let rate = (i + 1) as f64 / elapsed.as_secs_f64();
            let remaining = (ip_count - i - 1) as f64 / rate;

            println!(
                "  Progress: {}/{} ({:.1}%) - {} IPs/sec - est. {:.0}s remaining",
                format_number(i + 1),
                format_number(ip_count),
                (i + 1) as f64 / ip_count as f64 * 100.0,
                format_qps(rate),
                remaining
            );
        }
    }

    println!("  Finalizing database...");
    print_memory_usage("Peak build memory");
    let db_bytes = builder.build()?;
    print_memory_usage("After finalization");
    let build_time = build_start.elapsed();

    let ips_per_sec = ip_count as f64 / build_time.as_secs_f64();
    let bytes_per_ip = db_bytes.len() as f64 / ip_count as f64;

    println!("✓ Build complete!");
    println!("  Build time: {:.2}s", build_time.as_secs_f64());
    println!("  Build rate: {} IPs/sec", format_qps(ips_per_sec));
    println!("  Database size: {}", format_bytes(db_bytes.len()));
    println!("  Bytes per IP: {:.2}", bytes_per_ip);
    print_memory_usage("After build complete");
    println!();

    // === Phase 2: Save to Disk ===
    println!("--- Phase 2: Save to Disk ---");
    let temp_file = "/tmp/matchy_large_scale_ip.mmdb";

    let save_start = Instant::now();
    std::fs::write(temp_file, &db_bytes)?;
    let save_time = save_start.elapsed();

    let db_size = db_bytes.len();
    let write_speed_mbps = (db_size as f64 / (1024.0 * 1024.0)) / save_time.as_secs_f64();

    // Drop db_bytes to free memory
    drop(db_bytes);
    print_memory_usage("After save (db_bytes dropped)");

    println!("  Save time: {:.2}s", save_time.as_secs_f64());
    println!("  Write speed: {:.2} MB/s", write_speed_mbps);
    println!();

    // === Phase 3: Load Database ===
    println!("--- Phase 3: Load Database (mmap) ---");

    // Measure load time multiple times
    let mut load_times = Vec::new();
    for i in 1..=3 {
        let load_start = Instant::now();
        let _db = Database::open(temp_file)?;
        let load_time = load_start.elapsed();
        load_times.push(load_time);

        println!(
            "  Load #{}: {:.3}ms ({} IPs ready)",
            i,
            load_time.as_micros() as f64 / 1000.0,
            format_number(ip_count)
        );
    }

    let avg_load_time: std::time::Duration =
        load_times.iter().sum::<std::time::Duration>() / load_times.len() as u32;

    println!(
        "  Average load time: {:.3}ms",
        avg_load_time.as_micros() as f64 / 1000.0
    );
    println!();

    // === Phase 4: Query Performance ===
    println!("--- Phase 4: Query Performance ---");

    let db = Database::open(temp_file)?;

    // Calculate the last IP we inserted
    let last_ip_num = (ip_count - 1) as u32;
    let last_octet1 = (last_ip_num >> 24) & 0xFF;
    let last_octet2 = (last_ip_num >> 16) & 0xFF;
    let last_octet3 = (last_ip_num >> 8) & 0xFF;
    let last_octet4 = last_ip_num & 0xFF;

    // Build test IPs as owned Strings
    let mut test_ips: Vec<(String, bool)> = vec![
        // SHOULD MATCH (in our range)
        ("0.0.0.0".to_string(), true), // First IP
        ("0.0.0.1".to_string(), true), // Second IP
        ("0.0.1.0".to_string(), true), // Early IP
        (
            format!(
                "{}.{}.{}.{}",
                last_octet1, last_octet2, last_octet3, last_octet4
            ),
            true,
        ), // Last IP
    ];

    // Add IPs that are BEYOND our range (should NOT match)
    if ip_count < 4_294_967_296 {
        // Add IPs beyond our inserted range
        for offset in [1, 100, 1000, 10000] {
            let beyond_ip_num = (ip_count as u64 + offset) as u32;
            let b_octet1 = (beyond_ip_num >> 24) & 0xFF;
            let b_octet2 = (beyond_ip_num >> 16) & 0xFF;
            let b_octet3 = (beyond_ip_num >> 8) & 0xFF;
            let b_octet4 = beyond_ip_num & 0xFF;
            test_ips.push((
                format!("{}.{}.{}.{}", b_octet1, b_octet2, b_octet3, b_octet4),
                false,
            ));
        }
    }

    // Add some obviously out of range IPs
    test_ips.push(("255.255.255.255".to_string(), ip_count >= 4_294_967_296)); // Last possible IPv4
    test_ips.push(("255.255.255.254".to_string(), ip_count >= 4_294_967_295));
    test_ips.push(("255.0.0.0".to_string(), (255 << 24) < ip_count as u32));

    println!("  Testing queries against {} IPs:", format_number(ip_count));

    let mut total_query_time = std::time::Duration::ZERO;
    let mut correct_results = 0;
    let mut found_count = 0;
    let mut not_found_count = 0;

    for (ip_str, expected_found) in &test_ips {
        let ip = ip_str.as_str().parse::<std::net::IpAddr>()?;

        let query_start = Instant::now();
        let result = db.lookup_ip(ip)?;
        let query_time = query_start.elapsed();

        total_query_time += query_time;

        let found = match result {
            Some(matchy::database::QueryResult::NotFound) => false,
            Some(_) => true,
            None => false,
        };
        if found {
            found_count += 1;
        } else {
            not_found_count += 1;
        }

        let correct = found == *expected_found;
        if correct {
            correct_results += 1;
        }

        println!(
            "    \"{}\" -> {} in {:.2}µs {}",
            ip_str,
            if found { "FOUND    " } else { "NOT FOUND" },
            query_time.as_nanos() as f64 / 1000.0,
            if correct { "✓" } else { "✗ WRONG!" }
        );
    }

    let avg_query_time = total_query_time / test_ips.len() as u32;
    println!(
        "  Average query time: {:.2}µs",
        avg_query_time.as_nanos() as f64 / 1000.0
    );
    println!(
        "  Results: {}/{} correct ({} found, {} not found)",
        correct_results,
        test_ips.len(),
        found_count,
        not_found_count
    );
    println!();

    // === Phase 5: Batch Query Benchmark ===
    println!("--- Phase 5: Batch Query Benchmark ---");

    let batch_size = 100_000;
    println!("  Running {} queries...", format_number(batch_size));

    let batch_start = Instant::now();
    let mut batch_found = 0;

    for i in 0..batch_size {
        // Query random IPs from our range
        let ip_num = ((i * 43) % ip_count) as u32; // Pseudo-random within range
        let octet1 = (ip_num >> 24) & 0xFF;
        let octet2 = (ip_num >> 16) & 0xFF;
        let octet3 = (ip_num >> 8) & 0xFF;
        let octet4 = ip_num & 0xFF;

        let ip = std::net::Ipv4Addr::new(octet1 as u8, octet2 as u8, octet3 as u8, octet4 as u8);

        let result = db.lookup_ip(std::net::IpAddr::V4(ip))?;
        if matches!(result, Some(matchy::database::QueryResult::Ip { .. })) {
            batch_found += 1;
        }
    }

    let batch_time = batch_start.elapsed();
    let queries_per_sec = batch_size as f64 / batch_time.as_secs_f64();
    let avg_batch_query = batch_time / batch_size as u32;

    println!("  Batch time: {:.2}s", batch_time.as_secs_f64());
    println!("  Query rate: {} queries/sec", format_qps(queries_per_sec));
    println!(
        "  Average query time: {:.2}µs",
        avg_batch_query.as_nanos() as f64 / 1000.0
    );
    println!(
        "  Found: {}/{}",
        format_number(batch_found),
        format_number(batch_size)
    );
    println!();

    // === Summary ===
    println!("=== Summary ===");
    println!(
        "  ✓ Inserted {} IP addresses in {:.2}s",
        format_number(ip_count),
        build_time.as_secs_f64()
    );
    println!(
        "  ✓ Database size: {} ({:.2} bytes/IP)",
        format_bytes(db_size),
        bytes_per_ip
    );
    println!(
        "  ✓ Load time: {:.3}ms (zero-copy mmap)",
        avg_load_time.as_micros() as f64 / 1000.0
    );
    println!(
        "  ✓ Query time: {:.2}µs average ({} queries/sec)",
        avg_batch_query.as_nanos() as f64 / 1000.0,
        format_qps(queries_per_sec)
    );
    println!();

    println!("To test with different sizes:");
    println!("  10M:   cargo run --release --example large_scale_ip_benchmark 10000000");
    println!("  100M:  cargo run --release --example large_scale_ip_benchmark 100000000");
    println!("  1B:    cargo run --release --example large_scale_ip_benchmark 1000000000");
    println!("  1.5B:  cargo run --release --example large_scale_ip_benchmark 1500000000");

    // Clean up
    std::fs::remove_file(temp_file)?;

    Ok(())
}
