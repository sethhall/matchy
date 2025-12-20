//! Benchmark for AC root node optimization
//!
//! This benchmark specifically measures the performance of AC automaton
//! root node lookups, which is the hot path for non-matching text.
//!
//! Run with: cargo bench -p matchy-paraglob --bench ac_root_bench

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use matchy_match_mode::MatchMode;
use matchy_paraglob::Paraglob;
use std::hint::black_box;

/// Generate realistic domain patterns (like threat intel feeds)
fn generate_domain_patterns(count: usize) -> Vec<String> {
    (0..count)
        .map(|i| match i % 5 {
            0 => format!("evil{i}.com"),
            1 => format!("*.malware{i}.org"),
            2 => format!("bad{i}.example.net"),
            3 => format!("threat{i}.io"),
            _ => format!("*.suspicious{i}.biz"),
        })
        .collect()
}

/// Generate text that does NOT match any patterns (worst case for root)
/// This is realistic: most log lines don't contain threats
fn generate_non_matching_text(size: usize) -> String {
    // Simulate a typical HTTP log line repeated
    let log_line = "192.168.1.100 - - [01/Jan/2024:12:00:00 +0000] \"GET /api/v1/users HTTP/1.1\" 200 1234 \"https://safe-website.com/page\" \"Mozilla/5.0\"\n";
    log_line.repeat(size / log_line.len() + 1)[..size].to_string()
}

/// Generate text with some matches (mixed case)
fn generate_mixed_text(size: usize, pattern_count: usize) -> String {
    let mut text = String::with_capacity(size);
    let mut i = 0;
    while text.len() < size {
        if i % 20 == 0 && pattern_count > 0 {
            // Insert a matching pattern every 20 words
            let idx = i % pattern_count;
            text.push_str(&format!("evil{idx}.com "));
        } else {
            text.push_str("safe-domain.com normal-text ");
        }
        i += 1;
    }
    text.truncate(size);
    text
}

/// Benchmark AC root traversal with non-matching text
/// This is the hot path we're optimizing
fn bench_ac_root_nonmatch(c: &mut Criterion) {
    let mut group = c.benchmark_group("ac_root_nonmatch");

    // Test with different pattern counts
    for pattern_count in [100, 500, 1000, 5000] {
        let patterns = generate_domain_patterns(pattern_count);
        let pattern_refs: Vec<&str> = patterns.iter().map(String::as_str).collect();
        let pg = Paraglob::build_from_patterns(&pattern_refs, MatchMode::CaseInsensitive).unwrap();

        // Test with different text sizes
        for text_size in [1_000, 10_000, 100_000] {
            let text = generate_non_matching_text(text_size);

            group.throughput(Throughput::Bytes(text_size as u64));
            group.bench_with_input(
                BenchmarkId::new(format!("p{pattern_count}_nonmatch"), text_size),
                &text,
                |b, text| {
                    b.iter(|| {
                        let matches = pg.find_all(black_box(text));
                        black_box(matches)
                    });
                },
            );
        }
    }

    group.finish();
}

/// Benchmark AC root with mixed matching/non-matching text
fn bench_ac_root_mixed(c: &mut Criterion) {
    let mut group = c.benchmark_group("ac_root_mixed");

    for pattern_count in [100, 1000] {
        let patterns = generate_domain_patterns(pattern_count);
        let pattern_refs: Vec<&str> = patterns.iter().map(String::as_str).collect();
        let pg = Paraglob::build_from_patterns(&pattern_refs, MatchMode::CaseInsensitive).unwrap();

        for text_size in [10_000, 100_000] {
            let text = generate_mixed_text(text_size, pattern_count);

            group.throughput(Throughput::Bytes(text_size as u64));
            group.bench_with_input(
                BenchmarkId::new(format!("p{pattern_count}_mixed"), text_size),
                &text,
                |b, text| {
                    b.iter(|| {
                        let matches = pg.find_all(black_box(text));
                        black_box(matches)
                    });
                },
            );
        }
    }

    group.finish();
}

/// Benchmark specifically measuring throughput in bytes/second
/// This helps us understand the raw AC scanning speed
fn bench_ac_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("ac_throughput");

    // Use a fixed pattern set
    let patterns = generate_domain_patterns(1000);
    let pattern_refs: Vec<&str> = patterns.iter().map(String::as_str).collect();
    let pg = Paraglob::build_from_patterns(&pattern_refs, MatchMode::CaseInsensitive).unwrap();

    // Large text for accurate throughput measurement
    let text = generate_non_matching_text(1_000_000); // 1MB

    group.throughput(Throughput::Bytes(text.len() as u64));
    group.bench_function("1mb_nonmatch", |b| {
        b.iter(|| {
            let matches = pg.find_all(black_box(&text));
            black_box(matches)
        });
    });

    let mixed_text = generate_mixed_text(1_000_000, 1000);
    group.throughput(Throughput::Bytes(mixed_text.len() as u64));
    group.bench_function("1mb_mixed", |b| {
        b.iter(|| {
            let matches = pg.find_all(black_box(&mixed_text));
            black_box(matches)
        });
    });

    group.finish();
}

/// Micro-benchmark: measure individual character processing
/// This isolates the AC state machine performance
fn bench_ac_per_char(c: &mut Criterion) {
    let mut group = c.benchmark_group("ac_per_char");

    let patterns = generate_domain_patterns(1000);
    let pattern_refs: Vec<&str> = patterns.iter().map(String::as_str).collect();
    let pg = Paraglob::build_from_patterns(&pattern_refs, MatchMode::CaseInsensitive).unwrap();

    // Small texts to measure per-character overhead
    for size in [100, 500, 1000, 5000] {
        let text = generate_non_matching_text(size);

        group.throughput(Throughput::Elements(size as u64)); // Elements = characters
        group.bench_with_input(BenchmarkId::new("chars", size), &text, |b, text| {
            b.iter(|| {
                let matches = pg.find_all(black_box(text));
                black_box(matches)
            });
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_ac_root_nonmatch,
    bench_ac_root_mixed,
    bench_ac_throughput,
    bench_ac_per_char,
);

criterion_main!(benches);
