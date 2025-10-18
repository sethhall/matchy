use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use matchy::extractor::PatternExtractor;
use std::hint::black_box;

// Realistic log lines for benchmarking
fn get_test_lines() -> Vec<Vec<u8>> {
    vec![
        b"2024-01-15 10:32:45 GET /api evil.example.com 192.168.1.1 - malware.badsite.org".to_vec(),
        b"[INFO] Connecting to api.github.com via proxy.corporate.internal".to_vec(),
        b"DNS query for www.google.com from 10.0.0.5 (user@company.com)".to_vec(),
        b"https://www.amazon.com/products?id=123&ref=evil.tracker.net".to_vec(),
        b"Blocked request to phishing-site.example.co.uk from suspicious.domain.xyz".to_vec(),
        b"Email sent to admin@internal-server.company.org via smtp.mail.provider.com".to_vec(),
        "UTF-8 test: example.org and test.com from 192.168.1.100"
            .as_bytes()
            .to_vec(),
        b"Multiple domains: test1.com test2.net test3.org test4.io test5.dev".to_vec(),
    ]
}

// Generate synthetic log lines for scale testing
fn generate_log_lines(count: usize) -> Vec<Vec<u8>> {
    let templates = get_test_lines();
    (0..count)
        .map(|i| templates[i % templates.len()].clone())
        .collect()
}

// Benchmark: Domain extraction from realistic log lines
fn bench_domain_extraction(c: &mut Criterion) {
    let mut group = c.benchmark_group("domain_extraction");

    let extractor = PatternExtractor::new().unwrap();
    let test_lines = get_test_lines();

    // Single line extraction
    group.throughput(Throughput::Bytes(test_lines[0].len() as u64));
    group.bench_function("single_line", |b| {
        b.iter(|| {
            let matches = extractor
                .extract_from_line(black_box(&test_lines[0]))
                .count();
            black_box(matches);
        });
    });

    // Batch extraction (8 lines)
    let total_bytes: usize = test_lines.iter().map(|l| l.len()).sum();
    group.throughput(Throughput::Bytes(total_bytes as u64));
    group.bench_function("batch_8_lines", |b| {
        b.iter(|| {
            let mut total_matches = 0;
            for line in black_box(&test_lines) {
                total_matches += extractor.extract_from_line(line).count();
            }
            black_box(total_matches);
        });
    });

    group.finish();
}

// Benchmark: Extraction throughput at scale
fn bench_extraction_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("extraction_throughput");

    let extractor = PatternExtractor::new().unwrap();

    for count in [100, 1000, 10000].iter() {
        let lines = generate_log_lines(*count);
        let total_bytes: usize = lines.iter().map(|l| l.len()).sum();

        group.throughput(Throughput::Bytes(total_bytes as u64));
        group.bench_with_input(BenchmarkId::from_parameter(count), &lines, |b, lines| {
            b.iter(|| {
                let mut total_matches = 0;
                for line in black_box(lines) {
                    total_matches += extractor.extract_from_line(line).count();
                }
                black_box(total_matches);
            });
        });
    }

    group.finish();
}

// Benchmark: Individual extraction types
fn bench_extraction_types(c: &mut Criterion) {
    let mut group = c.benchmark_group("extraction_types");

    // Domain-only extraction
    let domain_extractor = PatternExtractor::builder()
        .extract_domains(true)
        .extract_emails(false)
        .extract_ipv4(false)
        .extract_ipv6(false)
        .build()
        .unwrap();

    let domain_line = b"Visit example.com and api.github.com for more info";
    group.throughput(Throughput::Bytes(domain_line.len() as u64));
    group.bench_function("domains_only", |b| {
        b.iter(|| {
            let matches = domain_extractor
                .extract_from_line(black_box(domain_line))
                .count();
            black_box(matches);
        });
    });

    // IPv4-only extraction
    let ipv4_extractor = PatternExtractor::builder()
        .extract_domains(false)
        .extract_emails(false)
        .extract_ipv4(true)
        .extract_ipv6(false)
        .build()
        .unwrap();

    let ipv4_line = b"Traffic from 192.168.1.1 to 10.0.0.5 via 172.16.0.10";
    group.throughput(Throughput::Bytes(ipv4_line.len() as u64));
    group.bench_function("ipv4_only", |b| {
        b.iter(|| {
            let matches = ipv4_extractor
                .extract_from_line(black_box(ipv4_line))
                .count();
            black_box(matches);
        });
    });

    // Email-only extraction
    let email_extractor = PatternExtractor::builder()
        .extract_domains(false)
        .extract_emails(true)
        .extract_ipv4(false)
        .extract_ipv6(false)
        .build()
        .unwrap();

    let email_line = b"Contact admin@example.com or support@company.org for help";
    group.throughput(Throughput::Bytes(email_line.len() as u64));
    group.bench_function("emails_only", |b| {
        b.iter(|| {
            let matches = email_extractor
                .extract_from_line(black_box(email_line))
                .count();
            black_box(matches);
        });
    });

    // All extraction types
    let all_extractor = PatternExtractor::new().unwrap();
    let mixed_line = b"[INFO] admin@company.com accessed api.example.com from 192.168.1.100";
    group.throughput(Throughput::Bytes(mixed_line.len() as u64));
    group.bench_function("all_types", |b| {
        b.iter(|| {
            let matches = all_extractor
                .extract_from_line(black_box(mixed_line))
                .count();
            black_box(matches);
        });
    });

    group.finish();
}

// Benchmark: Different line lengths
fn bench_line_lengths(c: &mut Criterion) {
    let mut group = c.benchmark_group("line_lengths");

    let extractor = PatternExtractor::new().unwrap();

    // Short line (~50 bytes)
    let short_line = b"GET /api example.com 200";
    group.throughput(Throughput::Bytes(short_line.len() as u64));
    group.bench_function("short_50b", |b| {
        b.iter(|| {
            let matches = extractor.extract_from_line(black_box(short_line)).count();
            black_box(matches);
        });
    });

    // Medium line (~100 bytes)
    let medium_line =
        b"2024-01-15 10:32:45 GET /api evil.example.com 192.168.1.1 - malware.badsite.org";
    group.throughput(Throughput::Bytes(medium_line.len() as u64));
    group.bench_function("medium_100b", |b| {
        b.iter(|| {
            let matches = extractor.extract_from_line(black_box(medium_line)).count();
            black_box(matches);
        });
    });

    // Long line (~500 bytes with many domains)
    let long_line = format!(
        "Check {} and {} and {} and {} and {} and {} and {} and {}",
        "test1.example.com",
        "test2.github.io",
        "test3.company.org",
        "api.service.net",
        "cdn.provider.com",
        "mail.server.io",
        "web.application.dev",
        "auth.system.co.uk"
    );
    group.throughput(Throughput::Bytes(long_line.len() as u64));
    group.bench_function("long_500b", |b| {
        b.iter(|| {
            let matches = extractor
                .extract_from_line(black_box(long_line.as_bytes()))
                .count();
            black_box(matches);
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_domain_extraction,
    bench_extraction_throughput,
    bench_extraction_types,
    bench_line_lengths,
);
criterion_main!(benches);
