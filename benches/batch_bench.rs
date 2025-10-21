use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use matchy::{glob::MatchMode, Paraglob};
use std::hint::black_box;

fn generate_texts(count: usize, size: usize) -> Vec<Vec<u8>> {
    (0..count)
        .map(|i| {
            let mut text = format!("text_{}_", i).into_bytes();
            text.resize(size, b'x');
            text
        })
        .collect()
}

fn bench_batch_vs_single(c: &mut Criterion) {
    let patterns = vec!["test", "hello", "world", "example", "data"];
    let pg = Paraglob::build_from_patterns(&patterns, MatchMode::CaseSensitive).unwrap();

    let mut group = c.benchmark_group("batch_vs_single");

    for text_count in [10, 50, 100].iter() {
        let texts = generate_texts(*text_count, 100);
        let refs: Vec<&[u8]> = texts.iter().map(|t| t.as_slice()).collect();

        group.throughput(Throughput::Elements(*text_count as u64));

        group.bench_with_input(
            BenchmarkId::new("single", text_count),
            &refs,
            |b, texts| {
                b.iter(|| {
                    for text in texts.iter() {
                        black_box(pg.find_matches_with_positions_bytes(text));
                    }
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("batch", text_count),
            &refs,
            |b, texts| {
                b.iter(|| {
                    black_box(pg.match_patterns_batch_with_positions(texts));
                });
            },
        );
    }

    group.finish();
}

fn bench_uniform_small(c: &mut Criterion) {
    let patterns = vec!["test", "hello", "world"];
    let pg = Paraglob::build_from_patterns(&patterns, MatchMode::CaseSensitive).unwrap();

    let texts = generate_texts(1000, 50);
    let refs: Vec<&[u8]> = texts.iter().map(|t| t.as_slice()).collect();

    c.benchmark_group("uniform_small")
        .throughput(Throughput::Elements(1000))
        .bench_function("single", |b| {
            b.iter(|| {
                for text in refs.iter() {
                    black_box(pg.find_matches_with_positions_bytes(text));
                }
            });
        })
        .bench_function("batch", |b| {
            b.iter(|| {
                black_box(pg.match_patterns_batch_with_positions(&refs));
            });
        });
}

fn bench_variable_sizes(c: &mut Criterion) {
    let patterns = vec!["test", "hello", "world", "example"];
    let pg = Paraglob::build_from_patterns(&patterns, MatchMode::CaseSensitive).unwrap();

    // Mix of small and medium texts
    let mut texts = Vec::new();
    texts.extend(generate_texts(25, 50));
    texts.extend(generate_texts(25, 200));
    texts.extend(generate_texts(25, 500));
    texts.extend(generate_texts(25, 1000));

    let refs: Vec<&[u8]> = texts.iter().map(|t| t.as_slice()).collect();

    c.benchmark_group("variable_sizes")
        .throughput(Throughput::Elements(100))
        .bench_function("single", |b| {
            b.iter(|| {
                for text in refs.iter() {
                    black_box(pg.find_matches_with_positions_bytes(text));
                }
            });
        })
        .bench_function("batch", |b| {
            b.iter(|| {
                black_box(pg.match_patterns_batch_with_positions(&refs));
            });
        });
}

criterion_group!(benches, bench_batch_vs_single, bench_uniform_small, bench_variable_sizes);
criterion_main!(benches);
