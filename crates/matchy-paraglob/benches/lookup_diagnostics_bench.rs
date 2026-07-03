use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use matchy_paraglob::{MatchMode, Paraglob};
use std::hint::black_box;

struct LookupCase {
    name: &'static str,
    patterns: Vec<String>,
    query: String,
    mode: MatchMode,
}

fn numbered_patterns(count: usize, mut make_pattern: impl FnMut(usize) -> String) -> Vec<String> {
    (0..count).map(&mut make_pattern).collect()
}

fn lookup_cases() -> Vec<LookupCase> {
    const LARGE_COUNT: usize = 1_000;
    const WILDCARD_COUNT: usize = 128;

    vec![
        LookupCase {
            name: "literal_only",
            patterns: numbered_patterns(LARGE_COUNT, |i| format!("literal_{i:04}")),
            query: "literal_0500".to_string(),
            mode: MatchMode::CaseSensitive,
        },
        LookupCase {
            name: "glob_low_fanout_false",
            patterns: numbered_patterns(LARGE_COUNT, |i| format!("*anchor_{i:04}*needle_{i:04}")),
            query: "anchor_0500 missing".to_string(),
            mode: MatchMode::CaseSensitive,
        },
        LookupCase {
            name: "glob_high_fanout_false",
            patterns: numbered_patterns(LARGE_COUNT, |i| format!("*shared*needle_{i:04}")),
            query: "shared nothing-to-match".to_string(),
            mode: MatchMode::CaseSensitive,
        },
        LookupCase {
            name: "glob_high_fanout_true",
            patterns: numbered_patterns(LARGE_COUNT, |i| format!("*shared*needle_{i:04}")),
            query: "shared payload needle_0500".to_string(),
            mode: MatchMode::CaseSensitive,
        },
        LookupCase {
            name: "pure_wildcard",
            patterns: numbered_patterns(WILDCARD_COUNT, |i| {
                let questions = "?".repeat((i % 32) + 1);
                let stars = "*".repeat((i % 4) + 1);
                format!("{questions}{stars}")
            }),
            query: "abcdefghijklmnop".to_string(),
            mode: MatchMode::CaseSensitive,
        },
        LookupCase {
            name: "domain_suffix",
            patterns: numbered_patterns(LARGE_COUNT, |i| format!("*.evil{i:04}.com")),
            query: "sub.evil0500.com".to_string(),
            mode: MatchMode::CaseSensitive,
        },
        LookupCase {
            name: "prefix_star",
            patterns: numbered_patterns(LARGE_COUNT, |i| format!("prefix_{i:04}*")),
            query: "prefix_0500_payload".to_string(),
            mode: MatchMode::CaseSensitive,
        },
        LookupCase {
            name: "star_suffix",
            patterns: numbered_patterns(LARGE_COUNT, |i| format!("*suffix_{i:04}")),
            query: "payload_suffix_0500".to_string(),
            mode: MatchMode::CaseSensitive,
        },
        LookupCase {
            name: "star_contains",
            patterns: numbered_patterns(LARGE_COUNT, |i| format!("*middle_{i:04}*")),
            query: "payload_middle_0500_tail".to_string(),
            mode: MatchMode::CaseSensitive,
        },
        LookupCase {
            name: "ordered_literals",
            patterns: numbered_patterns(LARGE_COUNT, |i| {
                format!("*alpha_{i:04}*beta_{i:04}*gamma_{i:04}")
            }),
            query: "alpha_0500 x beta_0500 y gamma_0500".to_string(),
            mode: MatchMode::CaseSensitive,
        },
        LookupCase {
            name: "case_insensitive_domain",
            patterns: numbered_patterns(LARGE_COUNT, |i| format!("*.Evil{i:04}.COM")),
            query: "SUB.evil0500.com".to_string(),
            mode: MatchMode::CaseInsensitive,
        },
        LookupCase {
            name: "suffix_question_domain",
            patterns: numbered_patterns(LARGE_COUNT, |i| format!("*.evil{i:04}.?om")),
            query: "sub.evil0500.com".to_string(),
            mode: MatchMode::CaseSensitive,
        },
        LookupCase {
            name: "suffix_class_domain",
            patterns: numbered_patterns(LARGE_COUNT, |i| format!("*.evil{i:04}.[co]om")),
            query: "sub.evil0500.com".to_string(),
            mode: MatchMode::CaseSensitive,
        },
        LookupCase {
            name: "prefix_question_domain",
            patterns: numbered_patterns(LARGE_COUNT, |i| format!("evil{i:04}?.com*")),
            query: "evil0500x.com/path".to_string(),
            mode: MatchMode::CaseSensitive,
        },
    ]
}

fn bench_lookup_diagnostics(c: &mut Criterion) {
    let mut group = c.benchmark_group("lookup_diagnostics");

    for case in lookup_cases() {
        let pattern_count = case.patterns.len();
        let pattern_refs: Vec<&str> = case.patterns.iter().map(String::as_str).collect();
        let pg = Paraglob::build_from_patterns(&pattern_refs, case.mode).unwrap();
        let (sample_matches, diagnostics) = pg.find_all_with_diagnostics(&case.query);

        println!(
            "lookup_diagnostics case={} patterns={} matches={} counters={:?}",
            case.name,
            pattern_count,
            sample_matches.len(),
            diagnostics
        );

        group.throughput(Throughput::Bytes(case.query.len() as u64));
        group.bench_function(BenchmarkId::new(case.name, pattern_count), |b| {
            b.iter(|| {
                let matches = pg.find_all(black_box(&case.query));
                black_box(matches);
            });
        });
    }

    group.finish();
}

criterion_group!(benches, bench_lookup_diagnostics);
criterion_main!(benches);
