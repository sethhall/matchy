//! Direct benchmark for the owned, eagerly validated AC traversal used by
//! streaming consumers such as Zeek.
//!
//! This is deliberately a small, dependency-free custom harness so the bench
//! continues to compile at `matchy-ac`'s Rust 1.74 MSRV. Pass a bare integer
//! after `--` to select the number of timed samples, for example:
//! `cargo bench -p matchy-ac --bench ac_traversal_bench -- 15`.

use std::hint::black_box;
use std::time::{Duration, Instant};

use matchy_ac::{ACAutomaton, ACAutomatonView, ACMatch, MatchMode};

const MIB: f64 = 1024.0 * 1024.0;
const STREAM_CHUNK_BYTES: usize = 1_460;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ScanSummary {
    outputs: u64,
    checksum: u64,
}

struct BenchShape {
    name: &'static str,
    mode: MatchMode,
    patterns: Vec<Vec<u8>>,
    input: Vec<u8>,
    expect_sidecar: bool,
}

fn productive_patterns(count: usize) -> Vec<Vec<u8>> {
    let mut patterns = (0..count)
        .map(|index| format!("threat-{index:04}-payload").into_bytes())
        .collect::<Vec<_>>();
    // These one-byte terminals ensure the root-pair shortcut is measured with
    // the same output-preservation guard required by production automata.
    patterns.push(b"G".to_vec());
    patterns.push(b"x".to_vec());
    patterns
}

fn productive_traffic(size: usize) -> Vec<u8> {
    let ordinary =
        b"GET /safe/path HTTP/1.1\r\nHost: ordinary.example\r\nUser-Agent: benchmark\r\n\r\n";
    let hit = b"POST /ThReAt-0042-PaYlOaD HTTP/1.1\r\nHost: ordinary.example\r\n\r\n";
    let mut result = Vec::with_capacity(size);
    let mut line = 0_usize;
    while result.len() < size {
        result.extend_from_slice(if line % 512 == 0 { hit } else { ordinary });
        line = line.saturating_add(1);
    }
    result.truncate(size);
    result
}

fn adverse_patterns() -> Vec<Vec<u8>> {
    // A terminal for every possible first byte makes every root pair require
    // scalar treatment. The tails take the serialized automaton past the size
    // gate, so an adaptive implementation must reject it on pair density.
    let mut patterns = (u8::MIN..=u8::MAX)
        .map(|byte| vec![byte])
        .collect::<Vec<_>>();
    patterns.extend((0..512).map(|index| format!("dense-tail-{index:04}-payload").into_bytes()));
    patterns
}

fn adverse_traffic(size: usize) -> Vec<u8> {
    let mut result = Vec::with_capacity(size);
    let mut value = 0x243f_6a88_u32;
    while result.len() < size {
        // Deterministic xorshift traffic supplies all byte values without
        // spending benchmark time in a random-number dependency.
        value ^= value << 13;
        value ^= value >> 17;
        value ^= value << 5;
        result.push(value.to_le_bytes()[0]);
    }
    result
}

fn scan(view: &ACAutomatonView<'_>, input: &[u8], chunk_size: usize) -> ScanSummary {
    let mut state = view.create_state();
    let mut summary = ScanSummary {
        outputs: 0,
        checksum: 0xcbf2_9ce4_8422_2325,
    };

    for chunk in input.chunks(chunk_size) {
        view.advance(&mut state, chunk, |matched: ACMatch| {
            summary.outputs = summary.outputs.saturating_add(1);
            summary.checksum = summary.checksum.rotate_left(9)
                ^ u64::from(matched.pattern_id)
                ^ matched.start.rotate_left(21)
                ^ matched.end.rotate_left(43);
        })
        .expect("benchmark uses an exact-span AC view");
    }

    summary
}

fn timed_scan(
    view: &ACAutomatonView<'_>,
    input: &[u8],
    chunk_size: usize,
) -> (Duration, ScanSummary) {
    let started = Instant::now();
    let summary = black_box(scan(black_box(view), black_box(input), chunk_size));
    (started.elapsed(), summary)
}

fn median(samples: &mut [Duration]) -> Duration {
    samples.sort_unstable();
    samples[samples.len() / 2]
}

fn throughput_mib_per_second(input_bytes: usize, elapsed: Duration) -> f64 {
    input_bytes as f64 / MIB / elapsed.as_secs_f64()
}

fn measure_pair(
    owned: &ACAutomatonView<'_>,
    scalar: &ACAutomatonView<'_>,
    input: &[u8],
    chunk_size: usize,
    samples: usize,
) -> (Duration, Duration, ScanSummary) {
    let expected = scan(scalar, input, chunk_size);
    assert_eq!(
        scan(owned, input, chunk_size),
        expected,
        "owned sidecar and serialized scalar paths disagree"
    );

    // Warm both instruction paths before collecting samples. Timed order is
    // alternated to reduce systematic thermal/frequency bias.
    black_box(scan(owned, input, chunk_size));
    black_box(scan(scalar, input, chunk_size));

    let mut owned_samples = Vec::with_capacity(samples);
    let mut scalar_samples = Vec::with_capacity(samples);
    for sample in 0..samples {
        let ((owned_elapsed, owned_summary), (scalar_elapsed, scalar_summary)) = if sample % 2 == 0
        {
            (
                timed_scan(owned, input, chunk_size),
                timed_scan(scalar, input, chunk_size),
            )
        } else {
            let scalar_result = timed_scan(scalar, input, chunk_size);
            let owned_result = timed_scan(owned, input, chunk_size);
            (owned_result, scalar_result)
        };
        assert_eq!(owned_summary, expected);
        assert_eq!(scalar_summary, expected);
        owned_samples.push(owned_elapsed);
        scalar_samples.push(scalar_elapsed);
    }

    (
        median(&mut owned_samples),
        median(&mut scalar_samples),
        expected,
    )
}

fn run_shape(shape: &BenchShape, samples: usize) {
    let pattern_refs = shape.patterns.iter().map(Vec::as_slice).collect::<Vec<_>>();
    let matcher = ACAutomaton::build_bytes(&pattern_refs, shape.mode)
        .expect("benchmark patterns should compile");
    let owned = matcher.view().expect("owned automaton should be valid");
    let scalar = ACAutomatonView::with_pattern_lengths(
        matcher.buffer(),
        matcher.node_count(),
        matcher.pattern_lengths(),
        matcher.match_mode(),
    )
    .expect("serialized automaton should validate");
    let serialized_bytes = matcher.buffer().len();
    let memory_bytes = matcher.memory_bytes();
    let has_execution_sidecar = memory_bytes > serialized_bytes;
    assert_eq!(
        has_execution_sidecar, shape.expect_sidecar,
        "benchmark shape no longer exercises its intended sidecar path"
    );

    println!(
        "\n{}: mode={:?}, patterns={}, input={} bytes, serialized={} bytes, total={} bytes, sidecar={}, sidecar-bytes={}",
        shape.name,
        shape.mode,
        matcher.pattern_count(),
        shape.input.len(),
        serialized_bytes,
        memory_bytes,
        has_execution_sidecar,
        memory_bytes.saturating_sub(serialized_bytes),
    );

    for (label, chunk_size) in [
        ("single", shape.input.len()),
        ("stream-1460", STREAM_CHUNK_BYTES),
    ] {
        let (owned_elapsed, scalar_elapsed, summary) =
            measure_pair(&owned, &scalar, &shape.input, chunk_size, samples);
        let owned_throughput = throughput_mib_per_second(shape.input.len(), owned_elapsed);
        let scalar_throughput = throughput_mib_per_second(shape.input.len(), scalar_elapsed);
        println!(
            "  {label:>11}: owned={owned_elapsed:?} ({owned_throughput:8.1} MiB/s), scalar={scalar_elapsed:?} ({scalar_throughput:8.1} MiB/s), speedup={:.3}x, outputs={}, checksum={:016x}",
            scalar_elapsed.as_secs_f64() / owned_elapsed.as_secs_f64(),
            summary.outputs,
            summary.checksum,
        );
    }
}

fn sample_count() -> usize {
    std::env::args()
        .skip(1)
        .find_map(|argument| argument.parse::<usize>().ok())
        .unwrap_or(9)
        .max(1)
}

fn main() {
    let samples = sample_count();
    println!("matchy-ac traversal benchmark ({samples} timed samples per path)");

    run_shape(
        &BenchShape {
            name: "sparse-productive",
            mode: MatchMode::CaseInsensitive,
            patterns: productive_patterns(1_000),
            input: productive_traffic(4 * 1024 * 1024),
            expect_sidecar: true,
        },
        samples,
    );
    run_shape(
        &BenchShape {
            name: "dense-one-byte-adverse",
            mode: MatchMode::CaseSensitive,
            patterns: adverse_patterns(),
            input: adverse_traffic(1024 * 1024),
            expect_sidecar: false,
        },
        samples,
    );
}
