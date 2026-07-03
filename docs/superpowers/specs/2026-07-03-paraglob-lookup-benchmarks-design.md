# Paraglob Lookup Benchmark and Diagnostics Design

## Context

Paraglob lookup already uses a zero-copy, mmap-friendly layout. Load time is not the current target: the loader validates section bounds and headers, then stores offsets into the mapped buffer. The performance question is lookup speed, especially the cost of verifying candidate glob patterns after Aho-Corasick finds literal anchors.

The current lookup flow is:

1. Scan query text with the serialized AC automaton.
2. Map matched AC literal IDs to candidate pattern IDs through the serialized AC literal hash table.
3. Always verify pure wildcard patterns.
4. Verify each candidate glob with the serialized segment matcher.
5. Sort and deduplicate results for `find_all`.

The suspected bottleneck is step 4, but candidate fan-out can make verification look worse than it is. The first pass should measure both effects before changing matching behavior.

## Goals

- Add lookup-focused benchmarks that isolate AC scanning, candidate fan-out, and glob verification cost.
- Add feature-gated diagnostics for benchmark/profiling builds.
- Keep the existing binary format unchanged.
- Keep public lookup behavior unchanged.
- Produce data that makes the first optimization choice clear.

## Non-Goals

- Do not change `#[repr(C)]` binary format structs.
- Do not add new dependencies.
- Do not modify C API signatures.
- Do not optimize the matcher in this pass except for trivial benchmark-only plumbing.
- Do not replace the current glob language or semantics.

## Benchmark Coverage

Add a new Criterion benchmark focused on lookup verification behavior at `crates/matchy-paraglob/benches/lookup_diagnostics_bench.rs`.

Benchmark cases:

- `literal_only`: exact literal patterns with no glob verification.
- `glob_low_fanout_false`: glob patterns with uncommon anchors where candidates mostly fail verification.
- `glob_high_fanout_false`: many glob patterns sharing common anchors, forcing many false-positive verifications.
- `glob_high_fanout_true`: shared anchors with true matches to measure successful verification cost.
- `pure_wildcard`: patterns with no extractable literals that must be checked on every query.
- `domain_suffix`: IoC-style `*.evilN.com` patterns.
- `prefix_star`: `prefixN*` patterns.
- `star_suffix`: `*suffixN` patterns.
- `ordered_literals`: `aN*bN*cN` patterns.
- `case_insensitive_domain`: ASCII-heavy case-insensitive domain lookups.

Each case should report normal Criterion timing and throughput, and when diagnostics are enabled, print aggregate counters after each benchmark group.

## Diagnostics

Add a feature-gated diagnostics path, for example behind a crate feature named `bench-diagnostics`.

The diagnostics should count:

- query bytes scanned
- AC literal hits
- unique candidate pattern IDs
- pure wildcard checks
- glob verification attempts
- successful glob verifications
- serialized glob segment steps
- star backtracking attempts

The diagnostics should be disabled by default and should not affect normal builds. The benchmark should be able to reset and read counters around each measured workload.

Implementation constraints:

- Prefer simple counters in benchmark-only code paths.
- Do not allocate on the default lookup path.
- Do not expose unstable diagnostics as public API unless necessary for Criterion access.
- If an internal API is needed, keep it crate-local or feature-gated.

## Expected Findings

The measurements should make one of these follow-up optimizations the clear first candidate:

- If candidate count is high, improve build-time anchor selection so common literals produce fewer candidate patterns.
- If candidate count is modest but verification steps are high, add specialized fast paths for common glob shapes.
- If `find_all` result handling dominates, add a caller-owned result buffer or visitor-style public API.
- If case-insensitive verification is costly, consider normalized byte-oriented glob literals and ASCII-specific verification fast paths.

## Testing

Add unit tests only if diagnostics introduce new code paths. The tests should verify that counters increment for representative literals, glob candidates, pure wildcards, and successful matches.

Run:

- `cargo fmt`
- `cargo test -p matchy-paraglob`
- `cargo bench -p matchy-paraglob --bench lookup_diagnostics_bench` when validating locally

## Risks

- Diagnostics can distort benchmark timings if counters are used inside measured loops. Keep normal timing runs available without diagnostics.
- High-fanout synthetic data may overstate real production cost. Include IoC-shaped domain patterns to balance this.
- Feature-gated internals can bitrot. Keep the diagnostic surface small and tied to benchmarks.

## Acceptance Criteria

- A lookup-focused benchmark file exists and covers the listed workload shapes.
- A default benchmark run works without changing database format or public behavior.
- An opt-in diagnostics run reports the key counters for each workload.
- Results are sufficient to decide whether candidate fan-out, verification mechanics, or result handling should be optimized first.
