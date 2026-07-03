# Documentation Correctness Audit - 2026-07-03

Scope: active Matchy documentation, crate README files, book sources, examples README, C examples, and public rustdoc examples that affect user-facing docs. Generated output under `target/**` and `book/book/**` was excluded. `CHANGELOG.md` and `book/src/changelog.md` were treated as historical release notes.

## Sources Of Truth Used

- CLI help and behavior from `target/debug/matchy --help` and each documented subcommand.
- CLI source under `crates/matchy/src/bin/**`.
- Rust API source under `crates/matchy/src/lib.rs`, `database.rs`, `builder_ext.rs`, `validation.rs`, `schema_validation.rs`, and `error.rs`.
- C API source under `crates/matchy/src/c_api/**`; generated header was regenerated with `cargo build --release -p matchy --locked`.
- Data model source in `crates/matchy-data-format` and extractor source in `crates/matchy-extractor`.
- Example source under `crates/matchy/examples/**`.
- Live command probes for `build`, `query`, `match`, `extract`, `inspect`, `validate`, and `bench`.

## Verification Status

Verified by final checks:

- `cargo fmt`: passed.
- `cargo build --release -p matchy --locked`: passed; regenerated `crates/matchy/include/matchy/matchy.h`.
- `cargo clippy --locked -- -D warnings`: passed.
- `cargo test --doc -p matchy --locked`: passed, 33 doc tests passed and 6 ignored.
- `cd book && mdbook build`: passed; wrote `book/book`.
- `git diff --check`: passed after fixing one trailing whitespace line in a C example.
- Targeted stale-symbol scans: no current-facing stale API families remained; intentional hits are listed below.
- Final git status: reviewed; untracked pre-existing `sample.log` and `threats.csv` remain.
- `Cargo.toml`, `Cargo.lock`, and `.github/workflows/**`: no diffs.

## Markdown Documentation Checklist

| File | Checked concepts and source of truth | Result | Status |
| --- | --- | --- | --- |
| `AGENTS.md` | Header path, C API result style, FFI boundary rules; `crates/matchy/src/c_api/**` and generated header path | Updated stale `include/matchy.h` references and old integer-only FFI example | Verified by final checks |
| `CHANGELOG.md` | Historical release-note references; stale-symbol scan | Verified historical only; no current-behavior edits | Verified by final checks |
| `CONTRIBUTING.md` | Contributor commands and local workflow; Cargo workspace commands | Verified no change | Verified by final checks |
| `DEVELOPMENT.md` | Architecture, C API shape, extractor/hash variants, processing structs, validation levels; source files | Updated stale C API wording, SHA512 coverage, extractor examples, processing result fields, validation levels | Verified by final checks |
| `README.md` | Quick start CLI output, Rust/C snippets, generated header path; CLI probes and C API source | Added C result cleanup in snippet; verified query output shape | Verified by final checks |
| `book/README.md` | Book build/use instructions; mdBook source layout | Verified no change | Verified by final checks |
| `book/mdbook-project-version/README.md` | mdBook preprocessor documentation | Verified no change | Verified by final checks |
| `book/src/SUMMARY.md` | Book navigation against existing source files | Verified no change | Verified by final checks |
| `book/src/appendix/examples.md` | Example names and command syntax; `crates/matchy/examples/**` | Updated stale examples/paths | Verified by final checks |
| `book/src/appendix/glossary.md` | Terms and database concepts; current architecture/source | Verified no change | Verified by final checks |
| `book/src/architecture/overview.md` | Architecture diagram and pipeline terms; source layout | Updated stale component wording | Verified by final checks |
| `book/src/architecture/performance-results.md` | Performance claims as historical/illustrative figures | Verified no change | Verified by final checks |
| `book/src/architecture/performance.md` | Performance model and lookup paths; source layout | Verified no change | Verified by final checks |
| `book/src/changelog.md` | Historical release-note references; stale-symbol scan | Verified historical only; no current-behavior edits | Verified by final checks |
| `book/src/commands/index.md` | Command index against `matchy --help` | Updated `bench` summary to include build/load/query | Verified by final checks |
| `book/src/commands/matchy.md` | Top-level command list/options; `target/debug/matchy --help` | Added missing `match`, `extract`, and `validate`; fixed `bench` wording | Verified by final checks |
| `book/src/commands/matchy-build.md` | Build syntax/options/output; CLI help and live build probe | Corrected example success output | Verified by final checks |
| `book/src/commands/matchy-query.md` | Query syntax, quiet flag, JSON output, exit codes; CLI help and live query probes | Updated output examples to JSON arrays and IP metadata fields; added quiet flag | Verified by final checks |
| `book/src/commands/matchy-match.md` | Match syntax/options/output schema; CLI help and live match probe | Added current options and changed examples from `line_number`/`input_line` to `source`-based NDJSON | Verified by final checks |
| `book/src/commands/matchy-extract.md` | Extract syntax/types/output; CLI help and live extract probes | Corrected accepted `--types`; documented hash/crypto always-enabled behavior and IDN preservation | Verified by final checks |
| `book/src/commands/matchy-inspect.md` | Inspect options/output; CLI help and live inspect probe | Verified no change after probe | Verified by final checks |
| `book/src/commands/matchy-validate.md` | Validation levels/options/output; CLI source/help | Removed unsupported `audit` level | Verified by final checks |
| `book/src/commands/matchy-bench.md` | Bench positional type/options; CLI help | Added missing cache options and verified type syntax | Verified by final checks |
| `book/src/contributing.md` | Contributor commands and generated header path | Updated stale command/path wording | Verified by final checks |
| `book/src/dev/benchmarking.md` | Bench/dev commands; CLI help and scripts | Updated stale benchmark wording | Verified by final checks |
| `book/src/dev/building.md` | Build behavior and cbindgen output | Updated generated header path | Verified by final checks |
| `book/src/dev/ci-checks.md` | CI command references | Verified no change | Verified by final checks |
| `book/src/dev/fuzz-targets.md` | Fuzz target descriptions | Verified no change | Verified by final checks |
| `book/src/dev/fuzzing.md` | Fuzzing commands and target layout | Verified no change | Verified by final checks |
| `book/src/dev/releasing.md` | Release process docs | Verified no change | Verified by final checks |
| `book/src/dev/symlink-setup.md` | Header symlink instructions | Updated generated header path and cleanup command | Verified by final checks |
| `book/src/dev/testing.md` | Test command references | Updated stale command wording | Verified by final checks |
| `book/src/faq.md` | Current behavior Q&A | Verified no change | Verified by final checks |
| `book/src/first-database.md` | First database CLI/Rust examples; CLI probes and Rust API | Updated stale output/API shape | Verified by final checks |
| `book/src/getting-started/index.md` | Navigation page | Verified no change | Verified by final checks |
| `book/src/getting-started/first-steps.md` | First-step commands and output | Updated stale output/API details | Verified by final checks |
| `book/src/getting-started/cli.md` | CLI workflow and outputs | Updated stale query/match behavior | Verified by final checks |
| `book/src/getting-started/cli-installation.md` | CLI install commands | Verified no change | Verified by final checks |
| `book/src/getting-started/cli-first-database.md` | CLI build/query examples | Updated stale output details | Verified by final checks |
| `book/src/getting-started/api.md` | Rust/C API overview snippets; API source | Guarded C JSON conversion and result cleanup | Verified by final checks |
| `book/src/getting-started/api-installation.md` | API install/header/library instructions | Updated generated header path/details | Verified by final checks |
| `book/src/getting-started/api-rust-first.md` | Rust builder/query examples; Rust API source | Updated stale Rust API/query examples | Verified by final checks |
| `book/src/getting-started/api-c-first.md` | C first program; C API source/header | Guarded JSON conversions and fixed cleanup examples | Verified by final checks |
| `book/src/getting-started/installation.md` | Install/build commands and examples | Removed stale example names and fixed header copy path | Verified by final checks |
| `book/src/guide/index.md` | Guide navigation | Verified no change | Verified by final checks |
| `book/src/guide/why-matchy-exists.md` | Conceptual positioning | Verified no change | Verified by final checks |
| `book/src/guide/database-concepts.md` | Database/query concepts | Verified no change | Verified by final checks |
| `book/src/guide/entry-types.md` | Entry types; builder/database source | Verified no change | Verified by final checks |
| `book/src/guide/ips-and-cidr.md` | IP/CIDR behavior; source and CLI probes | Verified no change | Verified by final checks |
| `book/src/guide/patterns.md` | Glob pattern semantics; paraglob source | Verified no change | Verified by final checks |
| `book/src/guide/creating-a-database.md` | Builder workflow and CLI build | Verified no change | Verified by final checks |
| `book/src/guide/querying.md` | Querying workflow and match result fields | Updated stale result wording | Verified by final checks |
| `book/src/guide/caching.md` | Cache concepts and options | Verified no change | Verified by final checks |
| `book/src/guide/extraction.md` | Extractor API/CLI behavior and hash variants; extractor source/probes | Added SHA384/SHA512 coverage and corrected CLI output fields | Verified by final checks |
| `book/src/guide/data-types.md` | DataValue variants/limits/nesting; data-format source | Removed `Null` claim and corrected size/depth limits | Verified by final checks |
| `book/src/guide/auto-reload.md` | Auto-reload C API and callback usage; C API source | Updated C query/cleanup snippets | Verified by final checks |
| `book/src/guide/migrating-libmaxminddb.md` | C API migration examples; C API source | Updated query/cleanup examples | Verified by final checks |
| `book/src/guide/mmdb-compatibility.md` | MMDB compatibility and C API examples | Updated C API query cleanup wording | Verified by final checks |
| `book/src/guide/performance.md` | Performance examples, C API snippets, benchmark commands | Updated C API cleanup and benchmark wording | Verified by final checks |
| `book/src/introduction.md` | Product overview and feature list | Verified no change | Verified by final checks |
| `book/src/quick-start.md` | Rust/C quick start and compile command; API/source paths | Guarded C JSON conversions, moved result cleanup, fixed include path | Verified by final checks |
| `book/src/reference/index.md` | Reference navigation | Verified no change | Verified by final checks |
| `book/src/reference/project-setup.md` | Project setup references | Verified no change | Verified by final checks |
| `book/src/reference/input-formats.md` | Supported build input formats; CLI/source | Verified no change | Verified by final checks |
| `book/src/reference/binary-format.md` | Binary format reference; format source | Verified no change | Verified by final checks |
| `book/src/reference/architecture.md` | Internal architecture summary | Updated stale wording | Verified by final checks |
| `book/src/reference/benchmarks.md` | Benchmark command references | Updated stale benchmark examples/options | Verified by final checks |
| `book/src/reference/rust-api.md` | Rust API examples; `lib.rs`, `database.rs`, `builder_ext.rs` | Updated stale API names/result examples | Verified by final checks |
| `book/src/reference/database-builder.md` | Builder API/examples; `builder_ext.rs` and C API builder source | Updated stale builder methods/signatures | Verified by final checks |
| `book/src/reference/database-query.md` | Query API/result variants; `database.rs` | Updated stale `Database::open`/old result variants/examples | Verified by final checks |
| `book/src/reference/error-handling-ref.md` | Error enum/C error constants; source | Rewrote stale error constants and examples to current API | Verified by final checks |
| `book/src/reference/data-types-ref.md` | DataValue reference; data-format source | Corrected variants, limits, and nesting behavior | Verified by final checks |
| `book/src/reference/schemas.md` | Schema concepts/API; schema source | Verified no change | Verified by final checks |
| `book/src/reference/validation-api.md` | Validation levels/stats fields; validation source | Removed `Audit` level and corrected stats/API examples | Verified by final checks |
| `book/src/reference/c-api.md` | C API overview; C source/header | Replaced stale APIs with current handles, results, errors, and cleanup | Verified by final checks |
| `book/src/reference/c-building.md` | C builder signatures and examples; C API source | Corrected `uintptr_t` size, function names, paths, error constants | Verified by final checks |
| `book/src/reference/c-querying.md` | C query/lifetime/cleanup examples; C API source | Corrected buffer lifetime, query APIs, JSON guards, cleanup | Verified by final checks |
| `book/src/reference/c-memory.md` | C allocation/lifetime rules; C API source | Corrected `matchy_open_buffer` ownership and JSON cleanup | Verified by final checks |
| `book/src/reference/c-installation.md` | C install/pkg-config/header paths | Updated current version/path details | Verified by final checks |
| `book/src/reference/mmdb-integration.md` | MMDB/C API migration; C API source | Updated query/free examples and current API mapping | Verified by final checks |
| `book/src/reference/mmdb-integration-design.md` | MMDB integration design | Updated stale C/API wording | Verified by final checks |
| `book/src/reference/examples.md` | Rust/C/CLI examples; current examples/source | Moved C result cleanup out of branch and verified command syntax | Verified by final checks |
| `crates/matchy-format/README.md` | Crate dependency references | Replaced stale `matchy-glob` reference | Verified by final checks |
| `crates/matchy-literal-hash/README.md` | Literal hash API/behavior | Verified no change | Verified by final checks |
| `crates/matchy-match-mode/README.md` | Crate dependency references | Removed stale `matchy-glob` reference | Verified by final checks |
| `crates/matchy-wasm/README.md` | WASM crate instructions | Verified no change | Verified by final checks |
| `crates/matchy-wasm/demo/README.md` | WASM demo instructions | Verified no change | Verified by final checks |
| `crates/matchy-extractor/tools/update-psl/README.md` | PSL update tooling | Verified no change | Verified by final checks |
| `crates/matchy/examples/README.md` | Example inventory and build commands; examples directory | Removed nonexistent examples, added existing ones, fixed C build commands/extensions | Verified by final checks |
| `fuzz/README.md` | Fuzz commands/targets | Verified no change | Verified by final checks |
| `scripts/README.md` | Script inventory | Verified no change | Verified by final checks |
| `scripts/BENCHMARKING.md` | Benchmark scripts and commands | Verified no change | Verified by final checks |

## Public Rustdoc And Example Source Checklist

| File | Checked concepts and source of truth | Result | Status |
| --- | --- | --- | --- |
| `crates/matchy/src/lib.rs` | Public re-exports/module docs; actual processing API | Removed stale `LineBatch`/`LineMatch` rustdoc reference | Verified by final checks |
| `crates/matchy/src/database.rs` | Public `Database` API; book/Rust examples | Used as source of truth; verified no direct edit needed | Verified by final checks |
| `crates/matchy/src/builder_ext.rs` | Public builder extension API; builder docs | Used as source of truth; verified no direct edit needed | Verified by final checks |
| `crates/matchy/src/c_api/mod.rs` | C API module-level rustdoc; generated header source | Guarded JSON conversion in public example | Verified by final checks |
| `crates/matchy/src/c_api/matchy.rs` | C API signatures, safety docs, generated header comments | Corrected builder size type, buffer lifetime doc, query/free examples, JSON guard | Verified by final checks |
| `crates/matchy/include/matchy/matchy.h` | Generated C header comments | Regenerated from Rust C API docs by `cargo build --release -p matchy --locked` | Verified by final checks |
| `crates/matchy-extractor/src/types.rs` | Public extractor type docs | Added SHA384/SHA512 to hash docs | Verified by final checks |
| `crates/matchy/examples/README.md` | Example catalog | See markdown checklist row | Verified by final checks |
| `crates/matchy/examples/build_ip_database.rs` | Example availability/API scan | Verified no change | Verified by final checks |
| `crates/matchy/examples/build_combined_database.rs` | Example availability/API scan | Verified no change | Verified by final checks |
| `crates/matchy/examples/build_misp_database.rs` | Example availability/API scan | Verified no change | Verified by final checks |
| `crates/matchy/examples/cache_demo.rs` | Example availability/API scan | Verified no change | Verified by final checks |
| `crates/matchy/examples/concurrent_extraction.rs` | Example availability/API scan | Verified no change | Verified by final checks |
| `crates/matchy/examples/custom_metadata.rs` | Example availability/API scan | Verified no change | Verified by final checks |
| `crates/matchy/examples/endianness_demo.rs` | Example availability/API scan | Verified no change | Verified by final checks |
| `crates/matchy/examples/extractor_demo.rs` | Example availability/API scan | Verified no change | Verified by final checks |
| `crates/matchy/examples/generate_logs.rs` | Example availability/API scan | Verified no change | Verified by final checks |
| `crates/matchy/examples/geoip_query.rs` | Example availability/API scan | Verified no change | Verified by final checks |
| `crates/matchy/examples/hash_build_bench.rs` | Example availability/API scan | Verified no change | Verified by final checks |
| `crates/matchy/examples/hash_demo.rs` | Hash extractor docs and algorithm lengths; extractor source | Added SHA384/SHA512 coverage | Verified by final checks |
| `crates/matchy/examples/lookup_extracted_demo.rs` | Example availability/API scan | Verified no change | Verified by final checks |
| `crates/matchy/examples/parallel_processing.rs` | Example availability/API scan | Verified no change | Verified by final checks |
| `crates/matchy/examples/prefix_convention.rs` | Example availability/API scan | Verified no change | Verified by final checks |
| `crates/matchy/examples/test_hash_speed.rs` | Example availability/API scan | Verified no change | Verified by final checks |
| `crates/matchy/examples/combined_query.rs` | Combined database example paths/extensions | Changed stale `.pgb`/MMDB wording to `.mxy` | Verified by final checks |
| `crates/matchy/examples/c_auto_reload_example.c` | C API signatures/includes/lifetime | Updated include path, query/free calls, close function, build/run command | Verified by final checks |
| `crates/matchy/examples/c_reload_callback.c` | C API signatures and result cleanup | Updated `uintptr_t`, `matchy_query`, and result cleanup | Verified by final checks |
| `crates/matchy/examples/enhanced_api_test.c` | C include path | Updated include path to `matchy/matchy.h` | Verified by final checks |

## Targeted Stale-Symbol Scan Notes

Current intentional hits before final verification:

- `MATCHY_ERROR_UNKNOWN_SCHEMA` is current and should not be confused with stale `MATCHY_ERROR_UNKNOWN`.
- `CHANGELOG.md` and `book/src/changelog.md` retain historical release-note references.
- `crates/matchy-paraglob/tests/integration_tests.rs` contains test names with `incremental_builder`; those are source test names, not user-facing stale examples.
- `book/src/reference/c-installation.md` retains `sudo cp include/matchy/*.h` for release tarball layout; source checkout paths use `crates/matchy/include/matchy/*.h`.
