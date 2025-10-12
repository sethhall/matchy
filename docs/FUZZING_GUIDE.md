# Rust Fuzzing Guide for matchy

## TL;DR

Rust doesn't have fuzzing built into cargo, but has **world-class** fuzzing tools:
- **cargo-fuzz** (libFuzzer) - Most popular, production-ready
- **AFL** (American Fuzzy Lop) - Classic fuzzer, very thorough
- **Honggfuzz** - Fast, great for parallel fuzzing
- **proptest** - Property-based testing (QuickCheck-style)

For matchy, I'd recommend **cargo-fuzz** for finding crashes and **proptest** for logic bugs.

---

## Fuzzing Tools Comparison

### 1. cargo-fuzz (libFuzzer) ⭐ **RECOMMENDED**

**What it is:** Cargo wrapper around LLVM's libFuzzer (coverage-guided fuzzing)

**Pros:**
- ✅ Easy to set up (`cargo install cargo-fuzz`)
- ✅ Great Rust integration
- ✅ Coverage-guided (smart, not just random)
- ✅ Fast feedback loop
- ✅ Excellent crash reporting
- ✅ Works on macOS, Linux

**Cons:**
- ❌ Requires nightly Rust (needs instrumentation)
- ❌ Single-process (slower than AFL for some workloads)

**Best for:** Finding crashes, memory safety issues, panics

```bash
# Install
cargo install cargo-fuzz

# Initialize (creates fuzz/ directory)
cargo fuzz init

# Run
cargo +nightly fuzz run my_target

# Run with corpus from previous runs
cargo +nightly fuzz run my_target fuzz/corpus/my_target
```

---

### 2. AFL (American Fuzzy Lop)

**What it is:** Classic coverage-guided fuzzer (industry standard)

**Pros:**
- ✅ Extremely thorough
- ✅ Multi-process (parallel fuzzing)
- ✅ Battle-tested (found 1000s of bugs)
- ✅ Great visualization

**Cons:**
- ❌ More complex setup
- ❌ Slower startup than libFuzzer
- ❌ Requires instrumentation at compile time

**Best for:** Long-running fuzzing campaigns, CI/CD

```bash
# Install
cargo install afl

# Build with instrumentation
cargo afl build --release

# Run
cargo afl fuzz -i in -o out target/release/my_target
```

---

### 3. Honggfuzz

**What it is:** Fast, parallel fuzzer from Google

**Pros:**
- ✅ Very fast
- ✅ Great for parallel fuzzing
- ✅ Good at finding edge cases
- ✅ Hardware-assisted fuzzing (Intel PT)

**Cons:**
- ❌ Less common in Rust ecosystem
- ❌ Harder to debug crashes

**Best for:** Performance testing, parallel campaigns

```bash
cargo install honggfuzz
cargo hfuzz run my_target
```

---

### 4. proptest (Property-Based Testing)

**What it is:** QuickCheck-style property testing (not traditional fuzzing)

**Pros:**
- ✅ Runs on stable Rust
- ✅ Great for logic bugs
- ✅ Shrinks failing inputs automatically
- ✅ Integrates with `cargo test`
- ✅ No unsafe code needed

**Cons:**
- ❌ Not coverage-guided
- ❌ Slower than fuzzers
- ❌ Requires writing properties

**Best for:** Testing invariants, logic bugs, business rules

```rust
use proptest::prelude::*;

proptest! {
    #[test]
    fn test_ip_parsing(ip in "[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}") {
        // This should never panic
        let _ = parse_ip(&ip);
    }
}
```

---

## Setting Up cargo-fuzz for matchy

### Step 1: Install

```bash
# Requires nightly for instrumentation
rustup install nightly
cargo install cargo-fuzz
```

### Step 2: Initialize

```bash
cd /Users/seth/factual/mmdb_with_strings/matchy
cargo fuzz init
```

This creates:
```
fuzz/
├── Cargo.toml              # Separate workspace
└── fuzz_targets/
    └── fuzz_target_1.rs    # Template target
```

### Step 3: Create Fuzz Targets

**Target 1: Database Loading** (Most Important!)

```rust
// fuzz/fuzz_targets/fuzz_database_load.rs
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // This should NEVER crash or panic, even on garbage input
    let _ = matchy::Database::from_bytes(data.to_vec());
});
```

**Target 2: IP Lookups**

```rust
// fuzz/fuzz_targets/fuzz_ip_lookup.rs
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(db) = matchy::Database::from_bytes(data.to_vec()) {
        // Try random IP lookups
        let _ = db.lookup("192.168.1.1");
        let _ = db.lookup("invalid");
    }
});
```

**Target 3: Pattern Matching**

```rust
// fuzz/fuzz_targets/fuzz_pattern_matching.rs
#![no_main]
use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    database: Vec<u8>,
    queries: Vec<String>,
}

fuzz_target!(|input: FuzzInput| {
    if let Ok(db) = matchy::Database::from_bytes(input.database) {
        for query in &input.queries {
            let _ = db.lookup(query);
        }
    }
});
```

**Target 4: Paraglob Format Parsing**

```rust
// fuzz/fuzz_targets/fuzz_paraglob.rs
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Test direct paraglob parsing
    // Should never cause UB even with garbage data
    let _ = matchy::paraglob_offset::Paraglob::from_bytes(
        data, 
        matchy::glob::MatchMode::CaseSensitive
    );
});
```

### Step 4: Run Fuzzing

```bash
# Quick test (5 minutes each)
cargo +nightly fuzz run fuzz_database_load -- -max_total_time=300
cargo +nightly fuzz run fuzz_paraglob -- -max_total_time=300

# Long campaign (overnight)
cargo +nightly fuzz run fuzz_database_load -- -max_total_time=28800

# Parallel fuzzing (use all cores)
cargo +nightly fuzz run fuzz_database_load -- -jobs=8

# With corpus (reuse previous findings)
cargo +nightly fuzz run fuzz_database_load fuzz/corpus/fuzz_database_load

# Memory limit (prevent OOM)
cargo +nightly fuzz run fuzz_database_load -- -rss_limit_mb=2048
```

### Step 5: Reproduce Crashes

When a crash is found:

```bash
# Fuzzer will save crash to: fuzz/artifacts/fuzz_database_load/crash-<hash>

# Reproduce crash
cargo +nightly fuzz run fuzz_database_load fuzz/artifacts/fuzz_database_load/crash-abc123

# Debug with lldb/gdb
cargo +nightly fuzz run --debug fuzz_database_load fuzz/artifacts/fuzz_database_load/crash-abc123

# Minimize crash (find smallest input that triggers bug)
cargo +nightly fuzz cmin fuzz_database_load
cargo +nightly fuzz tmin fuzz_database_load fuzz/artifacts/fuzz_database_load/crash-abc123
```

---

## Advanced Fuzzing Techniques

### Structure-Aware Fuzzing

For matchy, we should fuzz with **valid-ish** database structures:

```rust
use arbitrary::Arbitrary;

#[derive(Arbitrary, Debug)]
struct FuzzDatabase {
    // Force fuzzer to create semi-valid structures
    magic: [u8; 8],  // Might be "PARAGLOB" or garbage
    version: u32,
    node_count: u32,
    // ... but still allow invalid offsets, sizes, etc
    nodes: Vec<u8>,
}

fuzz_target!(|db: FuzzDatabase| {
    let bytes = serialize_fuzz_db(&db);
    let _ = matchy::Database::from_bytes(bytes);
});
```

### Differential Fuzzing

Compare Rust vs C++ implementations:

```rust
fuzz_target!(|patterns: Vec<String>, text: String| {
    let rust_result = matchy_rust::match_patterns(&patterns, &text);
    let cpp_result = matchy_cpp::match_patterns(&patterns, &text);
    assert_eq!(rust_result, cpp_result, "Rust and C++ disagree!");
});
```

### Sanitizer Fuzzing

Run with sanitizers to catch more bugs:

```bash
# Address sanitizer (use-after-free, buffer overflows)
RUSTFLAGS="-Z sanitizer=address" cargo +nightly fuzz run fuzz_database_load

# Memory sanitizer (uninitialized memory)
RUSTFLAGS="-Z sanitizer=memory" cargo +nightly fuzz run fuzz_database_load

# Thread sanitizer (data races)
RUSTFLAGS="-Z sanitizer=thread" cargo +nightly fuzz run fuzz_database_load
```

### Corpus Management

Build a good starting corpus:

```bash
# Create seed corpus with valid databases
mkdir -p fuzz/corpus/fuzz_database_load
cp tests/data/*.mxy fuzz/corpus/fuzz_database_load/
cp examples/*.pgb fuzz/corpus/fuzz_database_load/

# Minimize corpus (remove redundant inputs)
cargo +nightly fuzz cmin fuzz_database_load

# Merge corpora from multiple runs
cargo +nightly fuzz cmin -O merged_corpus fuzz/corpus/*
```

---

## Property-Based Testing with proptest

For logic bugs (not crashes), use proptest:

```toml
# Cargo.toml
[dev-dependencies]
proptest = "1.4"
```

```rust
// tests/properties.rs
use proptest::prelude::*;

proptest! {
    // Test 1: IP parsing should never panic
    #[test]
    fn ip_parsing_never_panics(
        a in 0u8..=255,
        b in 0u8..=255,
        c in 0u8..=255,
        d in 0u8..=255,
    ) {
        let ip = format!("{}.{}.{}.{}", a, b, c, d);
        let result = db.lookup(&ip);
        // Should return Ok(Some(...)) or Ok(None), never panic
        assert!(result.is_ok());
    }

    // Test 2: Glob matching should be symmetric
    #[test]
    fn glob_matching_properties(pattern in "[a-z*?]{1,20}") {
        let pg = ParaglobBuilder::new()
            .add_pattern(&pattern)
            .build()
            .unwrap();
        
        // Property: If pattern matches itself (no wildcards), it should always match
        if !pattern.contains('*') && !pattern.contains('?') {
            assert!(pg.is_match(&pattern));
        }
    }

    // Test 3: Database roundtrip
    #[test]
    fn database_roundtrip(patterns in prop::collection::vec(".*", 1..100)) {
        let mut builder = DatabaseBuilder::new();
        for pattern in &patterns {
            builder.add_entry(pattern, json!({"test": true}));
        }
        
        let bytes = builder.build().unwrap();
        let db = Database::from_bytes(bytes).unwrap();
        
        // All patterns should be findable
        for pattern in &patterns {
            let result = db.lookup(pattern).unwrap();
            assert!(result.is_some(), "Pattern {} not found after roundtrip", pattern);
        }
    }
}
```

Run with:
```bash
cargo test --test properties
```

---

## CI/CD Integration

### GitHub Actions

```yaml
# .github/workflows/fuzz.yml
name: Fuzzing

on:
  schedule:
    - cron: '0 0 * * *'  # Daily at midnight
  workflow_dispatch:      # Manual trigger

jobs:
  fuzz:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Install Rust nightly
        uses: dtolnay/rust-toolchain@nightly
      
      - name: Install cargo-fuzz
        run: cargo install cargo-fuzz
      
      - name: Restore corpus
        uses: actions/cache@v3
        with:
          path: fuzz/corpus
          key: fuzz-corpus-${{ github.sha }}
          restore-keys: fuzz-corpus-
      
      - name: Run fuzzing (1 hour)
        run: |
          cargo fuzz run fuzz_database_load -- -max_total_time=3600 || true
          cargo fuzz run fuzz_paraglob -- -max_total_time=3600 || true
      
      - name: Check for crashes
        run: |
          if [ -d fuzz/artifacts ]; then
            echo "::error::Fuzzing found crashes!"
            ls -la fuzz/artifacts/
            exit 1
          fi
      
      - name: Save corpus
        uses: actions/cache@v3
        with:
          path: fuzz/corpus
          key: fuzz-corpus-${{ github.sha }}
```

### OSS-Fuzz Integration

For continuous fuzzing at scale, join Google's OSS-Fuzz:

```bash
# https://github.com/google/oss-fuzz
# Free continuous fuzzing for open source projects
# 30+ CPU cores, 24/7 fuzzing
# Automatic bug reports
```

---

## What to Fuzz in matchy

### Priority 1: Safety Issues (Can cause crashes/UB)

1. **Database loading** - Most critical!
   - Malformed MMDB headers
   - Invalid offsets
   - Truncated files
   - Overlapping sections

2. **Pattern parsing**
   - Invalid UTF-8 (especially in trusted mode!)
   - Malformed glob patterns
   - AC automaton edge cases

3. **Memory-mapped file access**
   - Out-of-bounds offsets
   - Alignment issues
   - Invalid struct layouts

### Priority 2: Logic Bugs

4. **Pattern matching correctness**
   - Glob wildcards (*, ?, [])
   - Case sensitivity
   - Unicode handling

5. **IP lookup correctness**
   - CIDR ranges
   - IPv4 vs IPv6
   - Prefix length edge cases

### Priority 3: Performance Issues

6. **Denial of service**
   - Exponential backtracking in patterns
   - Hash collision attacks
   - Large input handling

---

## Expected Bugs Fuzzing Will Find

Based on the unsafe code analysis, fuzzing will likely find:

### High Probability

1. **Alignment violations** (if `read_struct` isn't fixed)
   - Crash on ARM/RISC-V
   - Miri/ASan will catch immediately

2. **Out-of-bounds reads** in offset-based access
   - Invalid offsets in headers
   - Buffer overruns in string reading

3. **Invalid UTF-8 in trusted mode**
   - UB from `read_str_unchecked`
   - Should only happen with malicious databases

### Medium Probability

4. **Integer overflows** in size calculations
   - `offset + length` overflow
   - Multiplication overflow in array indexing

5. **Panic-inducing inputs**
   - Unwrap on None/Err in parsing
   - Array index out of bounds

### Low Probability (but still worth testing)

6. **Hash collision exploits**
   - Crafted inputs causing O(n²) behavior
   - AC literal hash table degradation

7. **Memory exhaustion**
   - Huge reported sizes causing OOM
   - Recursive structures

---

## Practical Fuzzing Workflow for matchy

### Day 1: Setup

```bash
# 30 minutes
cargo install cargo-fuzz
cargo fuzz init
# Create 3-4 fuzz targets
# Run quick smoke tests
```

### Week 1: Initial Campaign

```bash
# Run overnight, check in morning
cargo +nightly fuzz run fuzz_database_load -- -max_total_time=28800 &

# Next night
cargo +nightly fuzz run fuzz_paraglob -- -max_total_time=28800 &
```

### Ongoing: Continuous Fuzzing

```bash
# Add to CI (1 hour per run)
# Add to pre-commit (1 minute smoke test)
# Keep corpus in git-lfs or cache
```

### When Bugs Found

```bash
# 1. Minimize
cargo +nightly fuzz tmin fuzz_database_load crash-abc123

# 2. Convert to unit test
cp fuzz/artifacts/.../crash-abc123 tests/data/regression_crash_abc123.bin

# 3. Add regression test
#[test]
fn test_regression_crash_abc123() {
    let data = include_bytes!("data/regression_crash_abc123.bin");
    let result = Database::from_bytes(data.to_vec());
    // Should not crash/panic
    assert!(result.is_err());
}

# 4. Fix bug
# 5. Verify fix
cargo +nightly fuzz run fuzz_database_load crash-abc123
```

---

## Resources

### Documentation
- cargo-fuzz book: https://rust-fuzz.github.io/book/
- Rust Fuzzing Authority: https://github.com/rust-fuzz
- libFuzzer docs: https://llvm.org/docs/LibFuzzer.html

### Examples
- Fuzzing real projects: https://github.com/rust-fuzz/trophy-case
- Fuzzing patterns: https://github.com/rust-fuzz/cargo-fuzz/tree/main/example

### Tools
- cargo-fuzz: https://github.com/rust-fuzz/cargo-fuzz
- proptest: https://github.com/proptest-rs/proptest
- arbitrary: https://github.com/rust-fuzz/arbitrary

---

## Conclusion

**For matchy, I recommend:**

1. **Start with cargo-fuzz** (easiest, most effective)
   - Set up 3-4 targets this week
   - Run overnight campaigns
   - Expected: Find 2-5 bugs in first week

2. **Add proptest** for logic testing
   - Test glob matching properties
   - Test IP parsing invariants
   - Runs on stable Rust, integrates with `cargo test`

3. **Consider AFL for long-term**
   - Once initial bugs are fixed
   - For CI/CD continuous fuzzing
   - Multi-core parallel fuzzing

**Time investment:**
- Setup: 1-2 hours
- First campaign: Overnight (8 hours)
- Bug fixing: 1-2 days per bug found
- Ongoing: Minimal (automated in CI)

**Expected value:**
- High probability of finding 5-10 real bugs
- Especially alignment and bounds-checking issues
- Prevents security vulnerabilities
- Builds confidence in unsafe code

Want me to create a working fuzz target you can try right now?
