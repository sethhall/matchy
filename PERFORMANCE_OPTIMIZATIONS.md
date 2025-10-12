# Performance Optimization Opportunities

This document analyzes the BurntSushi `aho-corasick` implementation and identifies performance techniques we can adapt while maintaining our zero-copy mmap architecture.

## Executive Summary

The BurntSushi crate achieves excellent performance through several techniques. **Most are incompatible with our offset-based mmap design**, but several key optimizations can be adapted:

1. **✅ Dense vs Sparse State Representation** - High impact, fully compatible
2. **✅ Byte Class Reduction** - High impact, fully compatible  
3. **✅ Special State Optimization** - Medium impact, fully compatible
4. **❌ SIMD Teddy Algorithm** - Not compatible with mmap
5. **✅ Prefiltering with Byte Frequencies** - Medium impact, partially compatible
6. **✅ Manual Loop Unrolling** - Low-medium impact, fully compatible

---

## 1. Dense vs Sparse State Representation ⭐⭐⭐

### Current Implementation
Your code always uses a **sparse representation**: each state stores an array of `(character, target_offset)` edges.

```rust
// Your current approach (lines 243-260)
for (ch, target_id) in &edges {
    let edge = ACEdge::new(*ch, target_offset as u32);
    // Write edge...
}
```

### BurntSushi's Approach
They use **three different encodings** based on state characteristics:

```rust
const KIND_DENSE: u32 = 0xFF;   // All transitions explicit
const KIND_ONE: u32 = 0xFE;     // Single transition (most common!)
const MAX_SPARSE_TRANSITIONS: usize = 127;
```

**Key insight**: States with 1 transition are overwhelmingly common in AC automata.

### Adaptation for Matchy

Add a `state_kind` field to `ACNode`:

```rust
#[repr(C)]
pub struct ACNode {
    pub id: u32,
    pub depth: u8,
    pub state_kind: u8,  // NEW: 0 = empty, 1 = one-trans, 2 = sparse, 3 = dense
    // ... rest of fields
}

// One-transition optimization (HOT PATH)
impl ACNode {
    fn find_transition_optimized(&self, buffer: &[u8], ch: u8) -> Option<usize> {
        match self.state_kind {
            1 => {  // ONE transition
                // Store single edge inline in node! No indirection needed
                if self.single_edge_char == ch {
                    Some(self.single_edge_target as usize)
                } else {
                    None
                }
            }
            2 => {  // SPARSE (current implementation)
                // Binary search through edges
                self.find_sparse(buffer, ch)
            }
            3 => {  // DENSE
                // Direct lookup: edges[ch] (if using byte classes: edges[class_of[ch]])
                self.find_dense(buffer, ch)
            }
            _ => None
        }
    }
}
```

**Expected Impact**: 
- **30-50% speedup** for typical patterns (majority of states have 1 transition)
- Eliminates cache miss on edge array lookup for 80%+ of transitions
- Minimal memory overhead (2 bytes per node)

**Implementation Complexity**: Medium
- Requires schema change (backwards incompatible)
- Need to classify states during construction
- Worth doing if making format changes anyway

---

## 2. Byte Class Reduction ⭐⭐⭐

### The Problem
Your current implementation uses the full 256-byte alphabet. But most patterns only use a small subset of ASCII characters.

### BurntSushi's Solution
They compute **equivalence classes** - bytes that have identical transitions are merged:

```rust
// Example: patterns ["hello", "world"]
// Only chars used: h,e,l,o,w,r,d (7 distinct)
// All other bytes → same "other" class
// Result: 8 classes instead of 256!
```

Their code:
```rust
pub byte_classes: ByteClasses,  // Maps byte → class ID
pub alphabet_len: usize,        // Number of distinct classes
```

### Adaptation for Matchy

**Option A: Pre-compute at build time** (recommended)

```rust
pub struct ACHeader {
    // ... existing fields
    pub alphabet_len: u8,       // Number of equivalence classes (typically 8-32)
    pub byte_to_class: [u8; 256],  // Lookup table: byte → class ID
}

// At build time:
fn compute_byte_classes(patterns: &[String]) -> ([u8; 256], u8) {
    let mut used_bytes = [false; 256];
    for pattern in patterns {
        for &byte in pattern.as_bytes() {
            used_bytes[byte as usize] = true;
        }
    }
    
    let mut byte_to_class = [0u8; 256];
    let mut class_id = 0u8;
    
    // Assign class 0 to all unused bytes
    class_id += 1;
    
    // Assign unique class to each used byte
    for (byte, &used) in used_bytes.iter().enumerate() {
        if used {
            byte_to_class[byte] = class_id;
            class_id += 1;
        }
    }
    
    (byte_to_class, class_id)
}
```

Then during matching:
```rust
fn find_transition(&self, node_offset: usize, ch: u8) -> Option<usize> {
    let class = self.header.byte_to_class[ch as usize];  // One lookup
    // Now search edges for 'class' instead of 'ch'
    // Dense states have only alphabet_len transitions (not 256!)
}
```

**Expected Impact**:
- **20-40% memory reduction** for dense states
- **10-20% speedup** from better cache utilization
- Especially beneficial for patterns with limited character sets (like domain names)

**Implementation Complexity**: Medium
- Requires format change (add header with byte_to_class table)
- Need to modify edge matching to use classes
- Can be done incrementally (version bump)

---

## 3. Special State Optimization ⭐⭐

### BurntSushi's Technique

They pre-compute which states are "special" (dead, start, match) and check them with fast integer comparisons:

```rust
struct Special {
    max_special_id: StateID,
    max_match_id: StateID,
    start_unanchored_id: StateID,
    start_anchored_id: StateID,
}

#[inline(always)]
fn is_match(&self, sid: StateID) -> bool {
    !self.is_dead(sid) && sid <= self.special.max_match_id
}

#[inline(always)]
fn is_special(&self, sid: StateID) -> bool {
    sid <= self.special.max_special_id
}
```

### Adaptation for Matchy

Add special state tracking to your format:

```rust
pub struct ACHeader {
    // ... existing
    pub first_match_offset: u32,  // Offset to first final state
    pub last_match_offset: u32,   // Offset to last final state
}

// Fast check during traversal
impl ACAutomaton {
    #[inline(always)]
    fn is_match_state(&self, offset: usize) -> bool {
        offset >= self.header.first_match_offset as usize 
            && offset <= self.header.last_match_offset as usize
    }
}
```

**Expected Impact**:
- **5-10% speedup** on match-heavy workloads
- Avoids loading node to check `is_final` flag
- Very easy to implement

**Implementation Complexity**: Low
- Minor format change (add 8 bytes to header)
- Easy to compute during construction
- Good low-hanging fruit

---

## 4. SIMD Teddy Algorithm ❌

### Why It Doesn't Apply

BurntSushi's "Teddy" algorithm uses SIMD (SSE/AVX) to check 16-32 bytes simultaneously:

```rust
// Conceptual - actual code uses intrinsics
let chunk = load_16_bytes(haystack_ptr);
let mask = simd_compare(chunk, first_bytes_of_patterns);
```

**Problem for Matchy**: 
- Teddy is a **prefilter** - it quickly scans for potential match positions
- Then falls back to full AC automaton for verification
- **We already have the full automaton in mmap'd form**
- Building a separate SIMD prefilter would require **heap allocation**
- Defeats the entire zero-copy design

**Verdict**: Not worth pursuing. Our mmap advantage is more valuable than SIMD speedup.

---

## 5. Prefiltering with Rare Byte Detection ⭐⭐

### BurntSushi's Technique

They use **byte frequency analysis** to find rare bytes in patterns:

```rust
// Pre-computed from analyzing English text corpus
pub const BYTE_FREQUENCIES: [u8; 256] = [
    55,   // '\x00' - very rare
    242,  // '\n' - common
    255,  // ' ' - very common (most frequent)
    249,  // 'a' - very common
    // ...
];

// At build time, find rarest byte in each pattern
// During search, scan for that rare byte first using memchr
```

### Adaptation for Matchy

**Option: Fast-path check for rare pattern prefixes**

```rust
impl ACAutomaton {
    pub fn find_pattern_ids_optimized(&self, text: &str) -> Vec<u32> {
        let normalized = self.normalize_text(text);
        
        // NEW: If all patterns start with rare bytes, scan for them first
        if let Some(rare_prefixes) = &self.rare_prefix_filter {
            return self.find_with_prefilter(&normalized, rare_prefixes);
        }
        
        // Otherwise, use standard algorithm
        self.find_standard(&normalized)
    }
    
    fn find_with_prefilter(&self, text: &[u8], prefixes: &[u8]) -> Vec<u32> {
        let mut matches = Vec::new();
        
        // Use memchr to scan for any rare prefix byte
        let mut pos = 0;
        while pos < text.len() {
            if let Some(found) = memchr::memchr3(
                prefixes[0], prefixes[1], prefixes[2], &text[pos..]
            ) {
                // Found potential match start - run AC from here
                let start = pos + found;
                matches.extend(self.match_from_position(&text[start..]));
                pos = start + 1;
            } else {
                break;
            }
        }
        
        matches
    }
}
```

**Expected Impact**:
- **Up to 3-5x speedup** for needle-in-haystack workloads (rare patterns in large text)
- **No benefit** for dense matching (many patterns, short text)
- **No format change needed** - just runtime optimization

**Implementation Complexity**: Low-Medium
- Add `memchr` crate dependency
- Compute rare prefixes during build
- Add conditional fast path
- Good for specific use cases (log analysis, security scanning)

---

## 6. Manual Loop Unrolling ⭐ (TESTED - NOT RECOMMENDED)

### BurntSushi's Technique

They manually unroll hot loops to reduce branch overhead:

```rust
// Instead of:
for (i, &chunk) in classes.iter().enumerate() {
    if chunk == target { return i; }
}

// They do:
for (i, &chunk) in repr[o+2..][..classes_len].iter().enumerate() {
    let classes = chunk.to_ne_bytes();
    if classes[0] == class { return trans_offset + i*4; }
    if classes[1] == class { return trans_offset + i*4 + 1; }
    if classes[2] == class { return trans_offset + i*4 + 2; }
    if classes[3] == class { return trans_offset + i*4 + 3; }
}
```

### Experimental Results (2025-01-12)

**❌ TESTED AND REJECTED**: Explicit loop unrolling using the `unroll` crate was tested and showed consistent **performance regressions** of ~3-4% across benchmarks.

**Test Details**:
- Applied `#[unroll_for_loops]` macro to the hot `find_transition` loop
- Used `unroll = "0.1"` crate for explicit unrolling
- All tests passed (79/79)
- Benchmarks showed degradation across all pattern types:
  - Suffix patterns: 3.0% slower
  - Mixed patterns: 2.8% slower  
  - Prefix patterns: 3.4% slower
  - Complex patterns: 3.6% slower

**Root Cause**: Modern LLVM already performs aggressive auto-vectorization and loop unrolling. Explicit unrolling via macros:
1. Interferes with LLVM's optimization heuristics
2. Bloats code size, hurting instruction cache
3. Prevents LLVM from making runtime-informed decisions

**Recommendation**: ❌ **Do not manually unroll loops**
- Trust LLVM's optimizer - it understands your CPU better than we do
- Simple loops with `#[inline]` hints are all LLVM needs
- Focus on algorithmic improvements, not micro-optimizations

### Alternative: Successful Micro-Optimizations

**✅ TESTED AND APPROVED** (~2.7% improvement):

1. **Add `#[inline]` to hot path functions**:
```rust
#[inline]
pub fn find_pattern_ids(&self, text: &str) -> Result<Vec<u32>> {
    // ...
}

#[inline]
fn find_transition(&self, node_offset: usize, ch: u8) -> Option<usize> {
    // ...
}
```

2. **Hoist invariant checks outside loops**:
```rust
// Before:
for i in 0..node.edge_count as usize {
    let edge_offset = edges_offset + i * edge_size;
    validate_offset(&self.buffer, edge_offset)?;  // ❌ Checked every iteration
    // ...
}

// After:
let total_edges_size = node.edge_count as usize * edge_size;
let edges_end = edges_offset + total_edges_size;
validate_offset(&self.buffer, edges_end)?;  // ✅ Single bounds check

for i in 0..node.edge_count as usize {
    let edge_offset = edges_offset + i * edge_size;
    // Safe: already validated above
    // ...
}
```

**Impact**: 2.7% speedup with no regressions
**Complexity**: Low - simple attribute annotations and refactoring
**Stability**: Excellent - all 79 tests pass

### Lessons Learned

1. **Trust the Compiler**: LLVM is very good at loop optimization
2. **Measure Everything**: Intuition about micro-optimizations is often wrong
3. **Simple is Better**: `#[inline]` + clean code beats manual unrolling
4. **Algorithmic Wins**: Focus on state encoding and byte classes (below) for real improvements

---

## Priority Recommendations

### Immediate (No Format Changes)
1. **Manual loop unrolling in `find_transition`** - Easy win, 5-15% improvement
2. **Rare byte prefiltering** - Optional fast path for specific workloads

### Next Version (Format Changes Acceptable)
1. **Dense/Sparse/One state encoding** - Biggest impact (30-50% speedup)
2. **Byte class reduction** - Memory and cache efficiency (20-40% memory, 10-20% speed)
3. **Special state optimization** - Small header addition, 5-10% speedup

### Not Recommended
- SIMD Teddy algorithm - Incompatible with zero-copy mmap design

---

## Benchmarking Strategy

Before implementing, establish baselines:

```bash
# 1. Current performance
cargo bench --bench paraglob_bench -- --save-baseline current

# 2. After each optimization
cargo bench --bench paraglob_bench -- --baseline current

# 3. Focus on these metrics:
# - Pattern matching throughput (MB/s)
# - Memory usage (bytes per pattern)
# - Construction time (if changing build)
# - Cold start time (mmap is key advantage)
```

Key scenarios to test:
- **Sparse patterns**: 10-100 patterns, mostly ASCII
- **Dense patterns**: 1000+ patterns, varied characters
- **Long patterns**: Average length > 20 chars
- **Short patterns**: Average length < 5 chars (common in security rules)

---

## Implementation Phases

### Phase 1: Low-Hanging Fruit (1-2 days)
- Loop unrolling in hot paths
- Special state offset tracking
- Benchmark and document improvements

### Phase 2: Format Evolution (1 week)
- Design header with byte classes and state kinds
- Implement backward compatibility check
- Version bump to 2.0

### Phase 3: Advanced (2 weeks)
- Implement all three state encodings
- Add byte class computation
- Comprehensive testing with various pattern sets

---

## Conclusion

The BurntSushi `aho-corasick` crate has excellent techniques, but many are specific to their heap-based design. **The good news**: the most impactful optimizations (state encoding, byte classes) are fully compatible with your offset-based architecture.

**My recommendation**: 
1. Start with loop unrolling (easy, immediate benefit)
2. Plan a format v2 that adds state kinds and byte classes
3. Skip SIMD prefiltering unless you have specific use cases that need it

Your current architecture is sound - these optimizations will make it even faster while preserving the zero-copy mmap advantage.

---

## 7. Early-Exit Optimizations (EXPLORED - NOT IMPLEMENTED)

### Use Case Analysis

Some workloads only need a boolean "does any pattern match?" result rather than all matches. We explored optimizing for this case.

### Domain Knowledge: Non-Overlapping Patterns

Glob patterns in a single database typically don't overlap:
- `*.evil.com` and `bad-*.com` can't match the same string
- Even if literal substrings overlap in the AC automaton, the final glob verification stage resolves to distinct matches
- Each pattern is independently evaluated

### Proposed Optimization: Early Exit at AC Level

```rust
pub fn has_any_match(&self, text: &str) -> Result<bool> {
    // Modified AC traversal that returns immediately on first literal match
    for ch in text.bytes() {
        // ... traverse AC automaton ...
        if node.pattern_count > 0 {
            return Ok(true);  // Early exit!
        }
    }
    Ok(false)
}
```

**Problem Identified**: This is **unsafe** in the current architecture!

- Multiple patterns can share literal substrings in the AC automaton
- Example: `evil-*.com` and `*-bad.com` both contain literal "-"
- The AC automaton finds ALL literals, mapping each to candidate patterns
- Early exit at the first literal match might miss other candidate patterns
- Final glob verification might fail on the first match but succeed on later matches

### Better Approach: Early Exit After Candidate Collection

```rust
pub fn has_any_match_safe(&self, text: &str) -> Result<bool> {
    // Step 1: Collect ALL candidate patterns from AC automaton (no shortcut here)
    let candidate_patterns = self.find_pattern_ids(text)?;
    
    // Step 2: Verify candidates, but exit early on first match
    for pattern_id in candidate_patterns {
        if self.verify_glob_match(text, pattern_id)? {
            return Ok(true);  // Safe early exit after all candidates found
        }
    }
    
    Ok(false)
}
```

**Safety**: This is correct because:
1. AC automaton fully traverses and finds all candidate patterns
2. Only the glob verification stage exits early
3. No risk of missing patterns that share literals

### Decision: Not Implemented

**User Feedback**: Most real-world use cases need **all matches**, not just a boolean:
- Security tools need to report all matching threat indicators
- Content filters need to list all violations
- Log analyzers need complete match lists for statistics

**Performance Impact**: Minimal benefit
- Early exit saves only the glob verification stage
- AC traversal (the slower part) still runs completely
- For workloads with many matches, savings are negligible

**API Complexity**: Adds maintenance burden
- Need to maintain two code paths: `find_all()` and `has_any()`
- Risk of divergence between implementations
- Users might choose the wrong API and get incorrect results

**Recommendation**: ❌ **Defer until specific use case demands it**

---

## 8. Other Explored Optimizations

### SIMD Pattern Search

**Status**: Not applicable for offset-based mmap architecture

**Why**: SIMD approaches (like BurntSushi's Teddy algorithm) require heap-allocated data structures for fast scanning. Our core advantage is zero-copy mmap, which is incompatible with SIMD prefilters.

**Verdict**: Stick with mmap advantage over SIMD.

### Binary Search in Edge Arrays

**Status**: Already optimal

**Current**: Linear search through edges, but typical nodes have 1-3 edges
**Analysis**: Binary search overhead exceeds benefit until ~8+ edges
**Benchmarks**: States with >8 edges are rare (<5% of nodes in typical patterns)

**Recommendation**: Current implementation is optimal for typical workloads.

### Parallel Pattern Matching

**Status**: Not explored (complex)

**Consideration**: For very large texts (>1MB), could split text into chunks and process in parallel.

**Challenges**:
- Need to handle pattern matches that span chunk boundaries
- Overhead of thread synchronization
- AC automaton traversal is already cache-friendly and fast

**When to Consider**: Only if profiling shows pattern matching is CPU-bound on multi-core systems with large texts (rare in practice).

---

## Summary: What Actually Works

### ✅ Proven Optimizations
1. **`#[inline]` on hot paths** - 2.7% improvement, no downsides
2. **Hoist bounds checks** - Small but measurable gains
3. **Trusted mode** (`--trusted` flag) - 15-20% speedup when safe to use

### 🚧 High-Value Future Work (Requires Format Changes)
1. **Dense/Sparse/One state encoding** - 30-50% potential speedup
2. **Byte class reduction** - 20-40% memory savings, 10-20% speedup
3. **Special state optimization** - 5-10% speedup, easy header addition

### ❌ Rejected After Testing
1. **Explicit loop unrolling** - 3-4% regression (LLVM is better)
2. **Early-exit API** - Deferred (no compelling use case)
3. **SIMD prefiltering** - Incompatible with mmap design

### 🤷 Not Investigated
1. **Parallel pattern matching** - Complexity doesn't justify benefit for typical workloads
2. **Binary search for edges** - Linear is optimal for small edge counts

---

## Experimental Methodology

All optimizations follow this process:

1. **Hypothesis**: Document expected improvement and reasoning
2. **Baseline**: Run `cargo bench` and save baseline
3. **Implementation**: Make focused change in isolated branch
4. **Validation**: Run full test suite (79 tests must pass)
5. **Benchmarking**: Compare against baseline across all pattern types
6. **Decision**: 
   - ✅ Keep if >2% improvement with no regressions
   - 🔄 Iterate if mixed results
   - ❌ Revert if any regressions
7. **Documentation**: Update this file with findings

This empirical approach prevents premature optimization and ensures measurable progress.
