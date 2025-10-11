# Hybrid Lookup Architecture Proposal

## Problem
Building Aho-Corasick automaton for 424K patterns takes ~16-18 seconds.
Most patterns are **literal strings** (not globs), which don't need AC.

## Solution: Three-Tier Lookup

```
Query Input
    ↓
┌─────────────┐
│ Is it IP?   │ → Yes → IP Tree Lookup (existing)
└─────────────┘
    ↓ No
┌─────────────┐
│ Is literal? │ → Yes → Hash Table Lookup (NEW!)
└─────────────┘
    ↓ No (has *, ?, [)
┌─────────────┐
│ Has globs?  │ → Yes → Aho-Corasick/Paraglob (existing)
└─────────────┘
```

## Database Format

```
[IP Tree Section]          (existing)
[16-byte separator]        (existing)
[Data Section]             (existing - shared by all)
[MMDB_PATTERN marker]      (existing)
[Paraglob Section]         (existing - only for globs now)
[MMDB_LITERAL marker]      (NEW!)
[Literal Hash Section]     (NEW!)
[Metadata]                 (existing)
```

## Literal Hash Section Format

### Option A: Perfect Hash (Recommended)

```rust
struct LiteralHashSection {
    magic: [u8; 4],              // "LHSH"
    version: u32,                 // 1
    entry_count: u32,             // Number of literal patterns
    
    // Perfect hash function parameters (minimal perfect hashing)
    hash_seed: u64,               // Seed for hash function
    table_size: u32,              // Size of hash table (slightly > entry_count)
    
    // Offset table: table_size entries
    // offsets[hash(key)] = pattern_id (or 0xFFFFFFFF for empty)
    offsets: [u32; table_size],
    
    // String pool
    strings_offset: u32,          // Where strings start
    strings_size: u32,            // Total string data size
    
    // Strings stored as: [length: u16][bytes][null terminator]
    strings_data: [u8],
    
    // Pattern ID to data offset mapping (same as existing pattern section)
    pattern_count: u32,
    pattern_mappings: [(pattern_id: u32, data_offset: u32)],
}
```

**Size for 424K literals:**
- Magic + metadata: ~40 bytes
- Hash table: 424K * 4 bytes = ~1.7 MB
- String pool: ~424K * 40 bytes avg = ~17 MB
- Mappings: 424K * 8 bytes = ~3.4 MB
- **Total: ~22 MB** (vs 1.1 GB for full Paraglob!)

### Option B: FxHash with Linear Probing

```rust
struct LiteralHashEntry {
    hash: u64,           // Full hash for verification
    key_offset: u32,     // Offset into string pool
    pattern_id: u32,     // Pattern ID for data lookup
}

// Table is 125% of entry count to keep load factor < 0.8
```

## Build Algorithm

```rust
fn build(&self) -> Result<Vec<u8>> {
    let mut literals = Vec::new();
    let mut globs = Vec::new();
    
    // Classify patterns
    for pattern in &self.patterns {
        if has_wildcards(pattern) {
            globs.push(pattern);
        } else {
            literals.push(pattern);
        }
    }
    
    // Build literal hash table (fast!)
    let literal_section = if !literals.is_empty() {
        build_perfect_hash(&literals)?  // Takes ~0.5 seconds for 424K
    } else {
        Vec::new()
    };
    
    // Build AC automaton only for globs (fast if few!)
    let paraglob_section = if !globs.is_empty() {
        build_paraglob(&globs)?
    } else {
        Vec::new()
    };
    
    // Assemble...
}
```

## Lookup Algorithm

```rust
fn lookup(&self, query: &str) -> Result<Option<Match>> {
    // 1. Try IP lookup
    if let Ok(ip) = query.parse::<IpAddr>() {
        return self.lookup_ip(ip);
    }
    
    // 2. Try literal hash lookup (O(1), very fast)
    if let Some(pattern_id) = self.literal_hash.get(query) {
        return Ok(Some(self.get_pattern_data(pattern_id)));
    }
    
    // 3. Fall back to glob matching (only if needed)
    self.paraglob.find_matches(query)
}
```

## Performance Estimates

### Build Time
- **Before**: 424K patterns → AC automaton = ~18 seconds
- **After**: 
  - 420K literals → Perfect hash = ~0.5 seconds
  - 4K globs → AC automaton = ~0.5 seconds
  - **Total: ~1 second** (18x speedup!)

### Query Time
- **Literal queries**: O(1) hash lookup vs O(query_length) AC scan
  - **~10-100x faster** for exact matches
  
### Memory
- **Before**: 1.1 GB database
- **After**: ~22 MB literals + ~50 MB globs = ~72 MB (15x smaller!)

## Implementation Libraries

### Perfect Hashing
- `boomphf` - Minimal perfect hash functions
- `phf` - Perfect hash function (compile-time, but has runtime builder)
- `mphf` - Minimal perfect hash, good for large datasets

### Standard Hash (Fallback)
- `rustc-hash` (FxHash) - Fast, non-cryptographic
- Custom implementation with linear probing

## Migration Path

1. **Phase 1**: Implement hybrid builder (2-3 days)
   - Separate literals from globs
   - Build perfect hash for literals
   - Update lookup logic
   
2. **Phase 2**: Optimize perfect hash (1 day)
   - Tune parameters
   - Add benchmarks
   
3. **Phase 3**: Update CLI (1 day)
   - Show split statistics
   - Add option to force AC for all

## Questions to Resolve

1. **Hash function choice**: FxHash vs SipHash vs custom?
   - FxHash is faster but non-cryptographic
   - For threat intel, doesn't matter
   
2. **Collision handling**: Perfect hash vs probing?
   - Perfect hash is better for this use case
   
3. **String storage**: Deduplicate identical strings?
   - Probably not worth the complexity

## Compatibility

- **Backward compatible**: Old databases still work
- **Forward compatible**: Add new section with marker
- **Fallback**: If literal section missing, use Paraglob for all

## Testing Strategy

1. Unit tests for perfect hash implementation
2. Property tests: hash(key) always finds key
3. Benchmark against existing implementation
4. Fuzz test with malicious inputs
5. Memory profile with large datasets

