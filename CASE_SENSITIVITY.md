# Case Sensitivity in Matchy

This document explains how case sensitivity works across the different matching systems in matchy.

## Overview

Matchy supports both **case-sensitive** (default) and **case-insensitive** matching for string patterns. The matching mode is set when building the database and applies to both glob patterns and literal strings.

## CLI Usage

### Building Databases

By default, databases use **case-sensitive** matching:

```bash
# Case-sensitive (default)
matchy build input.txt -o database.mxy
```

To create a case-insensitive database, use the `-i` or `--case-insensitive` flag:

```bash
# Case-insensitive
matchy build input.txt -o database.mxy --case-insensitive
```

### Querying Databases

The matching mode is embedded in the database file, so queries automatically use the mode that was specified during build. There's no need to specify case sensitivity when querying.

```bash
# Automatically uses the mode from the database
matchy query database.mxy "TEST.example.com"
```

## How Case Insensitivity Works

### Glob Patterns (Aho-Corasick Automaton)

The Aho-Corasick (AC) automaton handles case insensitivity by:

1. **During Build**: Patterns are normalized to lowercase before being added to the automaton
   ```rust
   let normalized = match self.mode {
       MatchMode::CaseSensitive => pattern.as_bytes().to_vec(),
       MatchMode::CaseInsensitive => pattern.to_lowercase().into_bytes(),
   };
   ```

2. **During Query**: Query text is also normalized to lowercase before matching
   ```rust
   let normalized = match self.mode {
       MatchMode::CaseSensitive => text.as_bytes().to_vec(),
       MatchMode::CaseInsensitive => text.to_lowercase().into_bytes(),
   };
   ```

This approach works for **all glob features**:
- Wildcards: `*.EXAMPLE.COM` matches `test.example.com`
- Character classes: `[A-Z]` matches `[a-z]` in case-insensitive mode
- Literals within patterns: Any literal text in the pattern

**Implementation**: See `src/ac_offset.rs` lines 103-104 (build) and 459-460 (query)

### Literal Strings (Hash Table)

The hash table for exact string matching **fully supports case insensitivity**:

1. **During Build**: Strings are normalized to lowercase if case-insensitive mode is enabled
2. **During Query**: Query strings are also normalized before hashing

**Implementation**: The hash table uses the same normalization strategy as the AC automaton:
```rust
// Builder (add_pattern)
let normalized = match self.mode {
    MatchMode::CaseSensitive => pattern,
    MatchMode::CaseInsensitive => pattern.to_lowercase(),
};

// Query (lookup)
let normalized_query = match self.mode {
    MatchMode::CaseSensitive => query.to_string(),
    MatchMode::CaseInsensitive => query.to_lowercase(),
};
```

**Result**: 
- ✅ **Glob patterns** are fully case-insensitive when the flag is set
- ✅ **Literal exact matches** are fully case-insensitive when the flag is set

### Character Classes in Patterns

When using case-insensitive mode with character classes:

```bash
# Pattern: file[0-9a-z].txt
# Case-insensitive mode

# Will match:
file5.txt
fileA.txt  # 'A' normalized to 'a', matches [a-z]
FILEA.TXT  # Everything normalized to lowercase
```

The entire pattern (including the parts outside character classes) is normalized, so case-insensitive matching applies uniformly.

## Implementation Details

### MatchMode Enum

The `MatchMode` enum is defined in `src/glob.rs`:

```rust
pub enum MatchMode {
    /// Case-sensitive matching
    CaseSensitive,
    /// Case-insensitive matching
    CaseInsensitive,
}
```

This enum is used by:
- `ACAutomaton` (Aho-Corasick for glob patterns)
- `GlobPattern` (individual pattern matching)
- `MmdbBuilder` (database construction)

### Normalization Strategy

Case-insensitive matching uses ASCII lowercase normalization:
- `to_lowercase()` for Rust strings
- `eq_ignore_ascii_case()` for comparisons

This works well for ASCII patterns (domain names, file paths, etc.) but note that Unicode case folding is more complex. The current implementation uses simple ASCII lowercase conversion.

## Examples

### Case-Sensitive Database (Default)

```bash
# Build
echo "*.Example.Com" > patterns.txt
matchy build patterns.txt -o case-sensitive.mxy

# Queries
matchy query case-sensitive.mxy "test.Example.Com"  # ✓ Matches
matchy query case-sensitive.mxy "test.example.com"  # ✗ No match
matchy query case-sensitive.mxy "test.EXAMPLE.COM"  # ✗ No match
```

### Case-Insensitive Database

```bash
# Build with -i flag
echo "*.Example.Com" > patterns.txt
matchy build patterns.txt -o case-insensitive.mxy -i

# Queries (all match because pattern and text are both normalized)
matchy query case-insensitive.mxy "test.Example.Com"  # ✓ Matches
matchy query case-insensitive.mxy "test.example.com"  # ✓ Matches
matchy query case-insensitive.mxy "test.EXAMPLE.COM"  # ✓ Matches
matchy query case-insensitive.mxy "TEST.EXAMPLE.COM"  # ✓ Matches
```

## Performance Considerations

Case-insensitive matching has minimal performance impact:

1. **Build Time**: Normalization happens once during database construction
2. **Query Time**: Single `to_lowercase()` call per query before matching
3. **Memory**: No additional memory required; patterns are stored in normalized form

The performance is nearly identical to case-sensitive matching since the AC automaton operates on the same number of states.

## Best Practices

1. **Choose the right mode for your use case**:
   - Domain names / URLs: Often case-insensitive
   - File paths: Depends on filesystem (Windows = insensitive, Linux = sensitive)
   - Threat intelligence: Usually case-insensitive for robustness

2. **Be consistent**: All patterns in a database use the same mode

3. **Document your choice**: Include the matching mode in your database type metadata:
   ```bash
   matchy build patterns.txt -o db.mxy -i \
       -t "ThreatIntel-CaseInsensitive" \
       -d "Threat indicators with case-insensitive matching"
   ```

4. **Inspect databases**: Use `matchy inspect` to check database properties, though currently the match mode is not displayed in the output (this could be a future enhancement)

## Future Enhancements

Potential improvements to case sensitivity handling:

1. ✅ **CLI flag for case-insensitive mode** - DONE!
2. ✅ **Store match mode in metadata** - DONE! (Stored as `match_mode` field: 0=CaseSensitive, 1=CaseInsensitive)
3. ✅ **Read match mode from metadata on load** - DONE! (Databases now remember their match mode)
4. ✅ **Case-insensitive literal hash matching** - DONE! (Normalizes strings at build and query time)
5. 📝 **Display match mode in `inspect` output** - Visible in verbose mode with `-v` flag
6. 📝 **Unicode case folding** - More sophisticated than ASCII lowercase (future enhancement)

## Code References

Key files for case sensitivity:
- `src/glob.rs` - MatchMode enum and GlobPattern matching (lines 45-50, 190-196)
- `src/ac_offset.rs` - AC automaton build/query normalization (lines 25-30, 103-104, 459-460)
- `src/bin/matchy.rs` - CLI flag handling (line 86-88, 446-450)
- `src/literal_hash.rs` - Hash table (currently case-sensitive only)

## Summary

| Component | Case Sensitivity Support | Method |
|-----------|-------------------------|--------|
| **Glob Patterns (AC)** | ✅ Full support | Pattern and query normalization |
| **Literal Hash** | ✅ Full support | Pattern and query normalization |
| **CLI** | ✅ `-i` flag | Sets MatchMode for builder |
| **Character Classes** | ✅ Works uniformly | Full pattern normalization |

**All components now fully support case-insensitive matching!** The implementation is consistent across all string databases.
