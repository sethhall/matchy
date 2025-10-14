# Entry Types

Matchy supports four types of [*entries*][def-entry], automatically detected based on
the format of the key.

## IP Addresses

**Format**: Standard IPv4 or IPv6 address notation

**Examples**:
- `192.0.2.1`
- `2001:db8::1`
- `10.0.0.1`

**Matching**: Exact IP address only

```
Entry: 192.0.2.1
Matches: 192.0.2.1
Doesn't match: 192.0.2.2, 192.0.2.0
```

**Use cases**:
- Known malicious IPs
- Specific hosts
- Allowlist/blocklist

## CIDR Ranges

**Format**: IP address with subnet mask (slash notation)

**Examples**:
- `10.0.0.0/8`
- `192.168.0.0/16`
- `2001:db8::/32`

**Matching**: All IP addresses within the range

```
Entry: 10.0.0.0/8
Matches: 10.0.0.1, 10.255.255.255, 10.123.45.67
Doesn't match: 11.0.0.1, 9.255.255.255
```

The number after the slash indicates how many bits are fixed:
- `/8` - First 8 bits fixed (~16.7 million addresses)
- `/16` - First 16 bits fixed (~65,000 addresses)
- `/24` - First 24 bits fixed (256 addresses)
- `/32` - All 32 bits fixed (single address, equivalent to IP entry)

**Use cases**:
- Network blocks
- Organization IP ranges
- Geographic regions
- Cloud provider ranges

**Best practice**: Use CIDR ranges instead of individual IPs when possible. It's more
efficient than adding thousands of individual IP addresses.

## Patterns (Globs)

**Format**: String containing wildcard characters (`*` or `?`)

**Examples**:
- `*.example.com`
- `test-*.domain.com`
- `http://*/admin/*`

**Matching**: Strings matching the glob pattern

```
Entry: *.example.com
Matches: foo.example.com, bar.example.com, sub.domain.example.com
Doesn't match: example.com, example.com.foo
```

**Wildcard rules**:
- `*` - Matches zero or more of any character
- `?` - Matches exactly one character
- `[abc]` - Matches one character from the set
- `[!abc]` - Matches one character NOT in the set

See [Pattern Matching](patterns.md) for complete syntax details.

**Use cases**:
- Domain wildcards (malware families)
- URL patterns
- Flexible matching rules
- Category-based blocking

**Performance**: Pattern matching uses the Aho-Corasick algorithm, which searches for
all patterns simultaneously. Query time is roughly constant regardless of the number
of patterns (within reason).

## Exact Strings

**Format**: Any string without wildcard characters and not an IP/CIDR

**Examples**:
- `example.com`
- `malicious-site.net`
- `test-string-123`

**Matching**: Exact string only (case-sensitive or insensitive based on match mode)

```
Entry: example.com
Matches: example.com (case-insensitive mode: Example.com, EXAMPLE.COM)
Doesn't match: foo.example.com, example.com/path
```

**Use cases**:
- Known malicious domains
- Exact matches
- High-confidence indicators
- Allowlists

**Performance**: Exact strings use hash table lookups (O(1) constant time), making
them the fastest entry type.

## Auto-Detection

Matchy automatically determines the entry type:

```
Input                    Detected As
─────────────────────   ─────────────
192.0.2.1                IP Address
10.0.0.0/8               CIDR Range
*.example.com            Pattern
example.com              Exact String
test-*                   Pattern
test.com                 Exact String
```

You don't need to specify the type - Matchy infers it from the format.

## Explicit Type Control (Prefix Technique)

Sometimes auto-detection doesn't match your intent. Use **type prefixes** to force a
specific entry type:

### Available Prefixes

| Prefix | Type | Description |
|--------|------|-------------|
| `literal:` | Exact String | Force exact match (no wildcards) |
| `glob:` | Pattern | Force glob pattern matching |
| `ip:` | IP/CIDR | Force IP address parsing |

### Why Use Prefixes?

**Problem 1: Literal strings that look like patterns**

Some strings contain characters like `*`, `?`, or `[` that should be matched literally,
not as wildcards:

```
Without prefix:
  file*.txt → Detected as pattern (matches file123.txt, fileabc.txt)
  
With prefix:
  literal:file*.txt → Exact match only (matches "file*.txt" literally)
```

**Problem 2: Patterns without wildcards**

You might want to match a string as a pattern for consistency, even without wildcards:

```
Without prefix:
  example.com → Detected as exact string
  
With prefix:
  glob:example.com → Treated as pattern (useful for batch processing)
```

**Problem 3: Ambiguous IP-like strings**

Force IP parsing when needed:

```
With prefix:
  ip:192.168.1.1 → Explicitly parsed as IP
```

### Usage Examples

**Text file input:**
```text
# Auto-detected
192.0.2.1
*.evil.com
malware.com

# Explicit control
literal:*.not-a-glob.com
glob:no-wildcards.com
ip:10.0.0.1
```

**CSV input:**
```csv
entry,category
literal:test[1].txt,filesystem
glob:*.example.com,pattern
ip:192.168.1.0/24,network
```

**JSON input:**
```json
[
  {"key": "literal:file[backup].tar", "data": {"type": "archive"}},
  {"key": "glob:*.example.*", "data": {"category": "domain"}},
  {"key": "ip:10.0.0.0/8", "data": {"range": "private"}}
]
```

**Rust API:**
```rust
use matchy::{DatabaseBuilder, MatchMode};
use std::collections::HashMap;

let mut builder = DatabaseBuilder::new(MatchMode::CaseSensitive);

// Auto-detection handles most cases
builder.add_entry("*.example.com", HashMap::new())?;

// Use prefixes when needed
builder.add_entry("literal:file*.txt", HashMap::new())?;
builder.add_entry("glob:simple-string", HashMap::new())?;
```

### Prefix Stripping

The prefix is **automatically stripped** before processing:

```
Input:        literal:*.example.com
Stored as:    *.example.com (as exact string)
Matches:      Only the exact string "*.example.com"

Input:        glob:test.com  
Stored as:    test.com (as pattern)
Matches:      Strings matching pattern "test.com"
```

### Validation

Prefixes enforce validation:

```bash
# This will fail - invalid glob syntax
glob:[unclosed-bracket

# This will fail - invalid IP address
ip:not-an-ip-address

# literal: accepts anything (no validation)
literal:[any$pecial*chars]
```

### When to Use

**Use prefixes when:**
- ✅ String contains `*`, `?`, or `[` that should be matched literally
- ✅ Processing mixed data where type is known externally
- ✅ Building programmatically from heterogeneous sources
- ✅ Debugging auto-detection issues

**Don't use prefixes when:**
- ❌ Auto-detection works correctly (most cases)
- ❌ All entries are the same type (use format-specific method instead)
- ❌ Creating database manually (use `add_ip()`, `add_literal()`, `add_glob()` methods)

### API Alternatives

Instead of using prefixes with `add_entry()`, you can call type-specific methods:

**Rust API:**
```rust
// Using prefix
builder.add_entry("literal:*.txt", data)?;

// Using explicit method (preferred in Rust)
builder.add_literal("*.txt", data)?;
```

**Available methods:**
- `builder.add_ip(key, data)` - Force IP/CIDR
- `builder.add_literal(key, data)` - Force exact string
- `builder.add_glob(key, data)` - Force pattern
- `builder.add_entry(key, data)` - Auto-detect (with prefix support)

See [DatabaseBuilder API](../reference/database-builder.md) for details.

## Match Precedence

When querying, Matchy checks in this order:

1. **IP address** - If the query is a valid IP, search IP tree
2. **Exact string** - Check hash table for exact match
3. **Patterns** - Search for matching patterns

This means:
- IP queries are fastest (binary tree lookup)
- Exact strings are next fastest (hash table lookup)
- Pattern queries search all patterns (Aho-Corasick)

## Multiple Matches

A query can match multiple entries:

**Example**:
```
Entries:
- *.com
- *.example.com
- evil.example.com

Query: evil.example.com
Matches: All three patterns!
```

Matchy returns **all matching entries** for pattern queries. This lets you apply
multiple rules or categories to a single query.

## Combining Entry Types

A single database can contain all entry types:

```
Database contents:
- 192.0.2.1 (IP)
- 10.0.0.0/8 (CIDR)
- *.evil.com (pattern)
- malware.com (exact string)

Query 192.0.2.1 → IP match
Query 10.5.5.5 → CIDR match
Query phishing.evil.com → Pattern match
Query malware.com → Exact match
```

This makes Matchy databases very versatile.

## Entry Limits

Practical limits (depends on available memory):
- **IP addresses**: Millions
- **CIDR ranges**: Millions
- **Patterns**: Tens of thousands (automaton size grows)
- **Exact strings**: Millions

Performance degrades gracefully as databases grow. Most applications use thousands to
tens of thousands of entries.

## Examples by Tool

**Adding entries:**
- [CLI: CSV format](../getting-started/cli-first-database.md#create-input-data)
- [Rust API: add_entry method](../getting-started/api-rust-first.md#adding-entries)
- [C API: matchy_builder_add](../getting-started/api-c-first.md#add-entries)

**Querying entries:**
- [CLI: matchy query](../commands/matchy-query.md)
- [Rust API: Database::lookup](../reference/database-query.md)
- [C API: matchy_query](../reference/c-querying.md)

## Next Steps

- [Pattern Matching](patterns.md) - Glob syntax and advanced patterns
- [Data Types and Values](data-types.md) - Storing data with entries
- [Performance Considerations](performance.md) - Optimizing for your use case

[def-entry]: ../appendix/glossary.md#entry '"entry" (glossary entry)'
