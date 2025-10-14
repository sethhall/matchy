# Database Concepts

This chapter covers the fundamental concepts of Matchy [*databases*][def-database].

## What is a Database?

A Matchy database is a binary file containing:
- **Entries** - IP addresses, CIDR ranges, patterns, or exact strings
- **Data** - Structured information associated with each entry
- **Indexes** - Optimized data structures for fast lookups

Databases use the `.mxy` extension by convention, though any extension works.

## Immutability

Databases are **read-only** once built. You cannot add, remove, or modify entries in
an existing database.

To update a database:
1. Create a new builder
2. Add all entries (old + new + modified)
3. Build the new database
4. Atomically replace the old file

This ensures readers always see consistent state and enables safe concurrent access.

## Entry Types

Matchy automatically detects four types of [*entries*][def-entry]:

| Entry Type | Example | Matches |
|------------|---------|---------|
| **IP Address** | `192.0.2.1` | Exact IP address |
| **CIDR Range** | `10.0.0.0/8` | All IPs in range |
| **Pattern** | `*.example.com` | Strings matching glob |
| **Exact String** | `example.com` | Exact string only |

You don't need to specify the type - Matchy infers it from the format.

## Auto-Detection

When you query a database, Matchy automatically:
1. Checks if the query is an IP address → searches IP tree
2. Checks for exact string match → searches hash table
3. Searches patterns → uses Aho-Corasick algorithm

This makes querying simple: `db.lookup("anything")` works for all types.

## Memory Mapping

Databases use [*memory mapping*][def-mmap] (mmap) for instant loading:

```
Traditional Database          Matchy Database
─────────────────────        ─────────────────
1. Open file                 1. Open file
2. Read into memory          2. Memory map
3. Parse format              3. Done! (<1ms)
4. Build data structures
   (100-500ms for large DB)
```

Memory mapping has several benefits:

**Instant loading** - Databases load in under 1 millisecond regardless of size.

**Shared memory** - The OS shares memory-mapped pages across processes automatically:
- 64 processes with a 100MB database = ~100MB RAM total
- Traditional approach = 64 × 100MB = 6,400MB RAM

**Large databases** - Work with databases larger than available RAM. The OS pages data
in and out as needed.

## Binary Format

Databases use a compact binary format based on [MaxMind's MMDB specification][mmdb]:

- **IP tree** - Binary trie for IP address lookups (MMDB compatible)
- **Hash table** - For exact string matches (Matchy extension)
- **Aho-Corasick automaton** - For pattern matching (Matchy extension)  
- **Data section** - Structured data storage (MMDB compatible)

This means:
- Standard MMDB readers can read the IP portion
- Matchy can read standard MMDB files (like GeoIP databases)
- Cross-platform compatible (same file works on Linux, macOS, Windows)

## Building a Database

The general workflow is:

1. **Create a builder** - Specify [*match mode*][def-match-mode] (case-sensitive or not)
2. **Add entries** - Add IP addresses, patterns, strings with associated data
3. **Build** - Generate optimized binary format
4. **Save** - Write to file

**How to build:**
- [Using the CLI](../getting-started/cli-first-database.md#build-the-database)
- [Using the Rust API](../getting-started/api-rust-first.md#build-the-database)
- [Using the C API](../getting-started/api-c-first.md#save-the-database)

## Querying a Database

The query process:

1. **Open database** - Memory map the file
2. **Query** - Call lookup with any string
3. **Get result** - Receive match data or None

**How to query:**
- [Using the CLI](../getting-started/cli-first-database.md#query-the-database)
- [Using the Rust API](../getting-started/api-rust-first.md#open-and-query)
- [Using the C API](../getting-started/api-c-first.md#open-and-query)

## Query Results

Queries return one of:

- **IP match** - IP address or CIDR range matched
- **Pattern match** - One or more patterns matched
- **Exact match** - Exact string matched
- **No match** - No entries matched

For pattern matches, Matchy returns **all matching patterns** and their associated data.
This is useful when multiple patterns match (e.g., `*.com` and `example.*` both match
`example.com`).

## Database Size

Database size depends on:
- Number of entries
- Pattern complexity (more patterns = larger automaton)
- Data size (structured data per entry)

Typical sizes:
- **1,000 entries** - ~50-100KB
- **10,000 entries** - ~500KB-1MB
- **100,000 entries** - ~5-10MB
- **1,000,000 entries** - ~50-100MB

Pattern-heavy databases are larger due to the Aho-Corasick automaton.

## Thread Safety

Databases are **thread-safe for concurrent queries**:
- Multiple threads can safely query the same database
- Memory-mapped data is read-only
- No locking required

Builders are **NOT thread-safe**:
- Don't share a builder across threads
- Build databases sequentially

## Compatibility

Databases are:
- ✅ **Platform-independent** - Same file on Linux, macOS, Windows
- ✅ **Tool-independent** - CLI-built databases work with APIs
- ✅ **Language-independent** - Rust-built databases work with C
- ✅ **MMDB-compatible** - Can read standard MaxMind databases

## Next Steps

Now that you understand database concepts, dive into specific topics:

- [Entry Types](entry-types.md) - Deep dive on IP, CIDR, patterns, strings
- [Pattern Matching](patterns.md) - Glob syntax and matching rules
- [Data Types and Values](data-types.md) - What data you can store
- [Performance Considerations](performance.md) - Optimization strategies

[def-database]: ../appendix/glossary.md#database '"database" (glossary entry)'
[def-entry]: ../appendix/glossary.md#entry '"entry" (glossary entry)'
[def-mmap]: ../appendix/glossary.md#memory-mapping '"memory mapping" (glossary entry)'
[def-match-mode]: ../appendix/glossary.md#match-mode '"match mode" (glossary entry)'
[mmdb]: https://maxmind.github.io/MaxMind-DB/
