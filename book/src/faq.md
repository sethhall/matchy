# Frequently Asked Questions

## General

### What is Matchy?

Matchy is a database for IP address and string matching. It supports matching IP addresses,
CIDR ranges, exact strings, and glob patterns with associated structured data.

### How is Matchy different from MaxMind's GeoIP?

Matchy can read standard MaxMind MMDB files and extends the format to support string
matching and glob patterns. If you only need IP lookups, MaxMind's libraries work great.
If you also need string and pattern matching, Matchy provides that functionality.

### Is Matchy production-ready?

Matchy is actively developed and used in production systems. The API is stable, and the
binary format is versioned. Always test thoroughly in your specific environment.

## Performance

### How fast is Matchy?

IP traversal is bounded by the address width, exact strings use average-case
O(1) hash probing, and glob cost depends on pattern shape and input. Opening
avoids whole-file deserialization through memory mapping, but still performs
structural checks. Measure with `matchy bench`; results depend on hardware,
storage, page-cache state, database size, hit rate, cache settings, and query
patterns.

### Does Matchy work with multiple processes?

Yes. Matchy uses memory mapping, so the operating system can share clean
read-only database pages across processes. Actual resident memory also includes
private metadata, page tables, query caches, and the subset of pages each
process touches; measure RSS/PSS under the intended workload.

### What's the maximum database size?

Memory mapping allows a database to exceed physical RAM when the working set
fits the deployment. Serialized extension offsets are `u32`, builders and
decoders impose additional limits, and virtual address space is not the only
constraint. Test the intended size and enforce an application file-size limit.

## Compatibility

### Can I use Matchy with languages other than Rust?

Yes. Matchy provides a C API that can be called from any language with C FFI support. This
includes C++, Python, Go, Node.js, and many others.

### Does Matchy run on Windows?

Yes. Matchy supports Linux, macOS, and Windows (10+).

## Database Format

### What file format does Matchy use?

Matchy uses a compact binary format based on MaxMind's MMDB specification. The format
supports:
- IP address trees (compatible with MMDB)
- Hash tables for exact string matches (extension)
- Aho-Corasick automaton for patterns (extension)
- Structured data storage (compatible with MMDB)

### Can I read Matchy databases from other tools?

Standard MaxMind MMDB readers can read the IP address portion of a Matchy database. The
string and pattern matching features require using Matchy's libraries.

### Are databases portable across platforms?

Yes. Matchy databases are platform-independent binary files. A database built on Linux
works on macOS and Windows without modification.

## Entry Types

### How do I match a string that contains wildcards literally?

Use the `literal:` prefix to force exact matching:

```text
literal:file*.txt
```

This will match the literal string "file*.txt" instead of treating `*` as a wildcard.

### How do I force a string to be treated as a pattern?

Use the `glob:` prefix:

```text
glob:example.com
```

This forces "example.com" to be treated as a glob pattern instead of an exact string.

### What are type prefixes and when should I use them?

Type prefixes (`literal:`, `glob:`, `ip:`) override Matchy's automatic entry type detection.
Use them when:
- A string contains `*`, `?`, or `[` that should be matched literally
- You need consistent behavior across mixed data sources
- Auto-detection doesn't match your intent

See [Entry Types - Prefix Technique](guide/entry-types.md#explicit-type-control-prefix-technique) for details.
