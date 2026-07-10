# Architecture

This page is a concise map of Matchy's current runtime. The
[binary format specification](binary-format.md) is the authoritative reference
for serialized layouts, versions, sizes, and offset bases. The
[architecture overview](../architecture/overview.md) explains the design at a
higher level.

## Design Goals

Matchy is designed around four constraints:

1. One query API for IP addresses, exact strings, and glob patterns.
2. Memory-mapped, position-independent database files.
3. Bounded work and checked offsets when reading untrusted bytes.
4. Data structures specialized for each query type.

## Current Components

### MMDB IP Search Tree

IP and CIDR lookups use the MaxMind DB search-tree encoding. A tree node is two
packed 24-, 28-, or 32-bit records, so a serialized node occupies 6, 7, or 8
bytes. A record can select another node, the not-found sentinel, or a value in
the shared MMDB data section.

Lookup depth is bounded by the address width: 32 bits for an IPv4 database and
128 bits for an IPv6 database. IPv6 trees can also contain IPv4 entries beneath
the conventional 96-bit IPv4 subtree.

### Literal Hash Table

Exact strings use the version 3 `LHSH` format from
`matchy-literal-hash`. The table stores a 96-bit XXH3 hash as `u64 + u32` and a
pattern ID in each 16-byte slot. It is divided into power-of-two shards and uses
linear probing within a shard.

Original literal strings are not stored in this section. A separate mapping
associates pattern IDs with offsets relative to the shared MMDB data section.

### PARAGLOB Matcher

Glob patterns use the version 5 PARAGLOB format. Its main pieces are:

- a serialized Aho-Corasick automaton with 20-byte `ACNodeHot` records;
- pattern metadata and UTF-8 pattern strings;
- pre-serialized glob segments for wildcard verification;
- literal-to-pattern and meta-word mappings;
- optional inline pattern data for standalone PARAGLOB databases.

In a combined `.mxy` database, PARAGLOB bytes are wrapped with a count and an
array of offsets into the shared MMDB data section. Those outer mappings are
separate from PARAGLOB's optional inline `PatternDataMapping` table.

## Query Routing

`Database::lookup` first determines whether the input is an IP address.

- IP input traverses the MMDB tree and decodes the selected shared data value.
- Text input checks the literal hash table, then runs PARAGLOB matching for
  wildcard patterns.

The regular query API returns owned result values where appropriate. The
offset-oriented `lookup_ref` API avoids decoding the value and is intended for
callers such as the C boundary that can consume an MMDB data offset. Avoid
describing every query path as allocation-free: result collection and data
decoding can allocate.

## Combined File Layout

A current combined `.mxy` file is organized as:

```text
MMDB packed search tree
16-byte zero separator
shared MMDB data section
[optional padding]
[MMDB_PATTERN marker + combined PARAGLOB wrapper]
[MMDB_LITERAL marker + LHSH v3 bytes]
MMDB metadata marker
MMDB metadata map
```

Metadata fields identify the bytes immediately after each optional extension
marker. Current writers include those offsets; the reader retains a bounded
marker scan for older files whose extension offsets are absent or stale.

## Offset-Based Storage

Serialized structures contain integer offsets rather than process pointers, so
the same bytes can be mapped at different virtual addresses. Offset bases are
field-specific:

- metadata extension offsets are absolute file offsets;
- PARAGLOB header offsets are relative to the PARAGLOB buffer;
- AC-local references are relative to the serialized AC buffer;
- literal-header offsets are relative to the `LHSH` bytes;
- combined literal and glob data mappings are relative to the shared MMDB data
  section;
- inline PARAGLOB data mappings are relative to PARAGLOB's inline data section.

Zero is therefore not a universal null value. It is a valid first offset in the
shared and inline data sections. See [Offset Encoding](binary-format.md#offset-encoding)
for the full table.

## Opening and Memory Ownership

File-backed databases use memory mapping. This avoids reading and deserializing
the entire file during open and lets the operating system share read-only pages
across processes. Matchy still parses metadata, validates top-level section
envelopes and component topology, and retains small runtime metadata. Observed
open time depends on storage, page-cache state, platform, optional sections,
and whether legacy marker scanning is needed.

The `Database` owns the mapping or byte buffer and the internal views that
reference it. A small, contained unsafe lifetime bridge establishes that
self-referential ownership invariant. Nested serialized records remain
bounds-checked before access.

## Concurrency

An opened database is immutable and supports concurrent lookups. Query-cache
and live-reload state use synchronization internally. Builders are mutable;
use a separate builder per independent build operation.

## Validation Model

Runtime opening fails closed on malformed headers, unsupported versions,
invalid extension markers, impossible section envelopes, and invalid literal
hash topology. Query paths validate nested records before reading them.

The separate validator adds reporting and two coverage levels:

- **Standard** performs runtime-equivalent envelope checks and samples
  tree-reachable MMDB data. If the database declares a known schema, it still
  validates every referenced entry against that schema.
- **Strict** exhaustively checks MMDB tree records and reachable data, then runs
  deeper AC, PARAGLOB, literal, mapping, and schema consistency checks.

For attacker-controlled files, also impose an application-level file-size or
resource limit. A validation report applies to the bytes that were read; if a
path can be replaced between validation and opening, use a protected immutable
snapshot or verify a digest.

## Format Compatibility

The standard MMDB portion follows the MaxMind DB format. Matchy's current
extension readers accept PARAGLOB v5 and literal-hash v3. Extension structs are
currently supported on little-endian targets; the endianness marker reserves a
future byte-swapping implementation.

## See Also

- [Binary Format](binary-format.md) — exact layouts, sizes, versions, and offset bases
- [Architecture Overview](../architecture/overview.md) — design concepts and diagrams
- [Validation API](validation-api.md) — programmatic Standard and Strict validation
- [Performance](../guide/performance.md) — measurement guidance and workload tradeoffs
- [C API Design](c-api.md) — FFI ownership and error handling
