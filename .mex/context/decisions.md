---
name: decisions
description: Key architectural and technical decisions with reasoning. Load when making design choices or understanding why something is built a certain way.
triggers:
  - "why do we"
  - "why is it"
  - "decision"
  - "alternative"
  - "we chose"
edges:
  - target: context/architecture.md
    condition: when a decision relates to system structure
  - target: context/stack.md
    condition: when a decision relates to technology choice
  - target: context/binary-format.md
    condition: when a decision affects file compatibility, mmap, or validation
  - target: context/ffi.md
    condition: when a decision affects C ABI or generated headers
  - target: context/processing.md
    condition: when a decision affects extraction or log scanning throughput
last_updated: 2026-07-02
---

# Decisions

## Decision Log

### Use a unified MMDB-compatible `.mxy` database
**Date:** 2025-12-17
**Status:** Active
**Decision:** `Database` and `DatabaseBuilder` expose one fluent API for IP, literal, and glob data in an MMDB-compatible file.
**Reasoning:** Threat data commonly mixes CIDRs, exact domains/hashes, and glob patterns; a single memory-mapped file keeps loading and querying simple.
**Alternatives considered:** Separate IP and pattern database files, or a Paraglob-only format; rejected because callers would need routing and multiple handles.
**Consequences:** Builders always emit an IP tree, metadata, and optional literal/glob sections; loader must detect IP-only, pattern-only, and combined layouts.

### Keep canonical binary structs in `matchy-paraglob`
**Date:** 2025-12-18
**Status:** Active
**Decision:** `matchy-format::offset_format` re-exports the canonical `#[repr(C)]` format structs from `matchy-paraglob`.
**Reasoning:** Duplicate binary structs can drift and break byte-for-byte compatibility.
**Alternatives considered:** Maintaining identical definitions in multiple crates; rejected because layout changes would be easy to miss.
**Consequences:** Any Paraglob format change must update the canonical structs, size assertions, validation, and format version together.

### Use zero-allocation lookup references for C API
**Date:** 2025-12-19
**Status:** Active
**Decision:** `Database::lookup_ref` returns offsets and result metadata so C callers can decode data on demand.
**Reasoning:** Many FFI callers only need found/not-found checks; decoding full `DataValue` trees on every query wastes allocations.
**Alternatives considered:** Returning owned JSON strings for all C queries; rejected for performance and memory ownership complexity.
**Consequences:** C results carry `_data_offset` and `_db_ref`; offset validity and lifetime documentation are critical.

### Use literal hash v3 for exact string matching
**Date:** 2025-12-23
**Status:** Active
**Decision:** Exact strings use the `LHSH` v3 sharded hash table with 96-bit XXH3-derived hashes and pattern/data mappings.
**Reasoning:** Literal lookup should be O(1) and separate from glob matching; sharding allows parallel construction.
**Alternatives considered:** Treating all strings as Paraglob patterns; rejected because exact matches dominate many IoC feeds and should not pay glob costs.
**Consequences:** Literal format changes are breaking and must update version constants, validators, and loader expectations.

### Modularize extraction into focused extractors
**Date:** 2025-12-20
**Status:** Active
**Decision:** `matchy-extractor` uses modular extractor kinds and shared finder results for domains, IPs, email, hashes, and crypto addresses.
**Reasoning:** Scanning logs needs many candidate types, but each has different validation and boundary rules.
**Alternatives considered:** One large regex-like scanner; rejected because it is harder to optimize and test per indicator type.
**Consequences:** Adding an indicator type touches builder flags, extractor kind routing, CLI `--extractors`, C flags, and tests.
