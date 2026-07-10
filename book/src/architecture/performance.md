# Performance

Matchy is designed for high-performance lookups with minimal overhead.

## Overview

This section covers performance aspects of matchy:

- **[Benchmarking Guide](../dev/benchmarking.md)** - How to run and interpret measurements
- **[Performance Guide](../guide/performance.md)** - Workload and tuning considerations
- **[Archived Performance Results](./performance-results.md)** - Historical v0.5.2 measurements

## Key Performance Features

### Direct Memory-Mapped Index Access

Matchy uses memory-mapped files for direct index access:
- No whole-file deserialization
- Direct binary format access
- Shared memory pages across processes

### Fast Lookups

- **IP lookups**: Binary trie traversal, O(32) for IPv4
- **Literal lookups**: Hash table with O(1) average case
- **Pattern matching**: Aho-Corasick candidate discovery followed by selective glob verification

### Memory Accounting

- Runtime views and optional query caches use owned memory
- Clean file-backed pages can be shared across processes
- Resident pages are loaded on demand and depend on the working set

See the [Benchmarking Guide](../dev/benchmarking.md) for current measurement
guidance. The archived results are not guarantees for the current implementation.
