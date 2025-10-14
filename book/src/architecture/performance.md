# Performance

Matchy is designed for high-performance lookups with minimal overhead.

## Overview

This section covers performance aspects of matchy:

- **[Benchmarking Strategy](../benchmarking-strategy.md)** - How we measure performance
- **[Performance Optimizations](../performance-optimizations.md)** - Design decisions for speed
- **[Performance Results](./performance-results.md)** - Real-world benchmark numbers

## Key Performance Features

### Zero-Copy Architecture

Matchy uses memory-mapped files to achieve zero-copy data access:
- No deserialization overhead
- Direct binary format access
- Shared memory pages across processes

### Fast Lookups

- **IP lookups**: Binary trie traversal, O(32) for IPv4
- **Literal lookups**: Hash table with O(1) average case
- **Pattern matching**: Aho-Corasick automaton for parallel matching

### Minimal Memory Footprint

- Database handle overhead: ~200 bytes
- Shared pages reduce memory usage in multi-process scenarios
- Lazy loading via OS page faults

See [Performance Results](./performance-results.md) for detailed benchmark numbers on real hardware.
