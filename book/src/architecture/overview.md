# System Architecture

Matchy is built on three core principles: **unified querying**, **zero-copy memory mapping**, and **memory safety**.

## High-Level Architecture

```mermaid
graph TD
    A["Application Layer (C/Rust)"] --> B["C FFI (Opaque Handles)"]
    B --> C[Rust Core]
    
    C --> D["IP Binary Trie (O log n)"]
    C --> E["String Hash (O 1)"]
    C --> F["Pattern Matcher (AC+Glob)"]
    C --> G["MMDB Format (Extended)"]
    C --> H["Memory Mapping (mmap)"]
    
    style A fill:#e1f5fe
    style B fill:#fff3e0
    style C fill:#f3e5f5
    style D fill:#e8f5e9
    style E fill:#e8f5e9
    style F fill:#e8f5e9
    style G fill:#fff9c4
    style H fill:#fff9c4
```

## Query Routing

One API automatically detects and routes queries:

```mermaid
flowchart TD
    A["db.lookup(query)"] --> B{"Try Parse
IP/CIDR?"}
    B -->|"Valid IP"| F["Binary Trie Lookup"]
    B -->|"Not IP"| C["String Lookup"]
    
    C --> G["Check Literal Hash"]
    C --> H["Check Glob Patterns"]
    
    G --> J{"Any
Matches?"}
    H --> J
    
    F --> K["IP Result"]
    J --> L["Pattern Result"]
    
    style A fill:#e3f2fd
    style B fill:#fff3e0
    style C fill:#fff9c4
    style F fill:#c8e6c9
    style G fill:#c8e6c9
    style H fill:#c8e6c9
    style J fill:#fff3e0
    style K fill:#b2dfdb
    style L fill:#b2dfdb
```

## Pattern Matching Pipeline

Two-phase approach for glob patterns:

```mermaid
flowchart TD
    A["Input: phishing.evil.com"] --> B["Phase 1: Aho-Corasick"]
    
    B --> C{"Scan Literals"}
    C -->|"Found evil.com"| D["Candidate: *.evil.com"]
    C -->|"No match"| E["No Match"]
    
    D --> F["Phase 2: Glob Verify"]
    F --> G{"Match *.evil.com?"}
    G -->|"Yes"| H["Match Found!"]
    G -->|"No"| E
    
    style A fill:#e1f5fe
    style B fill:#fff3e0
    style C fill:#fff3e0
    style D fill:#c5e1a5
    style F fill:#ffccbc
    style G fill:#ffccbc
    style H fill:#a5d6a7
    style E fill:#ef9a9a
```

## Memory Architecture

### Traditional Approach

```mermaid
graph LR
    A[File] -->|Read| B[Deserialize]
    B -->|200ms| C["Heap: 6GB × 64 proc"]
    C --> D["Total: 6,400 MB"]
    
    style A fill:#e3f2fd
    style B fill:#fff3e0
    style C fill:#ffcdd2
    style D fill:#ef5350
```

### Matchy Approach

```mermaid
graph LR
    A[File] -->|mmap| B["Memory Mapped (<1ms)"]
    B --> C["Direct Access (100MB)"]
    C --> D["OS Page Sharing"]
    D --> E["Total: 100 MB (64 proc)"]
    
    style A fill:#e3f2fd
    style B fill:#c8e6c9
    style C fill:#c8e6c9
    style D fill:#a5d6a7
    style E fill:#66bb6a
```

**Memory Sharing**: OS automatically shares physical pages across processes reading the same file.

## Extended MMDB Format

```mermaid
graph TD
    A["Database File (.mxy)"] --> B["Standard MMDB"]
    A --> C["PARAGLOB Extension"]
    
    B --> B1["IP Search Tree"]
    B --> B2["Data Section"]
    B --> B3[Metadata]
    
    C --> C1["Magic: PARAGLOB"]
    C --> C2["AC Automaton"]
    C --> C3["Pattern Strings"]
    C --> C4["Literal Hash"]
    
    style A fill:#e1f5fe
    style B fill:#c8e6c9
    style C fill:#fff9c4
    style B1 fill:#a5d6a7
    style B2 fill:#a5d6a7
    style B3 fill:#a5d6a7
    style C1 fill:#fff59d
    style C2 fill:#fff59d
    style C3 fill:#fff59d
    style C4 fill:#fff59d
```

**Backwards Compatible:**
- IP-only databases work with MaxMind tools (ignore PARAGLOB section)
- Standard `.mmdb` files work with Matchy
- Extensions gracefully skipped by old readers

## Zero-Copy Design

All data structures use **file offsets** instead of memory pointers. This is the key to enabling memory mapping:

**Traditional approach (pointers):**
```rust
struct Node {
    next: *const Node,  // Memory address - invalid across processes!
}
```

**Matchy approach (offsets):**
```rust
struct Node {
    next_offset: u32,   // File offset - works anywhere!
}
```

When you open a memory-mapped file, it might be loaded at address `0x1000` in one process and `0x5000` in another. Pointers break, but offsets always work because they're relative to the file start.

This applies to all structures:
- **AC automaton nodes** reference edges by offset
- **Pattern entries** reference strings by offset  
- **Tree nodes** reference children by offset

Every offset is validated before dereferencing to prevent undefined behavior.

## Performance at a Glance

| Operation | Time | Technology |
|-----------|------|------------|
| **Load 100K IPs** | <1ms | `mmap()` syscall |
| **IP Lookup** | 0.25µs | Binary trie O(log n) |
| **Exact String** | 0.88µs | Hash table O(1) |
| **Suffix Pattern** | 0.30µs | AC + simple glob |
| **Complex Pattern** | 2-80µs | AC + backtracking |

*M4 MacBook Air benchmarks*

## Safety Guarantees

### Memory Safety

**Core matching algorithms**: Written in safe Rust
- Aho-Corasick traversal
- Glob pattern matching  
- Binary tree walking
- Hash table lookups

**Limited unsafe code** is used only for:
1. **C FFI boundaries** - Converting between C and Rust types
2. **Memory mapping** - `mmap()` system call requires unsafe
3. **Binary format access** - Reading offset-based structures from raw bytes

All unsafe operations are validated:
- Null pointer checks before dereferencing
- Offset bounds checking before structure access
- Alignment validation for structured reads
- Lifetime tracking to prevent use-after-free

### FFI Safety

The C API follows strict safety rules:

**1. Null checks on every pointer:**
```rust
if db.is_null() || query.is_null() {
    return MATCHY_ERROR_INVALID_PARAM;
}
```

**2. Panic catching at boundaries:**
```rust
let result = std::panic::catch_unwind(|| {
    // ... actual work ...
});
result.unwrap_or(MATCHY_ERROR_UNKNOWN)
```

**3. Opaque handles for ownership:**
```rust
// No raw struct access from C
pub struct matchy_t { _private: [u8; 0] }
```

Panics never cross FFI boundaries - they're caught and converted to error codes.

## Design Trade-offs

### Immutability

✅ **Benefits:**
- No locks needed for concurrent reads
- Enables memory mapping
- Guaranteed consistency

📝 **To Update (Live Reload):**

Databases are read-only, but you can update them **while processes are running**:

1. Build new database with updated entries
2. Atomically replace the file (e.g., `mv new.mxy old.mxy`)
3. Close old database handle
4. Reopen database (<1ms load time)
5. Continue serving requests

**Why this works:**
- Opening a database takes <1ms (just mmap)
- Old processes keep using the old file until they reopen
- No downtime needed - reload between requests
- OS handles the file transition cleanly

This is why we obsessed over making database opening so fast - you can reload threat feeds every few minutes in production without anyone noticing.

### Pattern Complexity

```mermaid
graph LR
    A["Suffix: *.domain.com"] -->|"3.3M q/s"| B[Fast]
    C["Prefix: log-*"] -->|"950K q/s"| D[Moderate]
    E["Complex: *0-9.*"] -->|"13K q/s"| F[Slow]
    
    style A fill:#a5d6a7
    style B fill:#66bb6a
    style C fill:#fff59d
    style D fill:#ffa726
    style E fill:#ffab91
    style F fill:#ef5350
```

**Recommendation:** Use suffix patterns when possible for best performance.

## Next Steps

- [Binary Format Details](./binary-format.md) - Deep dive into file format
- [Performance Analysis](./performance.md) - Benchmarks and optimization
- [MMDB Integration](../mmdb-integration-design.md) - MaxMind compatibility
