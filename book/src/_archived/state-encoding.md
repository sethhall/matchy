# State Encoding

State encoding in the Aho-Corasick automaton.

## Overview

The Aho-Corasick automaton uses **offset-based encoding** for memory-mapped compatibility.

## Node Structure

```rust
#[repr(C)]
pub struct AcNode {
    pub failure_offset: u32,  // Offset to failure node
    pub edges_offset: u32,    // Offset to edge array
    pub num_edges: u16,       // Number of outgoing edges
    pub output_offset: u32,   // Offset to output data
}
```

## Edge Encoding

Edges stored as sorted arrays:
```rust
#[repr(C)]
struct Edge {
    byte: u8,          // Input byte
    target_offset: u32 // Target node offset
}
```

Binary search for edge lookup: O(log edges)

## Failure Links

Failure links encoded as offsets:
- Point to longest proper suffix match
- Enable linear-time pattern matching
- Used when no edge matches current input

## Output Encoding

Match data stored as offsets to data section:
```rust
struct Output {
    pattern_id: u32,    // Which pattern matched
    data_offset: u32,   // Associated data
}
```

## Memory Layout

```
+----------------+
| Root Node      | Offset 0
+----------------+
| Node 1         | Offset 64
+----------------+
| Node 2         | Offset 128
+----------------+
| Edge Arrays    | Variable offsets
+----------------+
| Output Lists   | Variable offsets
+----------------+
```

## See Also

- [Binary Format](binary-format.md)
- [System Architecture](overview.md)
