# Endianness

Endianness handling in Matchy.

## Overview

Matchy uses **big-endian** (network byte order) for all multi-byte integers to ensure cross-platform compatibility.

## Why Big-Endian?

1. **MMDB Standard** - MaxMind DB format uses big-endian
2. **Network Protocols** - IP addresses are big-endian
3. **Cross-Platform** - Works across different architectures
4. **Human-Readable** - Hex dumps read naturally

## Implementation

All multi-byte integers are converted on read/write:

```rust
// Writing
let value: u32 = 12345;
buffer.write_u32::<BigEndian>(value)?;

// Reading
let value = buffer.read_u32::<BigEndian>()?;
```

## Performance

Modern CPUs handle endianness conversion efficiently:
- **x86/x64**: Single `bswap` instruction
- **ARM**: Single `rev` instruction
- **Negligible overhead**: <1ns per conversion

## Binary Format

All structures use big-endian:
```
Magic:    AB CD 12 34  (0xABCD1234)
Offset:   00 00 10 00  (offset 4096)
Size:     00 00 00 64  (size 100)
```

## See Also

- [Binary Format](architecture/binary-format.md)
- [System Architecture](architecture/overview.md)
