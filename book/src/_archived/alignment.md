# Alignment Improvements

Memory alignment optimizations in Matchy.

## Why Alignment Matters

1. **Performance** - Aligned access is faster
2. **Correctness** - Some platforms require alignment
3. **mmap Safety** - Prevents undefined behavior

## Alignment Strategy

### Natural Alignment

All structures use natural alignment:
```rust
#[repr(C)]
struct AcNode {
    failure_offset: u32,  // 4-byte aligned
    edges_offset: u32,    // 4-byte aligned
    num_edges: u16,       // 2-byte aligned
    // 2 bytes padding inserted automatically
    output_offset: u32,   // 4-byte aligned
}
```

### Padding

Explicit padding ensures alignment:
```rust
#[repr(C)]
struct Header {
    magic: [u8; 8],
    version: u32,
    _padding: [u8; 4],  // Explicit padding
}
```

## Validation

Runtime checks prevent misaligned access:
```rust
fn validate_alignment<T>(buffer: &[u8], offset: usize) -> Result<()> {
    if offset % std::mem::align_of::<T>() != 0 {
        return Err(Error::MisalignedAccess);
    }
    Ok(())
}
```

## Performance Impact

Proper alignment improves performance:
- **Aligned**: 1 cycle load
- **Misaligned**: 3+ cycles (or crash)

## See Also

- [Binary Format](binary-format.md)
- [System Architecture](overview.md)
