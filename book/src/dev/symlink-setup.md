# Symlink Setup

Symlink configuration for development.

## Purpose

Symlinks allow testing Matchy as if it were installed system-wide without actual installation.

## Setup

```bash
# Link CLI tool
ln -sf $(pwd)/target/release/matchy ~/.cargo/bin/matchy

# Link library (macOS)
ln -sf $(pwd)/target/release/libmatchy.dylib /usr/local/lib/

# Link library (Linux)
ln -sf $(pwd)/target/release/libmatchy.so /usr/local/lib/

# Link header
ln -sf $(pwd)/include/matchy.h /usr/local/include/
```

## Cleanup

```bash
rm ~/.cargo/bin/matchy
rm /usr/local/lib/libmatchy.*
rm /usr/local/include/matchy.h
```

## See Also

- [Building](building.md)
- [Development Guide](../development.md)
