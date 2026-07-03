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

# Link headers
mkdir -p /usr/local/include/matchy
ln -sf $(pwd)/crates/matchy/include/matchy/matchy.h /usr/local/include/matchy/matchy.h
ln -sf $(pwd)/crates/matchy/include/matchy/maxminddb.h /usr/local/include/matchy/maxminddb.h
```

## Cleanup

```bash
rm ~/.cargo/bin/matchy
rm /usr/local/lib/libmatchy.*
rm /usr/local/include/matchy/matchy.h
rm /usr/local/include/matchy/maxminddb.h
```

## See Also

- [Building](building.md)
- [Development Guide](../development.md)
