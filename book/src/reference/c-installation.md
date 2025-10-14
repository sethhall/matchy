# C Installation

Installing Matchy for C/C++ development.

## From Release

```bash
# Download release
wget https://github.com/user/matchy/releases/latest/libmatchy.tar.gz
tar xzf libmatchy.tar.gz

# Install
sudo cp lib/libmatchy.* /usr/local/lib/
sudo cp include/matchy.h /usr/local/include/
sudo ldconfig  # Linux only
```

## From Source

```bash
# Build
git clone https://github.com/user/matchy.git
cd matchy
cargo build --release

# Install
sudo cp target/release/libmatchy.* /usr/local/lib/
sudo cp include/matchy.h /usr/local/include/
sudo ldconfig  # Linux only
```

## pkg-config

Create `/usr/local/lib/pkgconfig/matchy.pc`:

```
prefix=/usr/local
exec_prefix=${prefix}
libdir=${exec_prefix}/lib
includedir=${prefix}/include

Name: matchy
Description: Matchy database library
Version: 0.1.0
Libs: -L${libdir} -lmatchy
Cflags: -I${includedir}
```

## Usage

```bash
# Compile
gcc myapp.c -o myapp -lmatchy

# Or with pkg-config
gcc myapp.c -o myapp $(pkg-config --cflags --libs matchy)
```

## See Also

- [C API](../user-guide/c-api.md)
- [Project Setup](project-setup.md)
