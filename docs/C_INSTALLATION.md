# Installing Matchy as a C/C++ Library

Matchy can be installed as a C-compatible library using `cargo-c`, which provides proper system integration with headers, libraries, and pkg-config support.

## Prerequisites

Install `cargo-c`:
```bash
cargo install cargo-c
```

## Installation

### Option 1: Install to System Directories (requires sudo)

```bash
# Build and install to /usr/local (default)
sudo cargo cinstall --release --prefix=/usr/local

# Or install to /usr
sudo cargo cinstall --release --prefix=/usr
```

### Option 2: Install to Custom Location

```bash
# Install to a custom prefix (e.g., $HOME/.local)
cargo cinstall --release --prefix=$HOME/.local

# Make sure to add the path to your environment
export PKG_CONFIG_PATH=$HOME/.local/lib/pkgconfig:$PKG_CONFIG_PATH
export LD_LIBRARY_PATH=$HOME/.local/lib:$LD_LIBRARY_PATH  # Linux
export DYLD_LIBRARY_PATH=$HOME/.local/lib:$DYLD_LIBRARY_PATH  # macOS
```

### Option 3: Staged Install (for packaging)

```bash
# Install to a staging directory (e.g., for creating packages)
cargo cinstall --release --destdir=/tmp/matchy-staging --prefix=/usr
```

## What Gets Installed

After installation, the following files will be available:

```
$PREFIX/
├── include/matchy/
│   ├── matchy.h          # Main C API header
│   ├── matchy.hpp        # C++ wrapper header
│   └── maxminddb.h       # MaxMind DB compatibility API
├── lib/
│   ├── libmatchy.a       # Static library
│   ├── libmatchy.dylib   # Dynamic library (macOS)
│   ├── libmatchy.so      # Dynamic library (Linux)
│   └── pkgconfig/
│       └── matchy.pc     # pkg-config file
```

## Using the Library

### With pkg-config (Recommended)

```bash
# Compile with pkg-config
gcc myapp.c $(pkg-config --cflags --libs matchy) -o myapp

# Check matchy version
pkg-config --modversion matchy
```

### Manual Compilation

```bash
# C program
gcc myapp.c -I/usr/local/include -L/usr/local/lib -lmatchy -o myapp

# C++ program
g++ myapp.cpp -I/usr/local/include -L/usr/local/lib -lmatchy -o myapp
```

### In Your C Code

```c
#include <matchy/matchy.h>

int main() {
    // Create a database builder
    matchy_builder_t *builder = matchy_builder_new();
    
    // Add patterns
    matchy_builder_add_string(builder, "example.com", NULL, 0);
    
    // Build the database
    const char *output = "patterns.matchy";
    int result = matchy_builder_write_to_file(builder, output);
    
    // Clean up
    matchy_builder_free(builder);
    
    // Query the database
    matchy_db_t *db = matchy_db_open(output);
    bool matches = matchy_db_matches_string(db, "example.com");
    matchy_db_close(db);
    
    return 0;
}
```

### In Your C++ Code

```cpp
#include <matchy/matchy.hpp>

int main() {
    // C++ wrapper provides RAII and exceptions
    auto builder = matchy::Builder();
    builder.add_string("example.com");
    builder.write_to_file("patterns.matchy");
    
    auto db = matchy::Database("patterns.matchy");
    bool matches = db.matches_string("example.com");
    
    return 0;
}
```

### In Makefiles

```makefile
CFLAGS = $(shell pkg-config --cflags matchy)
LDFLAGS = $(shell pkg-config --libs matchy)

myapp: myapp.c
	$(CC) $(CFLAGS) $< $(LDFLAGS) -o $@
```

### In CMake

```cmake
find_package(PkgConfig REQUIRED)
pkg_check_modules(MATCHY REQUIRED matchy)

add_executable(myapp myapp.c)
target_include_directories(myapp PRIVATE ${MATCHY_INCLUDE_DIRS})
target_link_libraries(myapp PRIVATE ${MATCHY_LIBRARIES})
```

### In Meson

```meson
matchy_dep = dependency('matchy')

executable('myapp',
  'myapp.c',
  dependencies: matchy_dep
)
```

## Static vs Dynamic Linking

By default, pkg-config will prefer dynamic linking. To force static linking:

```bash
# Link statically
gcc myapp.c $(pkg-config --cflags --libs --static matchy) -o myapp -static
```

## Uninstalling

To uninstall matchy from system directories:

```bash
# Remove installed files (adjust prefix as needed)
sudo rm -f /usr/local/lib/libmatchy.*
sudo rm -rf /usr/local/include/matchy
sudo rm -f /usr/local/lib/pkgconfig/matchy.pc
```

## Development Workflow

For development, you can build without installing:

```bash
# Build the C library
cargo cbuild --release

# The built artifacts will be in:
# - target/aarch64-apple-darwin/release/libmatchy.{a,dylib}  # macOS
# - target/x86_64-unknown-linux-gnu/release/libmatchy.{a,so} # Linux
# - target/aarch64-apple-darwin/release/include/matchy/      # Headers

# Test with a local build
gcc test.c \
    -Itarget/aarch64-apple-darwin/release/include \
    -Ltarget/aarch64-apple-darwin/release \
    -lmatchy \
    -o test
```

## Distribution

### Homebrew (macOS)

Create a Homebrew formula:

```ruby
class Matchy < Formula
  desc "Fast database for IP address and pattern matching"
  homepage "https://github.com/sethhall/matchy"
  url "https://github.com/sethhall/matchy/archive/v0.5.0.tar.gz"
  license "BSD-2-Clause"

  depends_on "rust" => :build
  depends_on "cargo-c" => :build

  def install
    system "cargo", "cinstall", "--release", "--prefix", prefix
  end

  test do
    # Test the library
  end
end
```

### Debian/Ubuntu Package

In your `debian/rules`:

```makefile
override_dh_auto_configure:
	cargo cbuild --release

override_dh_auto_install:
	cargo cinstall --release --destdir=debian/tmp --prefix=/usr
```

## Troubleshooting

### Library Not Found at Runtime

On macOS:
```bash
export DYLD_LIBRARY_PATH=/usr/local/lib:$DYLD_LIBRARY_PATH
```

On Linux:
```bash
export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH
# Or update ldconfig
sudo ldconfig
```

### pkg-config Can't Find matchy

```bash
export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH
```

### Header Files Not Found

Make sure your include path points to the directory *containing* the matchy folder:
```bash
-I/usr/local/include  # Correct
# NOT -I/usr/local/include/matchy
```

Then include as:
```c
#include <matchy/matchy.h>  // Correct
```
