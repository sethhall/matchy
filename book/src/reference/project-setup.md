# Project Setup

Setting up a project to use Matchy.

## Rust Project

### Cargo.toml

```toml
[dependencies]
matchy = "0.1"
```

### main.rs

```rust
use matchy::{Database, MmdbBuilder, MatchMode};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Your code here
    Ok(())
}
```

## C/C++ Project

### CMakeLists.txt

```cmake
cmake_minimum_required(VERSION 3.10)
project(MyApp)

find_package(PkgConfig REQUIRED)
pkg_check_modules(MATCHY REQUIRED matchy)

add_executable(myapp main.c)
target_link_libraries(myapp ${MATCHY_LIBRARIES})
target_include_directories(myapp PUBLIC ${MATCHY_INCLUDE_DIRS})
```

### Makefile

```makefile
CFLAGS = $(shell pkg-config --cflags matchy)
LDFLAGS = $(shell pkg-config --libs matchy)

myapp: main.c
	$(CC) main.c -o myapp $(CFLAGS) $(LDFLAGS)
```

## See Also

- [C Installation](c-installation.md)
- [Rust API](rust-api.md)
- [C API](c-api.md)
