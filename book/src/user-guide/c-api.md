# C API

Matchy provides a clean, modern C API for building and querying databases from C/C++ applications.

## Overview

The C API uses opaque handles and integer error codes for safety and stability:

- **Opaque handles** - `matchy_t*`, `matchy_builder_t*` (no direct struct access)
- **Integer error codes** - All functions return status codes
- **Memory safety** - Clear ownership semantics
- **Thread safety** - Databases are read-only and thread-safe after building

## Quick Start

```c
#include "matchy.h"
#include <stdio.h>

int main() {
    // Build a database
    matchy_builder_t *builder = matchy_builder_new();
    matchy_builder_add(builder, "1.2.3.4", "{\"threat_level\": \"high\"}");
    matchy_builder_add(builder, "*.evil.com", "{\"category\": \"malware\"}");
    matchy_builder_save(builder, "threats.mxy");
    matchy_builder_free(builder);
    
    // Query the database
    matchy_t *db = matchy_open("threats.mxy");
    if (!db) {
        fprintf(stderr, "Failed to open database\n");
        return 1;
    }
    
    matchy_result_t result = matchy_query(db, "1.2.3.4");
    if (result.found) {
        printf("Threat detected!\n");
        matchy_free_result(&result);
    }
    
    matchy_close(db);
    return 0;
}
```

## Error Handling

All functions return status codes:

```c
// Error codes
#define MATCHY_SUCCESS              0
#define MATCHY_ERROR_FILE_NOT_FOUND -1
#define MATCHY_ERROR_INVALID_FORMAT -2
#define MATCHY_ERROR_CORRUPT_DATA   -3
#define MATCHY_ERROR_OUT_OF_MEMORY  -4
#define MATCHY_ERROR_INVALID_PARAM  -5
#define MATCHY_ERROR_IO             -6
```

**Example:**
```c
int status = matchy_builder_add(builder, key, data);
if (status != MATCHY_SUCCESS) {
    fprintf(stderr, "Failed to add entry: %d\n", status);
    return 1;
}
```

## Key Features

### Building Databases

- Create builder: `matchy_builder_new()`
- Add entries: `matchy_builder_add()`
- Set metadata: `matchy_builder_set_description()`
- Save to file: `matchy_builder_save()`
- Clean up: `matchy_builder_free()`

**See:** [Building Databases](c-building.md)

### Querying Databases

- Open database: `matchy_open()`
- Query entries: `matchy_query()`
- Get entry count: `matchy_entry_count()`
- Close database: `matchy_close()`

**See:** [Querying from C](c-querying.md)

### Memory Management

- Clear ownership semantics
- Explicit free functions
- No hidden allocations
- Thread-safe after building

**See:** [Memory Management](c-memory.md)

## Compilation

### Linux/macOS

```bash
gcc -o myapp myapp.c \
    -I/path/to/matchy/include \
    -L/path/to/matchy/target/release \
    -lmatchy
```

### pkg-config

```bash
gcc -o myapp myapp.c $(pkg-config --cflags --libs matchy)
```

## Complete Example

```c
#include "matchy.h"
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <database> <query>\n", argv[0]);
        return 1;
    }
    
    // Open database
    matchy_t *db = matchy_open(argv[1]);
    if (!db) {
        fprintf(stderr, "Failed to open database: %s\n", argv[1]);
        return 1;
    }
    
    // Query
    matchy_result_t result = matchy_query(db, argv[2]);
    
    if (result.found) {
        printf("Match found!\n");
        if (result.prefix_len > 0) {
            printf("  CIDR prefix: /%d\n", result.prefix_len);
        }
        matchy_free_result(&result);
    } else {
        printf("No match found\n");
    }
    
    // Cleanup
    matchy_close(db);
    return 0;
}
```

## API Reference

### Types

- `matchy_t` - Database handle (opaque)
- `matchy_builder_t` - Builder handle (opaque)
- `matchy_result_t` - Query result structure

### Functions

**Building:**
- `matchy_builder_new()` - Create builder
- `matchy_builder_add()` - Add entry
- `matchy_builder_save()` - Save to file
- `matchy_builder_free()` - Free builder

**Querying:**
- `matchy_open()` - Open database
- `matchy_query()` - Query database
- `matchy_free_result()` - Free result
- `matchy_close()` - Close database

## See Also

- [Building Databases](c-building.md) - Creating databases from C
- [Querying from C](c-querying.md) - Querying databases
- [Memory Management](c-memory.md) - Memory safety guidelines
- [C Installation](../reference/c-installation.md) - Installation guide
