# Building Databases from C

This page documents the C API functions for building Matchy databases.

## Overview

Building a database in C involves three steps:

1. **Create a builder** with `matchy_builder_new()`
2. **Add entries** with `matchy_builder_add_*()` functions  
3. **Build and save** with `matchy_builder_build()`

```c
#include <matchy.h>

matchy_builder_t *builder = matchy_builder_new();

matchy_builder_add_ip(builder, "192.0.2.1/32", NULL);
matchy_builder_add_pattern(builder, "*.example.com", NULL);

matchy_error_t err = matchy_builder_build(builder, "database.mxy");
matchy_builder_free(builder);
```

## Builder Functions

### `matchy_builder_new`

```c
matchy_builder_t *matchy_builder_new(void);
```

Creates a new database builder.

**Returns:** Builder handle, or `NULL` on error

**Example:**
```c
matchy_builder_t *builder = matchy_builder_new();
if (!builder) {
    fprintf(stderr, "Failed to create builder\n");
    return 1;
}
```

**Memory:** Caller must free with `matchy_builder_free()`

### `matchy_builder_free`

```c
void matchy_builder_free(matchy_builder_t *builder);
```

Frees a builder and all its resources.

**Parameters:**
- `builder` - Builder to free (may be `NULL`)

**Example:**
```c
matchy_builder_free(builder);
builder = NULL;  // Good practice
```

**Note:** After calling this, the builder handle must not be used.

## Adding Entries

### `matchy_builder_add_ip`

```c
matchy_error_t matchy_builder_add_ip(
    matchy_builder_t *builder,
    const char *ip_cidr,
    const char *data_json
);
```

Adds an IP address or CIDR range to the database.

**Parameters:**
- `builder` - Builder handle
- `ip_cidr` - IP address or CIDR (e.g., "192.0.2.1" or "10.0.0.0/8")
- `data_json` - Associated data as JSON string, or `NULL`

**Returns:** `MATCHY_SUCCESS` or error code

**Example:**
```c
// IP without data
err = matchy_builder_add_ip(builder, "8.8.8.8", NULL);

// IP with data
err = matchy_builder_add_ip(builder, "192.0.2.1/32",
    "{\"country\":\"US\",\"asn\":15169}");

// CIDR range
err = matchy_builder_add_ip(builder, "10.0.0.0/8",
    "{\"type\":\"private\"}");

if (err != MATCHY_SUCCESS) {
    fprintf(stderr, "Failed to add IP\n");
}
```

**Valid formats:**
- IPv4: `"192.0.2.1"`, `"10.0.0.0/8"`
- IPv6: `"2001:db8::1"`, `"2001:db8::/32"`

### `matchy_builder_add_pattern`

```c
matchy_error_t matchy_builder_add_pattern(
    matchy_builder_t *builder,
    const char *pattern,
    const char *data_json
);
```

Adds a glob pattern to the database.

**Parameters:**
- `builder` - Builder handle
- `pattern` - Glob pattern string
- `data_json` - Associated data as JSON, or `NULL`

**Returns:** `MATCHY_SUCCESS` or error code

**Example:**
```c
// Simple wildcard
err = matchy_builder_add_pattern(builder, "*.google.com", NULL);

// With data
err = matchy_builder_add_pattern(builder, "mail.*",
    "{\"category\":\"email\",\"priority\":10}");

// Character class
err = matchy_builder_add_pattern(builder, "test[123].com", NULL);

if (err != MATCHY_SUCCESS) {
    fprintf(stderr, "Invalid pattern\n");
}
```

**Pattern syntax:**
- `*` - Matches any characters
- `?` - Matches single character
- `[abc]` - Matches any of a, b, c
- `[!abc]` - Matches anything except a, b, c

### `matchy_builder_add_exact`

```c
matchy_error_t matchy_builder_add_exact(
    matchy_builder_t *builder,
    const char *string,
    const char *data_json
);
```

Adds an exact string match to the database.

**Parameters:**
- `builder` - Builder handle
- `string` - Exact string to match
- `data_json` - Associated data as JSON, or `NULL`

**Returns:** `MATCHY_SUCCESS` or error code

**Example:**
```c
// Exact match
err = matchy_builder_add_exact(builder, "example.com", NULL);

// With data
err = matchy_builder_add_exact(builder, "api.example.com",
    "{\"endpoint\":\"api\",\"rate_limit\":1000}");

if (err != MATCHY_SUCCESS) {
    fprintf(stderr, "Failed to add string\n");
}
```

**Note:** Exact matches are faster than patterns. Use them when possible.

## Building the Database

### `matchy_builder_build`

```c
matchy_error_t matchy_builder_build(
    matchy_builder_t *builder,
    const char *output_path
);
```

Builds the database and writes it to a file.

**Parameters:**
- `builder` - Builder handle
- `output_path` - Path where database file will be written

**Returns:** `MATCHY_SUCCESS` or error code

**Example:**
```c
err = matchy_builder_build(builder, "database.mxy");
if (err != MATCHY_SUCCESS) {
    fprintf(stderr, "Build failed\n");
    return 1;
}

printf("Database written to database.mxy\n");
```

**Notes:**
- File is created or overwritten
- Build process compiles all entries into optimized format
- Builder can be reused after building

## Complete Example

```c
#include <matchy.h>
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    matchy_error_t err;
    
    // Create builder
    matchy_builder_t *builder = matchy_builder_new();
    if (!builder) {
        fprintf(stderr, "Failed to create builder\n");
        return 1;
    }
    
    // Add IP entries
    err = matchy_builder_add_ip(builder, "192.0.2.1/32",
        "{\"country\":\"US\"}");
    if (err != MATCHY_SUCCESS) {
        fprintf(stderr, "Failed to add IP\n");
        goto cleanup;
    }
    
    err = matchy_builder_add_ip(builder, "10.0.0.0/8",
        "{\"type\":\"private\"}");
    if (err != MATCHY_SUCCESS) {
        fprintf(stderr, "Failed to add CIDR\n");
        goto cleanup;
    }
    
    // Add patterns
    err = matchy_builder_add_pattern(builder, "*.google.com",
        "{\"category\":\"search\"}");
    if (err != MATCHY_SUCCESS) {
        fprintf(stderr, "Failed to add pattern\n");
        goto cleanup;
    }
    
    err = matchy_builder_add_pattern(builder, "mail.*",
        "{\"category\":\"email\"}");
    if (err != MATCHY_SUCCESS) {
        fprintf(stderr, "Failed to add pattern\n");
        goto cleanup;
    }
    
    // Add exact strings
    err = matchy_builder_add_exact(builder, "example.com", NULL);
    if (err != MATCHY_SUCCESS) {
        fprintf(stderr, "Failed to add exact string\n");
        goto cleanup;
    }
    
    // Build database
    err = matchy_builder_build(builder, "my_database.mxy");
    if (err != MATCHY_SUCCESS) {
        fprintf(stderr, "Build failed\n");
        goto cleanup;
    }
    
    printf("✓ Database built successfully: my_database.mxy\n");
    
cleanup:
    matchy_builder_free(builder);
    return (err == MATCHY_SUCCESS) ? 0 : 1;
}
```

**Compilation:**
```bash
gcc -o build_db build_db.c -lmatchy
./build_db
```

## Data Format

### JSON Data Structure

Data is passed as JSON strings:

```json
{
  "key1": "string_value",
  "key2": 42,
  "key3": 3.14,
  "key4": true,
  "key5": ["array", "values"],
  "key6": {
    "nested": "object"
  }
}
```

**Supported types:**
- Strings
- Numbers (integers, floats)
- Booleans (`true`/`false`)
- Arrays
- Objects (nested maps)
- `null`

### Example with Complex Data

```c
const char *geo_data = 
    "{"
    "  \"country\": \"US\","
    "  \"city\": \"Mountain View\","
    "  \"coords\": {"
    "    \"lat\": 37.386,"
    "    \"lon\": -122.084"
    "  },"
    "  \"tags\": [\"datacenter\", \"cloud\"]"
    "}";

matchy_builder_add_ip(builder, "8.8.8.8", geo_data);
```

## Error Handling

### Error Codes

| Code | Constant | Meaning |
|------|----------|---------|  
| 0 | `MATCHY_SUCCESS` | Operation succeeded |
| -1 | `MATCHY_ERROR_FILE_NOT_FOUND` | File not found |
| -2 | `MATCHY_ERROR_INVALID_FORMAT` | Invalid format |
| -3 | `MATCHY_ERROR_CORRUPT_DATA` | Data corruption |
| -4 | `MATCHY_ERROR_OUT_OF_MEMORY` | Out of memory |
| -5 | `MATCHY_ERROR_INVALID_PARAM` | Invalid parameter |
| -6 | `MATCHY_ERROR_IO` | I/O error |

### Checking Errors

```c
err = matchy_builder_add_ip(builder, ip, data);
if (err != MATCHY_SUCCESS) {
    switch (err) {
        case MATCHY_ERROR_INVALID_PARAM:
            fprintf(stderr, "Invalid IP address: %s\n", ip);
            break;
        case MATCHY_ERROR_OUT_OF_MEMORY:
            fprintf(stderr, "Out of memory\n");
            break;
        default:
            fprintf(stderr, "Error: %d\n", err);
    }
}
```

## Best Practices

### 1. Always Check Returns

```c
if (matchy_builder_add_ip(builder, ip, data) != MATCHY_SUCCESS) {
    // Handle error
}
```

### 2. Use Cleanup Labels

```c
matchy_builder_t *builder = NULL;
matchy_error_t err;

builder = matchy_builder_new();
if (!builder) goto cleanup;

err = matchy_builder_add_ip(builder, "192.0.2.1", NULL);
if (err != MATCHY_SUCCESS) goto cleanup;

// ... more operations ...

cleanup:
    if (builder) matchy_builder_free(builder);
    return err;
```

### 3. Validate Input

```c
if (!ip || strlen(ip) == 0) {
    fprintf(stderr, "Empty IP address\n");
    return MATCHY_ERROR_INVALID_PARAM;
}

err = matchy_builder_add_ip(builder, ip, data);
```

### 4. Batch Operations

```c
const char *ips[] = {
    "192.0.2.1",
    "10.0.0.1",
    "172.16.0.1",
    NULL
};

for (int i = 0; ips[i]; i++) {
    err = matchy_builder_add_ip(builder, ips[i], NULL);
    if (err != MATCHY_SUCCESS) {
        fprintf(stderr, "Failed to add IP %s\n", ips[i]);
        // Continue or abort based on requirements
    }
}
```

## Thread Safety

**Builders are NOT thread-safe.** Do not call builder functions from multiple threads simultaneously.

```c
// WRONG: Don't do this
#pragma omp parallel for
for (int i = 0; i < n; i++) {
    matchy_builder_add_ip(builder, ips[i], NULL);  // Data race!
}

// RIGHT: Use a single thread for building
for (int i = 0; i < n; i++) {
    matchy_builder_add_ip(builder, ips[i], NULL);
}
```

## Performance Tips

### 1. Pre-allocate When Possible

If you know approximately how many entries you'll add, building is more efficient.

### 2. Order Doesn't Matter

Entries can be added in any order - the builder optimizes internally.

### 3. Reuse Builders

Builders can be reused after building:

```c
matchy_builder_build(builder, "db1.mxy");
// Builder is still valid, can add more entries
matchy_builder_add_ip(builder, "1.2.3.4", NULL);
matchy_builder_build(builder, "db2.mxy");
```

### 4. Build Time

Building time depends on entry count:
- 1,000 entries: ~10ms
- 10,000 entries: ~50ms
- 100,000 entries: ~500ms
- 1,000,000 entries: ~5s

## See Also

- [C API Overview](c-api.md) - C API introduction
- [Querying from C](c-querying.md) - Query databases
- [Memory Management](c-memory.md) - Memory handling
- [First Database with C](../getting-started/api-c-first.md) - Tutorial
