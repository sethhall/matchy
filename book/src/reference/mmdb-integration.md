# MMDB Integration

Technical reference for MaxMind DB (MMDB) compatibility layer.

## Overview

Matchy provides a compatibility layer that allows existing `libmaxminddb` applications to use Matchy databases with minimal code changes.

## Compatibility Header

```c
#include <matchy/maxminddb.h>
```

Provides drop-in replacements for `libmaxminddb` functions.

## Function Mapping

### Opening Databases

| libmaxminddb | Matchy Equivalent |
|--------------|-------------------|
| `MMDB_open()` | `matchy_open()` |
| `MMDB_open_from_buffer()` | `matchy_open_buffer()` |
| `MMDB_close()` | `matchy_close()` |

### Lookups

| libmaxminddb | Matchy Equivalent |
|--------------|-------------------|
| `MMDB_lookup_string()` | `matchy_lookup()` |
| `MMDB_lookup_sockaddr()` | `matchy_lookup_ip()` |

### Data Access

| libmaxminddb | Matchy Equivalent |
|--------------|-------------------|
| `MMDB_get_value()` | `matchy_aget_value()` |
| `MMDB_get_entry_data_list()` | `matchy_get_entry_data_list()` |

## Key Differences

### 1. Additional Features

Matchy extends MMDB with:
- **Pattern matching**: Glob patterns with `*` and `?`
- **Exact strings**: Hash-based literal matching
- **Zero-copy strings**: No allocation for string results

### 2. Error Handling

Matchy uses integer error codes:
```c
int32_t err = matchy_lookup(db, "192.0.2.1", &result);
if (err != MATCHY_SUCCESS) {
    // Handle error
}
```

vs. libmaxminddb status codes:
```c
int gai_error, mmdb_error;
MMDB_lookup_result result = MMDB_lookup_string(mmdb, "192.0.2.1", 
                                                &gai_error, &mmdb_error);
```

### 3. Result Lifetime

Matchy requires explicit result freeing:
```c
matchy_result_t *result = NULL;
matchy_lookup(db, query, &result);
if (result) {
    // Use result
    matchy_free_result(result);  // Required!
}
```

### 4. Data Types

Matchy uses MMDB-compatible data types but with extended support:
- All MMDB types supported
- Additional types for pattern metadata
- Same binary format for compatibility

## Migration Path

### Quick Migration

1. **Replace includes**:
   ```c
   // Old
   #include <maxminddb.h>
   
   // New
   #include <matchy/maxminddb.h>
   ```

2. **Update open calls**:
   ```c
   // Old
   MMDB_s mmdb;
   int status = MMDB_open(filename, MMDB_MODE_MMAP, &mmdb);
   
   // New
   matchy_t *db = matchy_open(filename);
   if (!db) { /* error */ }
   ```

3. **Update lookups**:
   ```c
   // Old
   int gai_error, mmdb_error;
   MMDB_lookup_result result = MMDB_lookup_string(&mmdb, ip, 
                                                   &gai_error, &mmdb_error);
   
   // New
   matchy_result_t *result = NULL;
   int32_t err = matchy_lookup(db, ip, &result);
   if (err == MATCHY_SUCCESS && result) {
       // Use result
       matchy_free_result(result);
   }
   ```

### Gradual Migration

For large codebases:
1. Use both libraries side-by-side
2. Migrate one component at a time
3. Test thoroughly
4. Switch fully when ready

## Binary Compatibility

Matchy databases are **forward-compatible** with MMDB:
- Standard MMDB metadata section
- Compatible binary format
- PARAGLOB extensions in separate section

Existing MMDB tools can read Matchy databases (ignoring pattern data).

## Performance

Matchy provides similar or better performance:
- **IP lookups**: Same O(n) binary trie
- **Memory usage**: Memory-mapped like MMDB
- **Load time**: <1ms for any size
- **Additional**: Pattern matching at no cost to IP lookups

## Limitations

### Not Supported

- MMDB metadata queries (use `matchy inspect` instead)
- Custom memory allocators
- Legacy MMDB v1 format

### Planned

- Full MMDB API compatibility shim
- Automatic format detection
- Transparent fallback to libmaxminddb

## See Also

- [MMDB Compatibility Guide](../guide/mmdb-compatibility.md) - User guide
- [Migrating from libmaxminddb](../guide/migrating-libmaxminddb.md) - Step-by-step migration
- [C API Overview](c-api.md) - Native Matchy C API
- [Binary Format](binary-format.md) - Database format specification
