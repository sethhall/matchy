# MMDB Integration

Technical reference for MaxMind DB (MMDB) compatibility layer.

## Overview

Matchy provides a compatibility layer that allows existing `libmaxminddb` applications to use Matchy databases with minimal code changes.

## Compatibility Header

```c
#include <matchy/maxminddb.h>
```

Provides source-level counterparts for commonly used `libmaxminddb` functions.
The compatibility layer is not ABI-compatible and does not implement every
low-level libmaxminddb behavior.

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
| `MMDB_lookup_string()` | `matchy_query()` |
| `MMDB_lookup_sockaddr()` | `matchy_query()` with a string form of the address |

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

Most Matchy C helpers use integer error codes. Queries return a result struct:
```c
matchy_result_t result = matchy_query(db, "192.0.2.1");
if (result.found) {
    // Use result
}
```

vs. libmaxminddb status codes:
```c
int gai_error, mmdb_error;
MMDB_lookup_result result = MMDB_lookup_string(mmdb, "192.0.2.1", 
                                                &gai_error, &mmdb_error);
```

### 3. Result Lifetime

Matchy query results are offset-only structs that own no decoded data (the
matcher may still grow bounded thread-local scratch on a cold string query):
```c
matchy_result_t result = matchy_query(db, query);
if (result.found) {
    // Use result
}
matchy_free_result(&result);  // No-op today; kept for ABI compatibility
```

### 4. Data Types

Matchy supports the standard MMDB data types and also defines a Matchy-only
`Timestamp` extended type 128. Standard MMDB readers cannot decode that type.
Matchy's decoder also enforces pointer-depth, nesting, work, and allocation
limits; these safety limits are not part of the MMDB format itself.

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
   matchy_result_t result = matchy_query(db, ip);
   if (result.found) {
       // Use result
       matchy_free_result(&result);
   }
   ```

### Gradual Migration

For large codebases:
1. Use both libraries side-by-side
2. Migrate one component at a time
3. Test thoroughly
4. Switch fully when ready

## Binary Compatibility

Matchy databases use:

- A standard MMDB tree, separator, metadata section, and standard data encodings
- Optional PARAGLOB and literal-hash sections outside tree-referenced data
- An optional Matchy-only `Timestamp` value type

Existing MMDB tools can ignore the text-index sections and read IP records whose
values use only standard MMDB types. They cannot decode Matchy `Timestamp`
values.

## Performance

Matchy uses the same broad MMDB tree and memory-mapping design:

- **IP lookups**: Same O(n) binary trie
- **Memory usage**: Memory-mapped like MMDB
- **Opening**: Memory-mapped and avoids whole-file deserialization; latency depends on storage, cache state, platform, extensions, and legacy scanning
- **Additional**: Optional text indexes do not participate in IP tree traversal, but they do add file size and open-time validation work

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
