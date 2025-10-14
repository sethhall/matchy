# Migrating from libmaxminddb

Matchy provides a **compatibility layer** that implements the libmaxminddb API on top of matchy's engine. Most existing libmaxminddb applications can switch to matchy with minimal code changes.

## Quick Start

### Before (libmaxminddb)

```c
#include <maxminddb.h>

// Compile: gcc -o app app.c -lmaxminddb
```

### After (matchy)

```c
#include <matchy/maxminddb.h>

// Compile: gcc -o app app.c -lmatchy
```

**That's it!** Most applications will work with just these changes.

## Why Migrate?

Benefits of switching to matchy:

1. **Unified database format**: IP addresses + string patterns + exact strings in one file
2. **Better performance**: Faster loads, optimized queries
3. **Memory-mapped by default**: Instant startup times
4. **Active development**: Modern codebase in Rust
5. **Drop-in compatibility**: Minimal code changes required

## Migration Steps

### 1. Update Include Path

**Before:**
```c
#include <maxminddb.h>
```

**After:**
```c
#include <matchy/maxminddb.h>
```

### 2. Update Linker Flags

**Before:**
```bash
gcc -o myapp myapp.c -lmaxminddb
```

**After:**
```bash
gcc -o myapp myapp.c -I/path/to/matchy/include -L/path/to/matchy/lib -lmatchy
```

Or with pkg-config:
```bash
gcc -o myapp myapp.c $(pkg-config --cflags --libs matchy)
```

### 3. Recompile

The compatibility layer is **API compatible** but **NOT binary compatible**. You must recompile your application.

```bash
make clean
make
```

### 4. Test

Your existing `.mmdb` files should work without modification:

```bash
./myapp /path/to/GeoLite2-City.mmdb
```

## Complete Example

### Original libmaxminddb Code

```c
#include <maxminddb.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <database> <ip>\n", argv[0]);
        exit(1);
    }
    
    const char *database = argv[1];
    const char *ip_address = argv[2];
    
    MMDB_s mmdb;
    int status = MMDB_open(database, MMDB_MODE_MMAP, &mmdb);
    
    if (status != MMDB_SUCCESS) {
        fprintf(stderr, "Can't open %s: %s\n", 
            database, MMDB_strerror(status));
        exit(1);
    }
    
    int gai_error, mmdb_error;
    MMDB_lookup_result_s result = MMDB_lookup_string(
        &mmdb, ip_address, &gai_error, &mmdb_error);
    
    if (gai_error != 0) {
        fprintf(stderr, "Error from getaddrinfo: %s\n",
            gai_strerror(gai_error));
        exit(1);
    }
    
    if (mmdb_error != MMDB_SUCCESS) {
        fprintf(stderr, "Lookup error: %s\n",
            MMDB_strerror(mmdb_error));
        exit(1);
    }
    
    if (result.found_entry) {
        MMDB_entry_data_s entry_data;
        
        // Get country ISO code
        status = MMDB_get_value(&result.entry, &entry_data,
            "country", "iso_code", NULL);
        
        if (status == MMDB_SUCCESS && entry_data.has_data &&
            entry_data.type == MMDB_DATA_TYPE_UTF8_STRING) {
            printf("%.*s\n", entry_data.data_size, entry_data.utf8_string);
        }
    } else {
        printf("No entry found for %s\n", ip_address);
    }
    
    MMDB_close(&mmdb);
    return 0;
}
```

### Migrated to Matchy

```c
#include <matchy/maxminddb.h>  // Only change: include path
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <database> <ip>\n", argv[0]);
        exit(1);
    }
    
    const char *database = argv[1];
    const char *ip_address = argv[2];
    
    MMDB_s mmdb;
    int status = MMDB_open(database, MMDB_MODE_MMAP, &mmdb);
    
    if (status != MMDB_SUCCESS) {
        fprintf(stderr, "Can't open %s: %s\n", 
            database, MMDB_strerror(status));
        exit(1);
    }
    
    int gai_error, mmdb_error;
    MMDB_lookup_result_s result = MMDB_lookup_string(
        &mmdb, ip_address, &gai_error, &mmdb_error);
    
    if (gai_error != 0) {
        fprintf(stderr, "Error from getaddrinfo: %s\n",
            gai_strerror(gai_error));
        exit(1);
    }
    
    if (mmdb_error != MMDB_SUCCESS) {
        fprintf(stderr, "Lookup error: %s\n",
            MMDB_strerror(mmdb_error));
        exit(1);
    }
    
    if (result.found_entry) {
        MMDB_entry_data_s entry_data;
        
        // Get country ISO code
        status = MMDB_get_value(&result.entry, &entry_data,
            "country", "iso_code", NULL);
        
        if (status == MMDB_SUCCESS && entry_data.has_data &&
            entry_data.type == MMDB_DATA_TYPE_UTF8_STRING) {
            printf("%.*s\n", entry_data.data_size, entry_data.utf8_string);
        }
    } else {
        printf("No entry found for %s\n", ip_address);
    }
    
    MMDB_close(&mmdb);
    return 0;
}
```

**Differences:** Only the `#include` line changed!

## Compatibility Matrix

### Fully Supported Functions

These functions work identically to libmaxminddb:

| Function | Status | Notes |
|----------|--------|-------|
| `MMDB_open()` | ✅ Full | Opens `.mmdb` files |
| `MMDB_close()` | ✅ Full | Closes database |
| `MMDB_lookup_string()` | ✅ Full | IP string lookup |
| `MMDB_lookup_sockaddr()` | ✅ Full | sockaddr lookup |
| `MMDB_get_value()` | ✅ Full | Navigate data structures |
| `MMDB_vget_value()` | ✅ Full | va_list variant |
| `MMDB_aget_value()` | ✅ Full | Array variant |
| `MMDB_get_entry_data_list()` | ✅ Full | Full data traversal |
| `MMDB_free_entry_data_list()` | ✅ Full | Free list |
| `MMDB_lib_version()` | ✅ Full | Returns matchy version |
| `MMDB_strerror()` | ✅ Full | Error messages |

### Stub Functions (Not Implemented)

These rarely-used functions return errors:

| Function | Status | Notes |
|----------|--------|-------|
| `MMDB_read_node()` | ⚠️ Stub | Low-level tree access (rarely used) |
| `MMDB_dump_entry_data_list()` | ⚠️ Stub | Debugging function (rarely used) |
| `MMDB_get_metadata_as_entry_data_list()` | ⚠️ Stub | Metadata access (rarely used) |

If your application uses these functions, please [open an issue](https://github.com/your-repo/issues).

## Important Differences

### 1. Binary Compatibility

**Not binary compatible** - you must **recompile** your application.

The `MMDB_s` struct has a different internal layout:

```c
// libmaxminddb (many internal fields)
typedef struct MMDB_s {
    // ... many implementation details
} MMDB_s;

// matchy (simpler, wraps matchy handle)
typedef struct MMDB_s {
    matchy_t *_matchy_db;
    uint32_t flags;
    const char *filename;
    ssize_t file_size;
} MMDB_s;
```

**Impact:** Applications that directly access `MMDB_s` fields may break. Most applications only pass the pointer around and should be fine.

### 2. Threading Model

**libmaxminddb:** Thread-safe for reads after open

**matchy:** Also thread-safe for reads after open

Both libraries are safe to use from multiple threads for lookups. No changes needed.

### 3. Memory Mapping

**libmaxminddb:** Optional with `MMDB_MODE_MMAP`

**matchy:** Always memory-mapped (flag accepted but ignored)

**Impact:** Better performance! Databases load instantly regardless of size.

### 4. Error Codes

Matchy uses the same error code numbers and names. Error handling code should work unchanged:

```c
if (status != MMDB_SUCCESS) {
    fprintf(stderr, "Error: %s\n", MMDB_strerror(status));
}
```

## Build System Updates

### Makefile

**Before:**
```makefile
CFLAGS = -Wall -O2
LIBS = -lmaxminddb

myapp: myapp.c
	$(CC) $(CFLAGS) -o myapp myapp.c $(LIBS)
```

**After:**
```makefile
CFLAGS = -Wall -O2 -I/usr/local/include
LIBS = -L/usr/local/lib -lmatchy

myapp: myapp.c
	$(CC) $(CFLAGS) -o myapp myapp.c $(LIBS)
```

Or use pkg-config:
```makefile
CFLAGS = -Wall -O2 $(shell pkg-config --cflags matchy)
LIBS = $(shell pkg-config --libs matchy)

myapp: myapp.c
	$(CC) $(CFLAGS) -o myapp myapp.c $(LIBS)
```

### CMake

**Before:**
```cmake
find_package(MMDB REQUIRED)
target_link_libraries(myapp PRIVATE MMDB::MMDB)
```

**After:**
```cmake
find_package(PkgConfig REQUIRED)
pkg_check_modules(MATCHY REQUIRED matchy)

target_include_directories(myapp PRIVATE ${MATCHY_INCLUDE_DIRS})
target_link_libraries(myapp PRIVATE ${MATCHY_LIBRARIES})
```

### Autotools

**Before:**
```bash
./configure
make
```

**After:**
```bash
./configure CFLAGS="$(pkg-config --cflags matchy)" \
            LDFLAGS="$(pkg-config --libs matchy)"
make
```

## Testing Your Migration

### 1. Compile Test

```bash
gcc -o test_migration test.c \
    -I/usr/local/include \
    -L/usr/local/lib \
    -lmatchy

./test_migration GeoLite2-City.mmdb 8.8.8.8
```

### 2. Functional Test

Verify results match libmaxminddb:

```bash
# With libmaxminddb
./old_binary database.mmdb 8.8.8.8 > old_output.txt

# With matchy
./new_binary database.mmdb 8.8.8.8 > new_output.txt

# Compare
diff old_output.txt new_output.txt
```

### 3. Performance Test

Matchy should be faster or comparable:

```bash
# Benchmark lookups
time ./myapp database.mmdb < ip_list.txt
```

## Performance Considerations

### Load Time

Both libraries use memory-mapping:

**libmaxminddb:**
- Uses memory-mapping when MMDB_MODE_MMAP is specified
- Load time depends on disk I/O and OS page cache state

**matchy:**
- Always memory-mapped
- Load time depends on disk I/O and OS page cache state

**Impact:** Similar load performance for IP lookups. Matchy's main advantage is supporting additional data types (strings, patterns) in the same database.

### Query Performance

For IP address lookups (what libmaxminddb does), both libraries have similar performance:
- Both use binary trie traversal
- Sub-microsecond latency typical
- Performance is comparable

**Impact:** Migration should not significantly affect IP lookup performance. Matchy's benefits are in unified database format and additional query types.

### Memory Usage

**libmaxminddb:** Memory-mapped when using MMAP mode, only active pages loaded

**matchy:** Memory-mapped, only active pages loaded

**Impact:** Similar memory footprint for IP-only databases.

## Troubleshooting

### Compilation Errors

**Error:** `maxminddb.h: No such file or directory`

**Solution:** Check include path:
```bash
gcc -I/usr/local/include/matchy ...
```

**Error:** `undefined reference to MMDB_open`

**Solution:** Add matchy library:
```bash
gcc ... -lmatchy
```

### Runtime Errors

**Error:** `./myapp: error while loading shared libraries: libmatchy.so`

**Solution:** Set library path:
```bash
export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH
```

Or install system-wide:
```bash
sudo ldconfig
```

### Behavior Differences

**Issue:** Results differ slightly from libmaxminddb

**Check:**
1. Are you using the same database file?
2. Is the database corrupted? Try `matchy validate database.mmdb`
3. Are there API usage differences?

## Using Native Matchy Features

After migration, you can optionally use matchy-specific features:

### Pattern Matching

Matchy databases can include string patterns:

```c
// Use native matchy API alongside MMDB API
#include <matchy/maxminddb.h>
#include <matchy/matchy.h>

// IP lookup with MMDB API
MMDB_lookup_result_s result = MMDB_lookup_string(&mmdb, "8.8.8.8", ...);

// Pattern matching with matchy API
// Query with a string, database contains patterns like "*.google.com"
matchy_result_t *pattern_result = NULL;
matchy_lookup(db, "www.google.com", &pattern_result);
```

### Building Enhanced Databases

Use `matchy build` to create databases with both IP and pattern data:

```bash
matchy build -i ips.csv -i patterns.csv -o enhanced.mxy
```

Then query with the MMDB compatibility API as usual.

## FAQ

### Q: Do I need to convert my .mmdb files?

**A:** No! Matchy reads standard `.mmdb` files directly.

### Q: Can I use both libmaxminddb and matchy in the same project?

**A:** Not recommended. They have overlapping symbols. Choose one.

### Q: Is matchy slower than libmaxminddb?

**A:** For IP address lookups, performance is similar - both use memory-mapped binary tries. Matchy's advantage is supporting additional query types (patterns, strings) in a unified database format.

### Q: What if a function I need isn't implemented?

**A:** Please [open an issue](https://github.com/your-repo/issues) with your use case.

### Q: Can I contribute MMDB compatibility improvements?

**A:** Yes! See [Contributing](../contributing.md).

## Next Steps

After migration:

1. ✅ **Test thoroughly** with your production data
2. 📊 **Benchmark** to verify performance improvements
3. 🎯 **Explore** matchy-specific features (patterns, validation)
4. 📖 **Read** the [C API Reference](../reference/c-api.md)
5. 🚀 **Deploy** with confidence

## Getting Help

- **Documentation:** [C API Reference](../reference/c-api.md)
- **Issues:** Report bugs or request features
- **Examples:** See [examples/](../appendix/examples.md)
- **Community:** Join discussions

## See Also

- [C API Overview](../reference/c-api.md) - Native matchy C API
- [First Database with C](../getting-started/api-c-first.md) - C tutorial
- [MMDB Compatibility](mmdb-compatibility.md) - Format compatibility details
