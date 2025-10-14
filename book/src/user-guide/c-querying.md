# Querying from C

Query Matchy databases from C applications.

## Basic Usage

```c
#include "matchy.h"

int main() {
    // Open database
    matchy_t *db = matchy_open("threats.mxy");
    if (!db) {
        fprintf(stderr, "Failed to open database\n");
        return 1;
    }
    
    // Query
    matchy_result_t result = matchy_query(db, "1.2.3.4");
    if (result.found) {
        printf("Match found!\n");
        if (result.prefix_len > 0) {
            printf("CIDR: /%d\n", result.prefix_len);
        }
        matchy_free_result(&result);
    }
    
    // Close
    matchy_close(db);
    return 0;
}
```

## Opening Databases

### Standard Mode

```c
matchy_t *db = matchy_open("database.mxy");
if (!db) {
    fprintf(stderr, "Failed to open database\n");
    return 1;
}
```

### Trusted Mode (Faster)

```c
// Skip UTF-8 validation - only for databases you control
matchy_t *db = matchy_open_trusted("my-database.mxy");
```

## Query Results

```c
typedef struct {
    bool found;         // Whether a match was found
    uint8_t prefix_len; // CIDR prefix length (for IP matches)
    void *_data_cache;  // Internal (opaque)
    void *_db_ref;      // Internal (opaque)
} matchy_result_t;
```

### Checking Results

```c
matchy_result_t result = matchy_query(db, query);

if (result.found) {
    printf("Match found\n");
    
    // For IP matches, check prefix
    if (result.prefix_len > 0) {
        printf("Matched CIDR: /%d\n", result.prefix_len);
    }
    
    // Always free result
    matchy_free_result(&result);
} else {
    printf("No match\n");
}
```

## Database Information

```c
// Get entry count
uint64_t count = matchy_entry_count(db);
printf("Database has %llu entries\n", count);
```

## Complete Example

```c
#include "matchy.h"
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <database> <query>...\n", argv[0]);
        return 1;
    }
    
    matchy_t *db = matchy_open(argv[1]);
    if (!db) {
        fprintf(stderr, "Failed to open: %s\n", argv[1]);
        return 1;
    }
    
    // Query all arguments
    for (int i = 2; i < argc; i++) {
        matchy_result_t result = matchy_query(db, argv[i]);
        
        if (result.found) {
            printf("%s: MATCH", argv[i]);
            if (result.prefix_len > 0) {
                printf(" (CIDR: /%d)", result.prefix_len);
            }
            printf("\n");
            matchy_free_result(&result);
        } else {
            printf("%s: no match\n", argv[i]);
        }
    }
    
    matchy_close(db);
    return 0;
}
```

## See Also

- [C API Overview](c-api.md) - C API introduction
- [Building Databases](c-building.md) - Build databases from C
- [Memory Management](c-memory.md) - Memory safety
