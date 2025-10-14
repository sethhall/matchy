# C Querying

Query operations and result handling in the Matchy C API.

## Overview

The C API provides functions to open databases and perform queries against IPs, strings, and patterns. All query functions are **thread-safe** for concurrent reads.

## Opening Databases

### Open from File

```c
matchy_t *matchy_open(const char *filename);
```

Opens a database file with validation:
- Memory-maps the file
- Validates MMDB structure
- Checks PARAGLOB section
- **Validates all UTF-8** strings

Returns `NULL` on error.

**Example:**
```c
matchy_t *db = matchy_open("database.mxy");
if (!db) {
    fprintf(stderr, "Failed to open database\n");
    return 1;
}

// Use db...

matchy_close(db);
```

### Open Trusted Database

```c
matchy_t *matchy_open_trusted(const char *filename);
```

Opens a database **without UTF-8 validation**:
- ~15-20% faster than `matchy_open()`
- Use **only** for databases you control
- Unsafe for untrusted sources

**Example:**
```c
// Safe: database created by your own application
matchy_t *db = matchy_open_trusted("internal.mxy");
```

**⚠️ Warning:** Never use with databases from untrusted sources!

### Open from Buffer

```c
matchy_t *matchy_open_buffer(const uint8_t *buffer, uintptr_t size);
```

Opens a database from memory:
- Buffer must remain valid for database lifetime
- No file I/O required
- Useful for embedded databases

**Example:**
```c
uint8_t *buffer = load_database_somehow();
uintptr_t size = get_database_size();

matchy_t *db = matchy_open_buffer(buffer, size);
if (!db) {
    free(buffer);
    return 1;
}

// Query db...

matchy_close(db);
free(buffer);  // Safe to free after close
```

## Query Operations

### Unified Lookup

```c
int32_t matchy_lookup(matchy_t *db, 
                      const char *text, 
                      matchy_result_t **result);
```

Queries the database with automatic type detection:
- **IP address**: Parses as IPv4 or IPv6
- **Domain/string**: Searches patterns and exact strings
- **Other text**: Pattern matching only

Returns:
- `MATCHY_SUCCESS` (0) on success
- Error code on failure
- `*result` set to `NULL` if no match

**Example:**
```c
matchy_result_t *result = NULL;
int32_t err = matchy_lookup(db, "192.0.2.1", &result);

if (err != MATCHY_SUCCESS) {
    fprintf(stderr, "Query error: %d\n", err);
    return 1;
}

if (result != NULL) {
    printf("Match found!\n");
    matchy_free_result(result);
} else {
    printf("No match\n");
}
```

### IP Lookup

```c
int32_t matchy_lookup_ip(matchy_t *db, 
                         struct sockaddr *addr, 
                         matchy_result_t **result);
```

Direct IP lookup using `sockaddr`:
- Supports IPv4 (`sockaddr_in`)
- Supports IPv6 (`sockaddr_in6`)
- Faster than parsing text

**Example:**
```c
struct sockaddr_in addr = {0};
addr.sin_family = AF_INET;
addr.sin_addr.s_addr = inet_addr("192.0.2.1");

matchy_result_t *result = NULL;
int32_t err = matchy_lookup_ip(db, (struct sockaddr *)&addr, &result);

if (err == MATCHY_SUCCESS && result) {
    // Process result...
    matchy_free_result(result);
}
```

### String Lookup

```c
int32_t matchy_lookup_string(matchy_t *db, 
                             const char *text, 
                             matchy_result_t **result);
```

Pattern and exact string matching:
- Searches glob patterns
- Searches exact string table
- Returns first match

**Example:**
```c
matchy_result_t *result = NULL;
int32_t err = matchy_lookup_string(db, "test.example.com", &result);

if (err == MATCHY_SUCCESS && result) {
    printf("Matched pattern or exact string\n");
    matchy_free_result(result);
}
```

## Result Handling

### Get Result Type

```c
uint32_t matchy_result_type(const matchy_result_t *result);
```

Returns the match type:
- `MATCHY_RESULT_IP` (1) - IP address match
- `MATCHY_RESULT_PATTERN` (2) - Pattern match
- `MATCHY_RESULT_EXACT_STRING` (3) - Exact string match

**Example:**
```c
uint32_t type = matchy_result_type(result);

switch (type) {
case MATCHY_RESULT_IP:
    printf("IP match\n");
    break;
case MATCHY_RESULT_PATTERN:
    printf("Pattern match\n");
    break;
case MATCHY_RESULT_EXACT_STRING:
    printf("Exact string match\n");
    break;
}
```

### Get Entry Data

```c
int32_t matchy_result_get_entry(const matchy_result_t *result,
                                matchy_entry_s *entry);
```

Extracts structured data from the result:

**Example:**
```c
matchy_entry_s entry = {0};
if (matchy_result_get_entry(result, &entry) == MATCHY_SUCCESS) {
    // Entry contains structured data
    // See Data Types Reference for details
}
```

### Extract Entry Data

```c
int32_t matchy_aget_value(const matchy_entry_s *entry,
                          matchy_entry_data_t *data,
                          const char *const *path);
```

Navigates structured data:

**Example:**
```c
matchy_entry_s entry = {0};
matchy_result_get_entry(result, &entry);

const char *path[] = {"metadata", "country", NULL};
matchy_entry_data_t data = {0};

if (matchy_aget_value(&entry, &data, path) == MATCHY_SUCCESS) {
    if (data.type == MATCHY_DATA_TYPE_UTF8_STRING) {
        printf("Country: %s\n", data.value.utf8_string);
    }
}
```

## Complete Examples

### Single Query

```c
#include <matchy/matchy.h>
#include <stdio.h>

int main(void) {
    // Open database
    matchy_t *db = matchy_open("database.mxy");
    if (!db) {
        fprintf(stderr, "Failed to open database\n");
        return 1;
    }
    
    // Query
    matchy_result_t *result = NULL;
    int32_t err = matchy_lookup(db, "192.0.2.1", &result);
    
    if (err != MATCHY_SUCCESS) {
        fprintf(stderr, "Query failed: %d\n", err);
        matchy_close(db);
        return 1;
    }
    
    if (result) {
        printf("Match found!\n");
        matchy_free_result(result);
    } else {
        printf("No match\n");
    }
    
    matchy_close(db);
    return 0;
}
```

### Batch Queries

```c
void batch_query(matchy_t *db, const char **queries, size_t count) {
    for (size_t i = 0; i < count; i++) {
        matchy_result_t *result = NULL;
        
        if (matchy_lookup(db, queries[i], &result) == MATCHY_SUCCESS) {
            if (result) {
                printf("%s: MATCH\n", queries[i]);
                matchy_free_result(result);
            } else {
                printf("%s: no match\n", queries[i]);
            }
        }
    }
}
```

### Multi-threaded Queries

```c
#include <pthread.h>

struct query_args {
    matchy_t *db;
    const char *query;
};

void *query_thread(void *arg) {
    struct query_args *args = arg;
    matchy_result_t *result = NULL;
    
    if (matchy_lookup(args->db, args->query, &result) == MATCHY_SUCCESS) {
        if (result) {
            printf("[%ld] Match: %s\n", 
                   (long)pthread_self(), args->query);
            matchy_free_result(result);
        }
    }
    
    return NULL;
}

int main(void) {
    matchy_t *db = matchy_open("database.mxy");
    if (!db) return 1;
    
    pthread_t threads[4];
    struct query_args args[4] = {
        {db, "192.0.2.1"},
        {db, "10.0.0.1"},
        {db, "example.com"},
        {db, "*.test.com"}
    };
    
    // Spawn threads (safe: db is thread-safe for reads)
    for (int i = 0; i < 4; i++) {
        pthread_create(&threads[i], NULL, query_thread, &args[i]);
    }
    
    // Wait for completion
    for (int i = 0; i < 4; i++) {
        pthread_join(threads[i], NULL);
    }
    
    matchy_close(db);
    return 0;
}
```

## Performance Tips

### 1. Reuse Database Handle

❌ **Slow:**
```c
for (int i = 0; i < 1000; i++) {
    matchy_t *db = matchy_open("database.mxy");
    matchy_lookup(db, queries[i], &result);
    matchy_close(db);
}
```

✅ **Fast:**
```c
matchy_t *db = matchy_open("database.mxy");
for (int i = 0; i < 1000; i++) {
    matchy_lookup(db, queries[i], &result);
    if (result) matchy_free_result(result);
}
matchy_close(db);
```

### 2. Use Trusted Mode for Known Databases

```c
// 15-20% faster for databases you control
matchy_t *db = matchy_open_trusted("internal.mxy");
```

### 3. Free Results Promptly

```c
matchy_result_t *result = NULL;
matchy_lookup(db, query, &result);

if (result) {
    // Extract what you need
    uint32_t type = matchy_result_type(result);
    
    // Free immediately
    matchy_free_result(result);
}
```

### 4. Use Direct IP Lookup

❌ **Slower:**
```c
matchy_lookup(db, "192.0.2.1", &result);  // Parses string
```

✅ **Faster:**
```c
struct sockaddr_in addr = /* ... */;
matchy_lookup_ip(db, (struct sockaddr *)&addr, &result);  // Direct
```

## Error Handling

### Check All Return Codes

```c
matchy_t *db = matchy_open(filename);
if (!db) {
    fprintf(stderr, "Open failed\n");
    return 1;
}

matchy_result_t *result = NULL;
int32_t err = matchy_lookup(db, query, &result);

if (err != MATCHY_SUCCESS) {
    fprintf(stderr, "Lookup failed: %d\n", err);
    matchy_close(db);
    return 1;
}

// Check for no match
if (!result) {
    printf("No match found\n");
}

matchy_close(db);
```

### Common Error Codes

- `MATCHY_SUCCESS` (0) - Success
- `MATCHY_ERROR_INVALID_PARAM` (-5) - NULL parameter
- `MATCHY_ERROR_FILE_NOT_FOUND` (-1) - File doesn't exist
- `MATCHY_ERROR_INVALID_FORMAT` (-2) - Corrupt database
- `MATCHY_ERROR_CORRUPT_DATA` (-3) - Data integrity error

## Thread Safety

### Safe: Concurrent Queries

```c
// Thread 1
matchy_lookup(db, "query1", &r1);

// Thread 2 (safe!)
matchy_lookup(db, "query2", &r2);
```

### Unsafe: Query During Close

```c
// Thread 1: Querying
matchy_lookup(db, query, &result);

// Thread 2: Closing (RACE CONDITION!)
matchy_close(db);
```

### Pattern: Thread-Safe Queries

```c
// Main thread
matchy_t *db = matchy_open("database.mxy");

// Spawn worker threads
// ... all threads use db safely ...

// Wait for all threads to finish
// ... join threads ...

// Only then close
matchy_close(db);
```

## See Also

- [C Memory Management](c-memory.md) - Cleanup and lifetimes
- [C API Overview](c-api.md) - API design
- [Data Types Reference](data-types-ref.md) - Structured data handling
- [Error Handling Reference](error-handling-ref.md) - Error codes
