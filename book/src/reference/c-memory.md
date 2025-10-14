# C Memory Management

Comprehensive guide to memory management in the Matchy C API.

## Overview

The Matchy C API uses **opaque handles** to manage Rust objects safely from C. Understanding the ownership and lifetime rules is critical for preventing memory leaks and use-after-free bugs.

## Core Principles

### 1. Ownership Model

- **Caller owns input strings** - Keep them valid for the duration of the function call
- **Callee owns output handles** - The library manages the underlying memory
- **Explicit cleanup required** - Always call the matching `_free()` or `_close()` function

### 2. No Double-Free

Once you call a cleanup function, the handle is invalid:

```c
matchy_builder_free(builder);
builder = NULL;  // Good practice: prevent use-after-free
```

### 3. Memory Lifetime

Handles remain valid until explicitly freed, even if the creating function returns.

## Cleanup Functions

### Database Handles

```c
void matchy_close(matchy_t *db);
```

Closes a database and frees associated resources:
- Unmaps the database file
- Releases internal buffers
- Invalidates the handle

**When to call**: After you're done querying the database

```c
matchy_t *db = NULL;
if (matchy_open("database.mxy", &db) == MATCHY_SUCCESS) {
    // Use db for queries...
    
    matchy_close(db);
    db = NULL;  // Good practice
}
```

### Builder Handles

```c
void matchy_builder_free(matchy_builder_t *builder);
```

Frees a builder and all associated entries:
- Releases all added entries
- Frees internal build state
- Invalidates the handle

**When to call**: After building or if build fails

```c
matchy_builder_t *builder = matchy_builder_new();
if (builder) {
    matchy_builder_add(builder, "key", NULL);
    // ... build or error ...
    
    matchy_builder_free(builder);
    builder = NULL;
}
```

### Result Handles

```c
void matchy_free_result(matchy_result_t *result);
```

Frees a query result:
- Releases match data
- Frees any associated strings
- Invalidates the handle

**When to call**: Immediately after extracting needed data

```c
matchy_result_t *result = NULL;
int32_t err = matchy_lookup(db, "192.0.2.1", &result);

if (err == MATCHY_SUCCESS && result != NULL) {
    // Extract data from result...
    
    matchy_free_result(result);
    result = NULL;
}
```

### String Handles

```c
void matchy_free_string(char *string);
```

Frees strings allocated by the library (e.g., error messages, validation results):

**When to call**: After using library-allocated strings

```c
char *error_msg = NULL;
int32_t err = matchy_validate("file.mxy", MATCHY_VALIDATION_STRICT, &error_msg);

if (err != MATCHY_SUCCESS && error_msg != NULL) {
    fprintf(stderr, "Validation error: %s\n", error_msg);
    matchy_free_string(error_msg);
}
```

### Entry Data Lists

```c
void matchy_free_entry_data_list(matchy_entry_data_list_t *list);
```

Frees structured data query results:

**When to call**: After processing entry data

```c
matchy_entry_data_list_t *list = NULL;
if (matchy_get_entry_data_list(entry, &list) == MATCHY_SUCCESS) {
    // Process list...
    
    matchy_free_entry_data_list(list);
}
```

## Common Patterns

### Pattern 1: Single Query

```c
void query_once(const char *db_path, const char *query) {
    matchy_t *db = NULL;
    
    // Open database
    if (matchy_open(db_path, &db) != MATCHY_SUCCESS) {
        return;
    }
    
    // Query
    matchy_result_t *result = NULL;
    if (matchy_lookup(db, query, &result) == MATCHY_SUCCESS) {
        if (result != NULL) {
            // Use result...
            matchy_free_result(result);
        }
    }
    
    // Cleanup
    matchy_close(db);
}
```

### Pattern 2: Multiple Queries

```c
void query_many(const char *db_path, const char **queries, size_t count) {
    matchy_t *db = NULL;
    
    if (matchy_open(db_path, &db) != MATCHY_SUCCESS) {
        return;
    }
    
    // Reuse database handle for multiple queries
    for (size_t i = 0; i < count; i++) {
        matchy_result_t *result = NULL;
        
        if (matchy_lookup(db, queries[i], &result) == MATCHY_SUCCESS) {
            if (result != NULL) {
                // Use result...
                matchy_free_result(result);
            }
        }
    }
    
    matchy_close(db);
}
```

### Pattern 3: Build and Query

```c
int build_and_query(void) {
    matchy_builder_t *builder = matchy_builder_new();
    if (!builder) {
        return -1;
    }
    
    // Build
    matchy_builder_add(builder, "key", "{\"value\": 42}");
    
    uint8_t *buffer = NULL;
    uintptr_t size = 0;
    int32_t err = matchy_builder_build(builder, &buffer, &size);
    
    // Builder no longer needed
    matchy_builder_free(builder);
    
    if (err != MATCHY_SUCCESS) {
        return -1;
    }
    
    // Open from buffer
    matchy_t *db = NULL;
    err = matchy_open_buffer(buffer, size, &db);
    
    if (err != MATCHY_SUCCESS) {
        free(buffer);
        return -1;
    }
    
    // Query
    matchy_result_t *result = NULL;
    matchy_lookup(db, "key", &result);
    
    if (result) {
        matchy_free_result(result);
    }
    
    matchy_close(db);
    free(buffer);
    
    return 0;
}
```

## Error Handling

### Early Returns

Always cleanup on error paths:

```c
matchy_t *db = NULL;
if (matchy_open(path, &db) != MATCHY_SUCCESS) {
    return -1;  // Nothing to cleanup
}

matchy_result_t *result = NULL;
if (matchy_lookup(db, query, &result) != MATCHY_SUCCESS) {
    matchy_close(db);  // Must cleanup db!
    return -1;
}

// Use result...

matchy_free_result(result);
matchy_close(db);
return 0;
```

### Goto Cleanup Pattern

For complex functions:

```c
int process(const char *path) {
    matchy_t *db = NULL;
    matchy_result_t *result = NULL;
    int ret = -1;
    
    if (matchy_open(path, &db) != MATCHY_SUCCESS) {
        goto cleanup;
    }
    
    if (matchy_lookup(db, "query", &result) != MATCHY_SUCCESS) {
        goto cleanup;
    }
    
    // Success path
    ret = 0;
    
cleanup:
    if (result) matchy_free_result(result);
    if (db) matchy_close(db);
    return ret;
}
```

## Thread Safety

### Database Handles

**Thread-safe for concurrent reads:**

```c
// Thread 1
matchy_result_t *r1 = NULL;
matchy_lookup(db, "query1", &r1);  // Safe
matchy_free_result(r1);

// Thread 2 (concurrent, safe)
matchy_result_t *r2 = NULL;
matchy_lookup(db, "query2", &r2);  // Safe
matchy_free_result(r2);
```

**Not safe for concurrent close:**

```c
// Thread 1: Querying
matchy_lookup(db, "query", &result);

// Thread 2: Closing (UNSAFE!)
matchy_close(db);  // Race condition!
```

### Builder Handles

**Not thread-safe** - use from a single thread:

```c
// UNSAFE:
matchy_builder_t *builder = matchy_builder_new();

// Thread 1
matchy_builder_add(builder, "key1", NULL);

// Thread 2
matchy_builder_add(builder, "key2", NULL);  // Race condition!
```

### Result Handles

**Not thread-safe** - each thread needs its own:

```c
// Safe: Each thread has its own result
void *thread1(void *arg) {
    matchy_t *db = arg;
    matchy_result_t *result = NULL;
    matchy_lookup(db, "query1", &result);
    matchy_free_result(result);
    return NULL;
}

void *thread2(void *arg) {
    matchy_t *db = arg;
    matchy_result_t *result = NULL;
    matchy_lookup(db, "query2", &result);
    matchy_free_result(result);
    return NULL;
}
```

## Common Mistakes

### Mistake 1: Forgetting to Free

❌ **Wrong:**
```c
for (int i = 0; i < 1000; i++) {
    matchy_result_t *result = NULL;
    matchy_lookup(db, queries[i], &result);
    // Memory leak! Never freed result
}
```

✅ **Correct:**
```c
for (int i = 0; i < 1000; i++) {
    matchy_result_t *result = NULL;
    matchy_lookup(db, queries[i], &result);
    if (result) {
        // Use result...
        matchy_free_result(result);
    }
}
```

### Mistake 2: Use After Free

❌ **Wrong:**
```c
matchy_result_t *result = NULL;
matchy_lookup(db, "query", &result);
matchy_free_result(result);

// Use after free!
int type = matchy_result_type(result);
```

✅ **Correct:**
```c
matchy_result_t *result = NULL;
matchy_lookup(db, "query", &result);

int type = matchy_result_type(result);

matchy_free_result(result);
result = NULL;  // Good practice
```

### Mistake 3: Double Free

❌ **Wrong:**
```c
matchy_free_result(result);
matchy_free_result(result);  // Double free! Undefined behavior
```

✅ **Correct:**
```c
if (result) {
    matchy_free_result(result);
    result = NULL;
}
```

### Mistake 4: Missing Cleanup on Error

❌ **Wrong:**
```c
matchy_t *db = NULL;
matchy_open(path, &db);

matchy_result_t *result = NULL;
if (matchy_lookup(db, query, &result) != MATCHY_SUCCESS) {
    return -1;  // Leak! Didn't close db
}
```

✅ **Correct:**
```c
matchy_t *db = NULL;
matchy_open(path, &db);

matchy_result_t *result = NULL;
if (matchy_lookup(db, query, &result) != MATCHY_SUCCESS) {
    matchy_close(db);
    return -1;
}
```

## Valgrind Testing

Use Valgrind to detect memory issues:

```bash
valgrind --leak-check=full \
         --show-leak-kinds=all \
         --track-origins=yes \
         ./your_program
```

A clean run should show:
```
HEAP SUMMARY:
    in use at exit: 0 bytes in 0 blocks
  total heap usage: X allocs, X frees, Y bytes allocated

All heap blocks were freed -- no leaks are possible
```

## See Also

- [C API Overview](c-api.md) - API design and principles
- [C Querying](c-querying.md) - Query operations
- [Building with C](c-building.md) - Compilation and linking
- [Error Handling Reference](error-handling-ref.md) - Error codes and handling
