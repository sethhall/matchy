# Memory Management

Memory management guidelines for the Matchy C API.

## Overview

The Matchy C API uses clear ownership semantics:

- **Opaque handles** - No direct struct access
- **Explicit free functions** - No hidden deallocations
- **Clear ownership** - Who owns what is always clear
- **No hidden allocations** - All allocations are explicit

## Ownership Rules

### Builder Ownership

```c
// YOU own the builder after creation
matchy_builder_t *builder = matchy_builder_new();

// YOU must free it
matchy_builder_free(builder);
```

### Database Ownership

```c
// YOU own the database after opening
matchy_t *db = matchy_open("database.mxy");

// YOU must close it
matchy_close(db);
```

### Result Ownership

```c
// Result is stack-allocated but may contain heap data
matchy_result_t result = matchy_query(db, "query");

// If found, YOU must free internal resources
if (result.found) {
    matchy_free_result(&result);
}
```

## Memory Safety Patterns

### Always Check for NULL

```c
matchy_t *db = matchy_open("database.mxy");
if (!db) {
    // Handle error - no cleanup needed
    return 1;
}

// Use db...

// Always clean up
matchy_close(db);
```

### Free in Reverse Order

```c
// Create
matchy_builder_t *builder = matchy_builder_new();
matchy_result_t result;

// Use
matchy_builder_add(builder, "1.2.3.4", "{}");

// Free in reverse order
if (result.found) {
    matchy_free_result(&result);
}
matchy_builder_free(builder);
```

### Error Handling

```c
matchy_builder_t *builder = matchy_builder_new();
if (!builder) {
    return 1;  // No cleanup needed
}

int status = matchy_builder_add(builder, key, data);
if (status != MATCHY_SUCCESS) {
    matchy_builder_free(builder);  // Clean up on error
    return 1;
}

// Continue...
matchy_builder_free(builder);
```

## Thread Safety

### Building (Not Thread-Safe)

```c
// Builder is NOT thread-safe
// Only use from one thread at a time
matchy_builder_t *builder = matchy_builder_new();
matchy_builder_add(builder, "1.2.3.4", "{}");
matchy_builder_free(builder);
```

### Querying (Thread-Safe)

```c
// Database is read-only and thread-safe after opening
matchy_t *db = matchy_open("database.mxy");

// Multiple threads can query simultaneously
#pragma omp parallel for
for (int i = 0; i < query_count; i++) {
    matchy_result_t result = matchy_query(db, queries[i]);
    if (result.found) {
        // Process...
        matchy_free_result(&result);
    }
}

matchy_close(db);
```

## Common Patterns

### RAII-Style Cleanup (C++)

```cpp
class MatchyDatabase {
public:
    MatchyDatabase(const char *path)
        : db_(matchy_open(path)) {
        if (!db_) throw std::runtime_error("Failed to open database");
    }
    
    ~MatchyDatabase() {
        if (db_) matchy_close(db_);
    }
    
    // Delete copy
    MatchyDatabase(const MatchyDatabase&) = delete;
    MatchyDatabase& operator=(const MatchyDatabase&) = delete;
    
    matchy_t* get() const { return db_; }
    
private:
    matchy_t *db_;
};
```

### Cleanup Macros (C)

```c
#define CLEANUP_BUILDER __attribute__((cleanup(cleanup_builder)))
#define CLEANUP_DB __attribute__((cleanup(cleanup_db)))

static void cleanup_builder(matchy_builder_t **builder) {
    if (*builder) matchy_builder_free(*builder);
}

static void cleanup_db(matchy_t **db) {
    if (*db) matchy_close(*db);
}

// Usage (GCC/Clang)
int main() {
    CLEANUP_BUILDER matchy_builder_t *builder = matchy_builder_new();
    CLEANUP_DB matchy_t *db = matchy_open("database.mxy");
    
    // Automatically cleaned up on scope exit
    return 0;
}
```

## Memory Mapping

Databases use memory mapping:

```c
// Opening is fast - just mmaps the file
matchy_t *db = matchy_open("database.mxy");

// Multiple processes share the same pages in RAM
// No duplication - OS handles sharing

// Closing unmaps the file
matchy_close(db);
```

## Valgrind

Check for leaks:

```bash
valgrind --leak-check=full --show-leak-kinds=all ./myapp
```

Expected output:
```
All heap blocks were freed -- no leaks are possible
```

## See Also

- [C API Overview](c-api.md) - C API introduction
- [Building Databases](c-building.md) - Builder API
- [Querying from C](c-querying.md) - Query API
