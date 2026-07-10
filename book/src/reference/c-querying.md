# C Querying

The current C query API uses an offset-only result struct that owns no decoded
data. Cold string queries can still grow bounded thread-local matcher scratch;
steady-state queries reuse it. Queries return
`matchy_result_t` by value, or write into caller-provided storage with
`matchy_query_into()`.

An offset-only result from an auto-reloading handle is not bound to the database
generation that produced it. If a reload can occur between `matchy_query()` and
JSON/entry navigation, the token may refer to different bytes. Use a
non-watching handle when deferred data access must be snapshot-stable.

## Opening Databases

```c
matchy_t *matchy_open(const char *filename);
```

```c
matchy_t *db = matchy_open("database.mxy");
if (db == NULL) {
    fprintf(stderr, "failed to open database\n");
    return 1;
}
```

Open from memory:

```c
matchy_t *matchy_open_buffer(const uint8_t *buffer, uintptr_t size);
```

The buffer must be valid for the duration of the call. Matchy copies the bytes
before returning, so the caller may release or reuse the input buffer after
`matchy_open_buffer()` returns.

## Querying

```c
matchy_result_t matchy_query(const matchy_t *db, const char *query);
```

`matchy_query()` automatically detects IP strings and otherwise performs string
lookup across literals and glob patterns.

```c
matchy_result_t result = matchy_query(db, "192.0.2.1");
if (!result.found) {
    printf("no match\n");
}
```

For bindings that prefer out-parameters:

```c
void matchy_query_into(
    const matchy_t *db,
    const char *query,
    matchy_result_t *result
);
```

```c
matchy_result_t result;
matchy_query_into(db, "test.example.com", &result);
```

## Result Handling

```c
typedef struct matchy_result_t {
    bool found;
    uint8_t prefix_len;
    uint8_t _result_type;   /* 0=not found, 1=ip, 2=pattern */
    uint32_t _data_offset;
    const matchy_t *_db_ref;
} matchy_result_t;
```

Use `found` for match detection. `prefix_len` is populated for IP results.
The `_result_type`, `_data_offset`, and `_db_ref` fields are exposed by the C
ABI but should be treated as implementation details outside low-level bindings.

Convert a result to JSON:

```c
matchy_result_t result = matchy_query(db, "8.8.8.8");
if (result.found) {
    char *json = matchy_result_to_json(&result);
    if (json != NULL) {
        puts(json);
        matchy_free_string(json);
    }
}
matchy_free_result(&result);
```

Access structured data:

```c
matchy_entry_s entry = {0};
if (matchy_result_get_entry(&result, &entry) == MATCHY_SUCCESS) {
    const char *path[] = {"country", "iso_code", NULL};
    matchy_entry_data_t data = {0};

    if (matchy_aget_value(&entry, &data, path) == MATCHY_SUCCESS &&
        data.type_ == MATCHY_DATA_TYPE_UTF8_STRING) {
        printf("country: %.*s\n",
               (int)data.data_size,
               data.value.utf8_string);
    }
}
```

String and byte pointers returned through `matchy_aget_value()` remain valid
until `matchy_close(db)`. The handle retains successful returned allocations
without eviction under a 64 MiB estimated-storage cap. Exhaustion preserves all
earlier pointers and returns `MATCHY_ERROR_OUT_OF_MEMORY` for a new retained
value. Use `matchy_get_entry_data_list()` plus
`matchy_free_entry_data_list()` when caller-controlled reclamation is required;
each list has its own 64 MiB aggregate cap.

## Complete Example

```c
#include <matchy/matchy.h>
#include <stdio.h>

int main(void) {
    matchy_t *db = matchy_open("database.mxy");
    if (db == NULL) {
        fprintf(stderr, "failed to open database\n");
        return 1;
    }

    const char *queries[] = {
        "192.0.2.1",
        "test.example.com",
        "notfound.example",
    };

    for (size_t i = 0; i < sizeof(queries) / sizeof(queries[0]); i++) {
        matchy_result_t result = matchy_query(db, queries[i]);
        if (!result.found) {
            printf("%s: no match\n", queries[i]);
            matchy_free_result(&result);
            continue;
        }

        char *json = matchy_result_to_json(&result);
        if (json != NULL) {
            printf("%s: %s\n", queries[i], json);
            matchy_free_string(json);
        } else {
            printf("%s: match\n", queries[i]);
        }

        matchy_free_result(&result);
    }

    matchy_close(db);
    return 0;
}
```

## Performance Tips

- Reuse a `matchy_t *` handle instead of opening per query.
- Use `matchy_query_into()` for FFI layers that avoid by-value struct returns.
- Repeated string queries benefit from the built-in per-thread LRU cache.
- Keep the database handle open while inspecting a result; result data is offset
  based and depends on the open database.

## Error Codes

Most query calls return an empty `matchy_result_t` for invalid parameters or
misses. Data navigation helpers return integer status codes:

- `MATCHY_SUCCESS` (0)
- `MATCHY_ERROR_OUT_OF_MEMORY` (-4)
- `MATCHY_ERROR_INVALID_PARAM` (-5)
- `MATCHY_ERROR_NO_DATA` (-10)
- `MATCHY_ERROR_DATA_PARSE` (-11)

## See Also

- [C API Overview](c-api.md)
- [C Memory Management](c-memory.md)
- [Data Types Reference](data-types-ref.md)
