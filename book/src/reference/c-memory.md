# C Memory Management

The Matchy C API uses opaque handles for long-lived Rust objects and
zero-allocation query results for lookups. Most cleanup rules are simple:
close database handles, free builders, free strings returned by Matchy, and free
extractor match arrays.

## Ownership Rules

- Input strings and buffers are owned by the caller and must remain valid for
  the duration of the call.
- `matchy_t *` handles are owned by the caller after `matchy_open()` or
  `matchy_open_buffer()` succeeds.
- `matchy_builder_t *` handles are owned by the caller after
  `matchy_builder_new()` succeeds.
- `matchy_result_t` is returned by value and does not own decoded heap data.
- Strings returned by Matchy must be released with `matchy_free_string()`.
- Extracted match arrays must be released with `matchy_matches_free()`.

## Database Handles

```c
matchy_t *db = matchy_open("database.mxy");
if (db == NULL) {
    return 1;
}

/* query db */

matchy_close(db);
db = NULL;
```

Do not call `matchy_close()` while another thread is querying the same handle.

## Builder Handles

```c
matchy_builder_t *builder = matchy_builder_new();
if (builder == NULL) {
    return 1;
}

int32_t err = matchy_builder_add(builder, "key", "{\"value\":42}");
if (err == MATCHY_SUCCESS) {
    err = matchy_builder_save(builder, "database.mxy");
}

matchy_builder_free(builder);
builder = NULL;
```

Builder handles are not thread-safe.

## Query Results

```c
matchy_result_t result = matchy_query(db, "192.0.2.1");
if (result.found) {
    /* inspect result */
}
matchy_free_result(&result);
```

`matchy_free_result()` is currently a no-op because `matchy_result_t` stores
offsets into the open database instead of owning heap allocations. Keeping the
call in code is still useful for ABI compatibility and future changes.

Any data accessed through a result depends on the database handle remaining
open. Do not close `db` before converting the result to JSON or reading entry
data.

## Strings Returned By Matchy

```c
matchy_result_t result = matchy_query(db, "8.8.8.8");
if (result.found) {
    char *json = matchy_result_to_json(&result);
    if (json != NULL) {
        puts(json);
        matchy_free_string(json);
    }
}
```

Only pass strings returned by Matchy to `matchy_free_string()`.

## Entry Data Lists

```c
matchy_entry_s entry = {0};
if (matchy_result_get_entry(&result, &entry) == MATCHY_SUCCESS) {
    matchy_entry_data_list_t *list = NULL;
    if (matchy_get_entry_data_list(&entry, &list) == MATCHY_SUCCESS) {
        /* walk list */
        matchy_free_entry_data_list(list);
    }
}
```

## Build To Buffer

`matchy_builder_build()` allocates a byte buffer for the caller. Free it with
the C allocator after `matchy_open_buffer()` returns.

```c
uint8_t *buffer = NULL;
uintptr_t size = 0;

if (matchy_builder_build(builder, &buffer, &size) == MATCHY_SUCCESS) {
    matchy_t *db = matchy_open_buffer(buffer, size);
    free(buffer);

    if (db != NULL) {
        matchy_result_t result = matchy_query(db, "key");
        matchy_free_result(&result);
        matchy_close(db);
    }
}
```

The buffer passed to `matchy_open_buffer()` only needs to remain valid for the
call itself because Matchy copies the bytes before returning.

## Extractor Matches

```c
matchy_extractor_t *extractor = matchy_extractor_create(MATCHY_EXTRACT_ALL);
matchy_matches_t matches;

if (matchy_extractor_extract_chunk(
        extractor,
        (const uint8_t *)text,
        strlen(text),
        &matches
    ) == MATCHY_SUCCESS) {
    for (size_t i = 0; i < matches.count; i++) {
        puts(matches.items[i].value);
    }
    matchy_matches_free(&matches);
}

matchy_extractor_free(extractor);
```

The `value` pointers inside `matchy_matches_t` are valid until
`matchy_matches_free()` is called.

## Cleanup Pattern

```c
int process(const char *path, const char *query) {
    int ret = 1;
    matchy_t *db = matchy_open(path);
    if (db == NULL) {
        return ret;
    }

    matchy_result_t result = matchy_query(db, query);
    if (result.found) {
        ret = 0;
    }

    matchy_free_result(&result);
    matchy_close(db);
    return ret;
}
```

## Common Mistakes

Use after close:

```c
matchy_result_t result = matchy_query(db, "query");
matchy_close(db);
/* Wrong: result depends on db for data decoding */
char *json = matchy_result_to_json(&result);
```

Double close:

```c
matchy_close(db);
matchy_close(db);  /* undefined behavior */
```

Forgetting returned strings:

```c
char *json = matchy_result_to_json(&result);
if (json != NULL) {
    /* use json */
    matchy_free_string(json);
}
```

## Thread Safety

- `matchy_t *` may be shared across threads for concurrent queries.
- `matchy_builder_t *` should be used from one thread.
- Each thread should use its own `matchy_result_t`.
- Each thread should use its own `matchy_matches_t`.

## Valgrind

```bash
valgrind --leak-check=full \
         --show-leak-kinds=all \
         --track-origins=yes \
         ./your_program
```

## See Also

- [C API Overview](c-api.md)
- [C Querying](c-querying.md)
- [Building with C](c-building.md)
