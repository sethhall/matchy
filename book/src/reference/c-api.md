# C API Overview

Matchy provides a C ABI for applications that need to build, open, query, or
extract indicators without using Rust directly. The generated header is the
source of truth and is produced by `cbindgen` during release builds.

## Header File

```c
#include <matchy/matchy.h>
```

Build the release library to regenerate headers:

```bash
cargo build --release
```

The generated header is written under `crates/matchy/include/matchy/`.

## Core Types

```c
typedef struct matchy_t matchy_t;
typedef struct matchy_builder_t matchy_builder_t;

typedef struct matchy_result_t {
    bool found;
    uint8_t prefix_len;
    uint8_t _result_type;   /* 0=not found, 1=ip, 2=pattern */
    uint32_t _data_offset;
    const matchy_t *_db_ref;
} matchy_result_t;
```

`matchy_t` and `matchy_builder_t` are opaque handles. Do not dereference them.
`matchy_result_t` is returned by value and stores offsets into the database
rather than owning decoded heap data.

## Error Codes

```c
#define MATCHY_SUCCESS                 0
#define MATCHY_ERROR_FILE_NOT_FOUND   -1
#define MATCHY_ERROR_INVALID_FORMAT   -2
#define MATCHY_ERROR_CORRUPT_DATA     -3
#define MATCHY_ERROR_OUT_OF_MEMORY    -4
#define MATCHY_ERROR_INVALID_PARAM    -5
#define MATCHY_ERROR_IO               -6
#define MATCHY_ERROR_SCHEMA_VALIDATION -7
#define MATCHY_ERROR_UNKNOWN_SCHEMA   -8
#define MATCHY_ERROR_LOOKUP_PATH_INVALID -9
#define MATCHY_ERROR_NO_DATA         -10
#define MATCHY_ERROR_DATA_PARSE      -11
#define MATCHY_ERROR_INTERNAL        -12
```

## Function Groups

Database operations:

- `matchy_open()` - Open a database from a file path
- `matchy_open_with_options()` - Open with cache/watch/update options
- `matchy_init_open_options()` - Initialize `matchy_open_options_t`
- `matchy_open_buffer()` - Open from an in-memory buffer
- `matchy_close()` - Close a database handle
- `matchy_query()` - Query and return `matchy_result_t` by value
- `matchy_query_into()` - Query into caller-provided result storage
- `matchy_get_stats()` - Read query statistics
- `matchy_clear_cache()` - Clear the current thread's query cache

Builder operations:

- `matchy_builder_new()` - Create a builder
- `matchy_builder_set_case_insensitive()` - Configure string match mode
- `matchy_builder_set_schema()` - Enable built-in schema validation
- `matchy_builder_add()` - Add an IP, CIDR, literal, or glob entry with JSON data
- `matchy_builder_set_description()` - Set metadata description
- `matchy_builder_set_update_url()` - Set metadata update URL
- `matchy_builder_save()` - Build and write a database file
- `matchy_builder_build()` - Build into a caller-owned buffer
- `matchy_builder_free()` - Free a builder

Result and data operations:

- `matchy_result_get_entry()` - Convert a found result to an entry handle
- `matchy_aget_value()` - Read nested data using a NULL-terminated path array
- `matchy_get_entry_data_list()` - Traverse full entry data
- `matchy_free_entry_data_list()` - Free traversal output
- `matchy_result_to_json()` - Convert a result to a JSON string
- `matchy_free_string()` - Free strings returned by Matchy
- `matchy_free_result()` - No-op kept for ABI compatibility

Extractor operations:

- `matchy_extractor_create()` - Create an extractor with `MATCHY_EXTRACT_*` flags
- `matchy_extractor_extract_chunk()` - Extract patterns from bytes
- `matchy_matches_free()` - Free extracted match arrays
- `matchy_extractor_free()` - Free the extractor
- `matchy_item_type_name()` - Get a display name for an item type constant

## Query Pattern

```c
matchy_t *db = matchy_open("database.mxy");
if (db == NULL) {
    fprintf(stderr, "failed to open database\n");
    return 1;
}

matchy_result_t result = matchy_query(db, "192.0.2.1");
if (result.found) {
    char *json = matchy_result_to_json(&result);
    if (json != NULL) {
        printf("match: %s\n", json);
        matchy_free_string(json);
    }
}

matchy_free_result(&result);
matchy_close(db);
```

Use `matchy_query_into()` when a language binding cannot safely receive C
structs by value:

```c
matchy_result_t result;
matchy_query_into(db, "example.com", &result);
```

## Builder Pattern

```c
matchy_builder_t *builder = matchy_builder_new();
if (builder == NULL) {
    return 1;
}

int32_t err = matchy_builder_add(
    builder,
    "192.0.2.1",
    "{\"category\":\"scanner\"}"
);

if (err == MATCHY_SUCCESS) {
    err = matchy_builder_add(
        builder,
        "*.evil.com",
        "{\"category\":\"phishing\"}"
    );
}

if (err == MATCHY_SUCCESS) {
    err = matchy_builder_save(builder, "database.mxy");
}

matchy_builder_free(builder);
```

## Cache Options And Stats

```c
matchy_open_options_t opts;
matchy_init_open_options(&opts);
opts.cache_capacity = 100000;

matchy_t *db = matchy_open_with_options("threats.mxy", &opts);

matchy_stats_t stats;
matchy_get_stats(db, &stats);
printf("total queries: %llu\n", (unsigned long long)stats.total_queries);
```

Set `opts.cache_capacity = 0` to disable query caching.

## Extractor Example

```c
matchy_extractor_t *ext = matchy_extractor_create(
    MATCHY_EXTRACT_DOMAINS | MATCHY_EXTRACT_IPV4 | MATCHY_EXTRACT_IPV6
);

const char *text = "Check evil.com and 192.168.1.1";
matchy_matches_t matches;

if (matchy_extractor_extract_chunk(
        ext,
        (const uint8_t *)text,
        strlen(text),
        &matches
    ) == MATCHY_SUCCESS) {
    for (size_t i = 0; i < matches.count; i++) {
        printf("%s: %s\n",
               matchy_item_type_name(matches.items[i].item_type),
               matches.items[i].value);
    }
    matchy_matches_free(&matches);
}

matchy_extractor_free(ext);
```

## Thread Safety

- `matchy_t *` handles are safe for concurrent read queries.
- `matchy_builder_t *` handles are not thread-safe.
- Each thread should use its own `matchy_result_t` and `matchy_matches_t`.
- `matchy_result_t` does not own decoded data; it is valid only while its
  database handle remains open.

## See Also

- [C Building](c-building.md)
- [C Querying](c-querying.md)
- [C Memory Management](c-memory.md)
- [First Database with C](../getting-started/api-c-first.md)
