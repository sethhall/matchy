# Building Databases from C

The C builder API creates `.mxy` databases from IP addresses, CIDR ranges,
literal strings, and glob patterns. Entry type detection is handled by
`matchy_builder_add()`.

## Basic Flow

```c
#include <matchy/matchy.h>

matchy_builder_t *builder = matchy_builder_new();

matchy_builder_add(builder, "192.0.2.1", "{\"category\":\"scanner\"}");
matchy_builder_add(builder, "*.evil.com", "{\"category\":\"phishing\"}");

int32_t err = matchy_builder_save(builder, "database.mxy");
matchy_builder_free(builder);
```

Use `{}` when an entry has no metadata. `json_data` must not be `NULL`.

## Builder Functions

### `matchy_builder_new`

```c
matchy_builder_t *matchy_builder_new(void);
```

Creates a new builder. Free it with `matchy_builder_free()`.

### `matchy_builder_set_case_insensitive`

```c
int32_t matchy_builder_set_case_insensitive(
    matchy_builder_t *builder,
    bool case_insensitive
);
```

When enabled, literal and glob string matching is case-insensitive. IP matching
is unaffected.

### `matchy_builder_set_schema`

```c
int32_t matchy_builder_set_schema(
    matchy_builder_t *builder,
    const char *schema_name
);
```

Enables built-in schema validation. For example:

```c
int32_t err = matchy_builder_set_schema(builder, "threatdb");
```

### `matchy_builder_add`

```c
int32_t matchy_builder_add(
    matchy_builder_t *builder,
    const char *key,
    const char *json_data
);
```

`key` may be:

- IPv4 or IPv6 address: `"192.0.2.1"`, `"2001:db8::1"`
- CIDR range: `"10.0.0.0/8"`, `"2001:db8::/32"`
- Glob pattern: `"*.evil.com"`, `"test[123].example"`
- Literal string: `"example.com"`

Examples:

```c
int32_t err;

err = matchy_builder_add(builder, "8.8.8.8", "{}");
err = matchy_builder_add(builder, "10.0.0.0/8", "{\"type\":\"private\"}");
err = matchy_builder_add(builder, "*.google.com", "{\"category\":\"search\"}");
err = matchy_builder_add(builder, "example.com", "{\"safe\":true}");
```

JSON values that are not objects are wrapped under the `"value"` key internally:

```c
matchy_builder_add(builder, "score.example", "42");
```

### `matchy_builder_save`

```c
int32_t matchy_builder_save(
    matchy_builder_t *builder,
    const char *filename
);
```

Builds and writes a database file. This consumes the builder's current internal
state; create a new builder for another independent build.

### `matchy_builder_build`

```c
int32_t matchy_builder_build(
    matchy_builder_t *builder,
    uint8_t **buffer,
    uintptr_t *size
);
```

Builds into a C-allocated buffer. The caller must free the returned buffer with
`free()`.

```c
uint8_t *buffer = NULL;
uintptr_t size = 0;

if (matchy_builder_build(builder, &buffer, &size) == MATCHY_SUCCESS) {
    /* use buffer */
    free(buffer);
}
```

### `matchy_builder_free`

```c
void matchy_builder_free(matchy_builder_t *builder);
```

Safe to call with `NULL`. After calling it, the handle must not be used.

## Complete Example

```c
#include <matchy/matchy.h>
#include <stdio.h>

int main(void) {
    int32_t err = MATCHY_SUCCESS;
    matchy_builder_t *builder = matchy_builder_new();
    if (builder == NULL) {
        return 1;
    }

    err = matchy_builder_set_case_insensitive(builder, true);
    if (err != MATCHY_SUCCESS) goto cleanup;

    err = matchy_builder_add(builder, "192.0.2.1",
        "{\"country\":\"US\",\"category\":\"scanner\"}");
    if (err != MATCHY_SUCCESS) goto cleanup;

    err = matchy_builder_add(builder, "10.0.0.0/8",
        "{\"type\":\"private\"}");
    if (err != MATCHY_SUCCESS) goto cleanup;

    err = matchy_builder_add(builder, "*.google.com",
        "{\"category\":\"search\"}");
    if (err != MATCHY_SUCCESS) goto cleanup;

    err = matchy_builder_add(builder, "example.com",
        "{\"safe\":true}");
    if (err != MATCHY_SUCCESS) goto cleanup;

    err = matchy_builder_save(builder, "my_database.mxy");
    if (err != MATCHY_SUCCESS) goto cleanup;

    printf("database written to my_database.mxy\n");

cleanup:
    matchy_builder_free(builder);
    return err == MATCHY_SUCCESS ? 0 : 1;
}
```

Compile with the generated include directory and built library:

```bash
gcc -o build_db build_db.c \
    -I./crates/matchy/include \
    -L./target/release \
    -lmatchy
```

## Error Codes

| Code | Constant | Meaning |
|------|----------|---------|
| 0 | `MATCHY_SUCCESS` | Operation succeeded |
| -2 | `MATCHY_ERROR_INVALID_FORMAT` | Invalid JSON, key, or build format |
| -4 | `MATCHY_ERROR_OUT_OF_MEMORY` | Allocation failed |
| -5 | `MATCHY_ERROR_INVALID_PARAM` | NULL pointer or invalid UTF-8 |
| -6 | `MATCHY_ERROR_IO` | Write failed |
| -7 | `MATCHY_ERROR_SCHEMA_VALIDATION` | Entry failed configured schema |
| -8 | `MATCHY_ERROR_UNKNOWN_SCHEMA` | Unknown schema name |
| -12 | `MATCHY_ERROR_INTERNAL` | Panic caught at FFI boundary |

## Thread Safety

Builders are not thread-safe. Add entries and build from a single thread.

```c
for (size_t i = 0; ips[i] != NULL; i++) {
    int32_t err = matchy_builder_add(builder, ips[i], "{}");
    if (err != MATCHY_SUCCESS) {
        fprintf(stderr, "failed to add %s: %d\n", ips[i], err);
    }
}
```

## See Also

- [C API Overview](c-api.md)
- [Querying from C](c-querying.md)
- [Memory Management](c-memory.md)
- [First Database with C](../getting-started/api-c-first.md)
