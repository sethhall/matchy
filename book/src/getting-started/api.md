# Using the API

The Matchy API lets you build and query [*databases*][def-database] programmatically
from your application code. This is perfect for:

- Application development (servers, services, tools)
- Embedded systems and constrained environments
- Language integration (Rust, C/C++, Python, etc.)
- Custom data processing pipelines

## What You'll Learn

* [Installing as a Library](api-installation.md) - Add Matchy to your project
* [First Database with Rust](api-rust-first.md) - Build and query using Rust
* [First Database with C](api-c-first.md) - Build and query using C/C++

## Example (Rust)

```rust
use matchy::{Database, DatabaseBuilder, MatchMode, DataValue};
use std::collections::HashMap;

// Build database
let mut builder = DatabaseBuilder::new(MatchMode::CaseInsensitive);
let mut data = HashMap::new();
data.insert("threat".to_string(), DataValue::String("high".to_string()));
builder.add_entry("192.0.2.1", data)?;

let db_bytes = builder.build()?;
std::fs::write("threats.mxy", &db_bytes)?;

// Query database
let db = Database::open("threats.mxy")?;
if let Some(result) = db.lookup("192.0.2.1")? {
    println!("Found: {:?}", result);
}
```

## Example (C)

```c
#include "matchy.h"

// Build database
matchy_builder_t *builder = matchy_builder_new();
matchy_builder_add(builder, "192.0.2.1", "{\"threat\": \"high\"}");
matchy_builder_save(builder, "threats.mxy");
matchy_builder_free(builder);

// Query database
matchy_t *db = matchy_open("threats.mxy");
matchy_result_t result = matchy_query(db, "192.0.2.1");
if (result.found) {
    char *json = matchy_result_to_json(&result);
    printf("Found: %s\n", json);
    matchy_free_string(json);
    matchy_free_result(&result);
}
matchy_close(db);
```

## Going further

After completing this section, check out:

* [Matchy Guide](../guide/index.md) - Deeper dive into concepts
* [Rust API Reference](../reference/rust-api.md) - Complete Rust API docs
* [C API Reference](../reference/c-api.md) - Complete C API docs

[def-database]: ../appendix/glossary.md#database '"database" (glossary entry)'
