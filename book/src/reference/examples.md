# Examples

Code examples for Matchy.

## Rust Examples

### Building a Database

```rust
use matchy::{MmdbBuilder, MatchMode, DataValue};
use std::collections::HashMap;

let mut builder = MmdbBuilder::new(MatchMode::CaseSensitive);

let mut data = HashMap::new();
data.insert("threat".to_string(), DataValue::String("high".to_string()));

builder.add_ip("1.2.3.4", data)?;
builder.add_glob("*.evil.com", HashMap::new())?;

let bytes = builder.build()?;
std::fs::write("db.mxy", &bytes)?;
```

### Querying

```rust
use matchy::{Database, QueryResult};

let db = Database::open("db.mxy")?;

match db.lookup("1.2.3.4")? {
    Some(QueryResult::Ip { data, prefix_len }) => {
        println!("IP match: {:?}", data);
    }
    Some(QueryResult::Pattern { pattern_ids, data }) => {
        println!("Pattern match: {} patterns", pattern_ids.len());
    }
    _ => println!("No match"),
}
```

## C Examples

### Building

```c
#include "matchy.h"

matchy_builder_t *builder = matchy_builder_new();
matchy_builder_add(builder, "1.2.3.4", "{\"threat\": \"high\"}");
matchy_builder_save(builder, "db.mxy");
matchy_builder_free(builder);
```

### Querying

```c
matchy_t *db = matchy_open("db.mxy");
matchy_result_t result = matchy_query(db, "1.2.3.4");

if (result.found) {
    printf("Match found!\n");
    matchy_free_result(&result);
}

matchy_close(db);
```

## CLI Examples

```bash
# Build from CSV
matchy build -o threats.mxy --format csv threats.csv

# Query
matchy query threats.mxy 1.2.3.4

# Inspect
matchy inspect threats.mxy
```

## See Also

- [Rust API](rust-api.md)
- [C API](c-api.md)
- [CLI Tool](../commands/index.md)
