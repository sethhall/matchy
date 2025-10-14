# Fuzz Targets

Fuzzing targets for Matchy.

## Available Targets

### glob_matching
Fuzz glob pattern matching logic.

### database_building
Fuzz database construction.

### query_parsing
Fuzz query string parsing.

## Running

```bash
cargo fuzz run glob_matching
```

## See Also

- [Fuzzing Guide](fuzzing.md)
