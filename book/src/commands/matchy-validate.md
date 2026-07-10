# matchy validate

Validate a database file for integrity and correctness.

## Synopsis

```bash
matchy validate [OPTIONS] <DATABASE>
```

## Description

The `validate` command checks Matchy database files (`.mxy`) and reports structural, reference, and schema errors. Strict validation is the default and is recommended for databases from untrusted sources. Standard samples general MMDB data for trusted inputs, although a declared known schema still causes every referenced entry to be schema-validated.

Validation checks include:

- **Runtime envelopes**: Metadata, versions, section boundaries, and top-level extension structure
- **MMDB references**: Sampled in Standard mode and exhaustively traversed in Strict mode
- **Extension consistency**: Deeper mapping and automaton checks in Strict mode
- **Schema validation**: Referenced entry values are checked when `database_type` declares a known schema such as `ThreatDB-v1`

A passing report means that the bytes read passed the checks for the selected level. It does not make a validation result apply to different bytes that later appear at the same path.

## Options

### `-l, --level <LEVEL>`

Validation strictness level. Default: `strict`

Levels:

- **`standard`**: Runtime envelope checks plus sampled reachable MMDB data; known-schema checks remain exhaustive
- **`strict`**: Exhaustive MMDB tree validation plus deeper component checks (default)

### `-j, --json`

Output results as JSON instead of human-readable format.

### `-v, --verbose`

Show detailed information including warnings and info messages.

### `-h, --help`

Print help information.

## Arguments

### `<DATABASE>`

Path to the Matchy database file (`.mxy`) to validate.

## Examples

### Basic Validation

Validate with default strict checking:

```bash
matchy validate database.mxy
```

Shows:

- Validation level used (strict by default)
- Database statistics (nodes, patterns, IPs, size)
- Validation time
- Pass/fail status with clear ✅/❌ indicator

### Standard Validation

Use faster standard validation:

```bash
matchy validate --level standard database.mxy
```

### Verbose Output

Show warnings and informational messages:

```bash
matchy validate --verbose database.mxy
```

Adds additional detail:

- **Warnings**: Non-fatal issues and non-canonical structures
- **Information**: Validation steps completed successfully
- Useful for understanding what was checked and any potential optimizations

### JSON Output

Machine-readable JSON format:

```bash
matchy validate --json database.mxy
```

Provides structured output with:

- `is_valid`: Boolean pass/fail
- `duration_ms`: Validation time
- `errors`, `warnings`, `info`: Categorized messages
- `stats`: Detailed database metrics (node count, pattern count, file size, etc.)

Useful for CI/CD pipelines and automated testing.

## Exit Status

- **0**: Validation passed (no errors)
- **1**: Validation failed (errors found)
- **Other**: Command error (file not found, etc.)

## Validation Levels

### Standard

Fast integrity validation that performs:

- The top-level format and section-envelope checks used by the runtime loader
- Header, version, and section-boundary checks
- Sampled structural and value validation of reachable MMDB data from up to 20 tree nodes
- Exhaustive schema validation of referenced entries when `database_type` declares a known schema

Without a known schema, Standard mode does not exhaustively visit every tree record, data value, offset, or string. With a known schema, it still walks all referenced entries for schema conformance, so its running time can be linear in the database size.

**Use when**: Validating trusted databases for basic integrity

### Strict (Default)

Deeper validation that performs:

- All Standard checks
- Exhaustive checking of MMDB tree records and the reachable data references they expose
- Deeper consistency checks for extension components, mappings, and automaton structures
- The same exhaustive known-schema checks that also run in Standard

**Use when**: Validating databases from untrusted sources (default)

## Common Validation Errors

### Invalid MMDB format

```
ERROR: Invalid MMDB format: metadata marker not found
```

The file is not a valid MMDB database.

### Offset out of bounds

```
ERROR: Node 123 edge offset 45678 exceeds file size 40000
```

The database references data beyond the file size - likely corruption.

### Invalid UTF-8

```
ERROR: String at offset 12345 contains invalid UTF-8
```

A string in the database is not valid UTF-8 text.

### Cycle detected

```
ERROR: Cycle detected in failure function starting at node 56
```

The Aho-Corasick automaton has a cycle, making it unsafe to traverse.

### Invalid magic bytes

```
ERROR: PARAGLOB section magic bytes mismatch: expected "PARAGLOB", found "CORRUPT!"
```

The PARAGLOB section header is corrupted.

## When to Validate

### Always Validate

- Databases from untrusted sources
- Databases downloaded from the internet
- Databases created by third parties
- After file transfer (detect corruption)

### Optional Validation

- Databases built locally with `matchy build`
- Databases from trusted internal sources
- Development/testing environments

### Skip Validation

- After validation has already passed for the exact same immutable bytes
- In performance-critical hot paths
- When an application-managed digest or immutable identity proves the database has not changed

## Performance

Validation speed and resource use depend on database size, structure, storage, and the selected level. Standard mode is typically faster because it samples general MMDB tree data; Strict traverses every MMDB tree record and performs deeper component checks. A known schema makes both levels inspect every referenced entry for schema conformance.

For large trusted databases, Standard can provide a faster integrity check. Continue to use Strict for untrusted input, enforce deployment-appropriate resource limits, and cache results only in application code keyed by a digest or immutable file identity.

## Security Considerations

The validator handles malformed input with safe Rust parsing and fail-closed validation errors. The caller remains responsible for resource policy:

- **Bounds checks**: Structural references are checked according to the selected level before validation code uses them
- **Safe Rust**: Core validation parsing uses safe Rust
- **Fail closed**: Malformed structures become errors rather than successful reports
- **Bounded diagnostics**: Retains at most 256 errors, 256 warnings, and 128 informational messages, with a suppression sentinel on overflow
- **Resource limits**: Limit file size, memory, CPU time, and concurrency for the deployment

Separately, database open validates top-level envelopes, and query paths perform deliberate bounds checks before accessing nested serialized references. Those runtime checks complement explicit validation; they do not make a prior report apply to replacement bytes.

However, validation is not a substitute for other security measures:

- Always validate before first use
- Use strict mode for untrusted sources
- Combine with file integrity checks (checksums)
- Consider sandboxing if processing user-uploaded files

Validation applies to the bytes read during the command. Reopening a mutable path after validation creates a time-of-check/time-of-use gap: another process could replace the file. Validate a protected immutable or atomic snapshot, or record a content digest and invalidate or repeat validation whenever the file changes.

## Integration with Other Commands

### Validate After Building

```bash
matchy build patterns.csv --input-format csv --output database.mxy
matchy validate database.mxy
```

### Validate Before Querying

```bash
matchy validate database.mxy && \
matchy query database.mxy "*.example.com"
```

### Batch Validation

```bash
for db in *.mxy; do
    echo "Validating $db..."
    matchy validate --level standard "$db" || echo "FAILED: $db"
done
```

## Troubleshooting

### False Positives

Some warnings may be benign:

- Unreferenced or intentionally padded structures
- Non-canonical data that remains within the format's accepted rules

Review warnings in the context of how the database was produced; do not downgrade untrusted input merely to avoid warnings.

### Performance Issues

For very large databases (>100MB):

- Use Standard only when sampled general coverage is appropriate for a trusted input; known-schema validation remains exhaustive
- Use Strict for untrusted input and impose explicit resource limits
- Cache a result in the application only while a digest or immutable identity remains unchanged

### Memory Usage

Validation reads the file into memory. Enforce a file-size limit before validation and account for report and traversal overhead in the application's memory budget.

## See Also

- [matchy build](matchy-build.md) - Build databases
- [matchy inspect](matchy-inspect.md) - Inspect database structure
- [Validation API](../reference/validation-api.md) - Programmatic validation
- [Schemas Reference](../reference/schemas.md) - Schema validation details
- [Binary Format](../reference/binary-format.md) - Format specification
