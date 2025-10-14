# `matchy inspect` - Inspect Databases

View database information, capabilities, statistics, and metadata.

## Synopsis

```bash
matchy inspect [OPTIONS] <DATABASE>
```

## Arguments

- `<DATABASE>` - Path to the `.mxy` database file

## Options

| Option | Description |
|--------|-------------|
| `-j, --json` | Output metadata as JSON |
| `-v, --verbose` | Show detailed statistics and full metadata |

## Human-Readable Output

```bash
matchy inspect threats.mxy
```

**Example output:**
```
Database: threats.mxy
Format:   Combined IP+String database

Capabilities:
  IP lookups:      ✓
    Entries:       5,678
  String lookups:  ✓
    Literals:      ✓ (4,321 strings)
    Globs:         ✓ (5,235 patterns)

Metadata:
  Database type:   ThreatIntel-Premium
  Description:
    en: Combined IP and domain threat indicators
  Build time:      2025-01-15 10:30:45 UTC (1736936445)
```

## JSON Output

```bash
matchy inspect threats.mxy --json
```

**Example output:**
```json
{
  "file": "threats.mxy",
  "format": "combined",
  "has_ip_data": true,
  "has_literal_data": true,
  "has_glob_data": true,
  "has_string_data": true,
  "ip_count": 5678,
  "literal_count": 4321,
  "glob_count": 5235,
  "metadata": {
    "database_type": "ThreatIntel-Premium",
    "description": {
      "en": "Combined IP and domain threat indicators"
    },
    "build_epoch": 1736936445,
    "node_count": 11356,
    "record_size": 24
  }
}
```

## Verbose Output

```bash
matchy inspect threats.mxy --verbose
```

Shows all standard information plus the complete metadata tree.

## Examples

### Quick inspection

```bash
matchy inspect threats.mxy
```

### JSON for scripting

```bash
matchy inspect threats.mxy --json | jq '.ip_count'
# Output: 5678

matchy inspect threats.mxy --json | jq '.metadata.database_type'
# Output: "ThreatIntel-Premium"
```

### Check database type

```bash
DB_TYPE=$(matchy inspect threats.mxy --json | jq -r '.metadata.database_type')
echo "Database type: $DB_TYPE"
```

### List all databases in a directory

```bash
#!/bin/bash
# list-databases.sh

for db in *.mxy; do
    echo "=== $db ==="
    matchy inspect "$db" --json | jq '{
        type: .format,
        ips: .ip_count,
        literals: .literal_count,
        globs: .glob_count,
        db_type: .metadata.database_type
    }'
    echo
done
```

## See Also

- [CLI Overview](cli.md) - Command line tool overview
- [Build Command](cli-build.md) - Building databases
- [Query Command](cli-query.md) - Querying databases
