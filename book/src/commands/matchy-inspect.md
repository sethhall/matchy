# matchy inspect

Inspect database contents and structure.

## Synopsis

```console
matchy inspect <DATABASE>
```

## Description

The `matchy inspect` command displays information about a database including size,
entry counts, and structure.

## Arguments

### `<DATABASE>`

Path to the database file to inspect.

## Examples

### Basic Inspection

```console
$ matchy inspect threats.mxy
Database: threats.mxy
Size: 15,847,293 bytes (15.1 MB)
Format: Matchy Extended MMDB
Match mode: CaseInsensitive

Entry counts:
  IP addresses: 1,523
  CIDR ranges: 87
  Exact strings: 2,341
  Patterns: 8,492
  Total: 12,443 entries

Performance estimates:
  IP queries: ~7M/sec
  Pattern queries: ~2M/sec
  String queries: ~8M/sec
```

### Large Database

```console
$ matchy inspect large.mxy
Database: large.mxy
Size: 234,891,234 bytes (234.9 MB)
Format: Matchy Extended MMDB
Match mode: CaseInsensitive

Entry counts:
  IP addresses: 85,234
  CIDR ranges: 1,523
  Exact strings: 42,891
  Patterns: 52,341
  Total: 181,989 entries
```

### MMDB File

```console
$ matchy inspect GeoLite2-City.mmdb
Database: GeoLite2-City.mmdb
Size: 67,234,891 bytes (67.2 MB)
Format: Standard MMDB
Match mode: N/A (IP-only database)

Entry counts:
  IP addresses: ~3,000,000
  CIDR ranges: Included in IP tree
  Exact strings: 0
  Patterns: 0
```

## Output Information

The inspect command shows:
- File size
- Database format (MMDB or Matchy Extended)
- Match mode (case-sensitive or insensitive)
- Entry counts by type
- Performance estimates

## Use Cases

Inspect is useful for:
- Verifying database contents
- Checking file size before deployment
- Estimating query performance
- Debugging database issues

## Exit Status

- `0` - Success
- `1` - Error (file not found, invalid format, etc.)

## See Also

- [matchy build](matchy-build.md) - Build databases
- [matchy bench](matchy-bench.md) - Benchmark performance
- [Database Concepts](../guide/database-concepts.md) - Understanding databases
