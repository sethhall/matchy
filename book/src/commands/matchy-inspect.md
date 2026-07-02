# matchy inspect

Inspect database contents and lookup support.

## Synopsis

```console
matchy inspect [OPTIONS] <DATABASE>
```

## Description

The `matchy inspect` command displays a human-readable summary of what a database
contains and which lookup paths it supports. By default, it focuses on user-facing
contents rather than storage internals.

## Arguments

### `<DATABASE>`

Path to the database file to inspect.

## Options

### `-j`, `--json`

Output database information as JSON.

### `-v`, `--verbose`

Show storage details in addition to the default summary. Use `--json` when you
need raw metadata.

## Examples

### Basic Inspection

```console
$ matchy inspect threats.mxy
Database: threats.mxy
Format:   Matchy combined database
Size:     15.11 MB

Contents:
  IP/CIDR entries:  1610
    IPv4 entries:   1523
    IPv6 entries:   87
  Exact strings:    2341
  Glob patterns:    8492

Lookup support:
  IP addresses:     yes (IPv4 and IPv6)
  Exact strings:    yes
  Glob patterns:    yes
  String match mode: case-insensitive

Metadata:
  Database type:   ThreatDB-v1
  Description:
    en: Threat intelligence database
  Build time:      2026-02-25 11:50:49 UTC (1772020249)
```

### Verbose Inspection

```console
$ matchy inspect threats.mxy --verbose
Database: threats.mxy
Format:   Matchy combined database
Size:     15.11 MB

Contents:
  IP/CIDR entries:  1610
    IPv4 entries:   1523
    IPv6 entries:   87
  Exact strings:    2341
  Glob patterns:    8492

Lookup support:
  IP addresses:     yes (IPv4 and IPv6)
  Exact strings:    yes
  Glob patterns:    yes
  String match mode: case-insensitive

Metadata:
  Database type:   ThreatDB-v1
  Description:
    en: Threat intelligence database
  Build time:      2026-02-25 11:50:49 UTC (1772020249)

Storage:
  Container:        Matchy extended MMDB
  Format version:   2.0
  MMDB IP tree:     IPv6
  Record size:      24 bits
  Sections:         IP tree, literal hash, glob automaton
```

### MMDB File

```console
$ matchy inspect GeoLite2-City.mmdb
Database: GeoLite2-City.mmdb
Format:   MMDB IP database
Size:     64.12 MB

Contents:
  IP/CIDR entries:  not stored in metadata
  Exact strings:    0
  Glob patterns:    0

Lookup support:
  IP addresses:     yes
  Exact strings:    no
  Glob patterns:    no
```

## Output Information

The inspect command shows:
- File size
- Database format
- Entry counts by type when stored as user-facing metadata
- IP family entry counts when stored as user-facing metadata
- Lookup support by query type
- String match mode when string lookups are supported
- Source/build metadata
- Storage details with `--verbose`
- Raw metadata with `--json`

Older databases that do not store user-facing entry or IP family entry counts are
reported conservatively instead of deriving counts from storage internals.

## Use Cases

Inspect is useful for:
- Verifying database contents
- Checking file size before deployment
- Confirming which lookup paths are available
- Debugging database storage details with `--verbose`

## Exit Status

- `0` - Success
- `1` - Error (file not found, invalid format, etc.)

## See Also

- [matchy build](matchy-build.md) - Build databases
- [matchy bench](matchy-bench.md) - Benchmark performance
- [Database Concepts](../guide/database-concepts.md) - Understanding databases
