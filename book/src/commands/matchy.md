# matchy

The Matchy command-line interface.

## Synopsis

```console
matchy <COMMAND> [OPTIONS]
```

## Description

Matchy is a command-line tool for building and querying databases of IP addresses,
CIDR ranges, exact strings, and glob patterns.

## Commands

### matchy build

Build a database from input files.

```console
$ matchy build threats.csv -o threats.mxy
```

See [matchy build](matchy-build.md) for details.

### matchy query

Query a database for matches.

```console
$ matchy query threats.mxy 192.0.2.1
```

See [matchy query](matchy-query.md) for details.

### matchy inspect

Inspect database contents and structure.

```console
$ matchy inspect threats.mxy
```

See [matchy inspect](matchy-inspect.md) for details.

### matchy bench

Benchmark database query performance.

```console
$ matchy bench threats.mxy
```

See [matchy bench](matchy-bench.md) for details.

## Global Options

### `-h, --help`

Print help information for matchy or a specific command.

```console
$ matchy --help
$ matchy build --help
```

### `-V, --version`

Print version information.

```console
$ matchy --version
matchy {{version}}
```

## Examples

### Complete Workflow

```console
# 1. Build database
$ matchy build threats.csv -o threats.mxy

# 2. Inspect it
$ matchy inspect threats.mxy

# 3. Query it
$ matchy query threats.mxy 192.0.2.1

# 4. Benchmark it
$ matchy bench threats.mxy
```

### Working with GeoIP

```console
# Query a MaxMind GeoLite2 database
$ matchy query GeoLite2-City.mmdb 8.8.8.8

# Inspect it
$ matchy inspect GeoLite2-City.mmdb
```

## Environment Variables

### `MATCHY_LOG`

Set log level: `error`, `warn`, `info`, `debug`, `trace`

```console
$ MATCHY_LOG=debug matchy build data.csv -o db.mxy
```

## Exit Status

- `0` - Success
- `1` - Error

## Files

Matchy databases typically use the `.mxy` extension, though any extension works.
Standard MMDB files use `.mmdb`.

## See Also

- [Getting Started with CLI](../getting-started/cli.md) - CLI tutorial
- [CLI Commands](index.md) - All commands
- [Matchy Guide](../guide/index.md) - Conceptual documentation
