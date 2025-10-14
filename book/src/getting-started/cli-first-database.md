# First Database with CLI

Let's build and query a [*database*][def-database] using the Matchy CLI.

## Create input data

First, create a CSV file with some sample data. Create a file called `threats.csv`:

```csv
key,threat_level,category
192.0.2.1,high,malware
203.0.113.0/24,medium,botnet
*.evil.com,high,phishing
malicious-site.com,critical,c2_server
```

Each row defines an [*entry*][def-entry]:
- `key` - IP address, CIDR range, pattern, or exact string
- Other columns become data fields associated with the entry

## Build the database

Use `matchy build` to create a database:

```console
$ matchy build threats.csv -o threats.mxy
Building database from threats.csv
  Added 4 entries
  Database size: 2,847 bytes
Successfully wrote threats.mxy
```

This creates `threats.mxy`, a binary database file.

## Query the database

Now query it with `matchy query`:

```console
$ matchy query threats.mxy 192.0.2.1
Found: IP address 192.0.2.1
  threat_level: "high"
  category: "malware"
```

The CLI automatically detects that `192.0.2.1` is an IP address and performs an IP lookup.

## Query a CIDR range

IPs within a CIDR range match that range:

```console
$ matchy query threats.mxy 203.0.113.42
Found: IP address 203.0.113.42 (matched 203.0.113.0/24)
  threat_level: "medium"
  category: "botnet"
```

## Query a pattern

Patterns match using wildcards:

```console
$ matchy query threats.mxy phishing.evil.com
Found: Pattern match
  Matched patterns: *.evil.com
  threat_level: "high"
  category: "phishing"
```

The domain `phishing.evil.com` matches the pattern `*.evil.com`.

## Query an exact string

Exact strings must match completely:

```console
$ matchy query threats.mxy malicious-site.com
Found: Exact string match
  threat_level: "critical"
  category: "c2_server"
```

## Inspect the database

Use `matchy inspect` to see what's inside:

```console
$ matchy inspect threats.mxy
Database: threats.mxy
Size: 2,847 bytes
Match mode: CaseInsensitive

IP entries: 2
String entries: 1
Pattern entries: 1

Performance estimate:
  IP queries: ~7M/sec
  Pattern queries: ~2M/sec
```

## Benchmark performance

Test query performance with `matchy bench`:

```console
$ matchy bench threats.mxy
Running benchmarks on threats.mxy...

IP lookups:     7,234,891 queries/sec (138ns avg)
Pattern lookups: 2,156,892 queries/sec (463ns avg)
String lookups:  8,932,441 queries/sec (112ns avg)
```

## Input formats

The CLI supports multiple input formats:

- **CSV** - Comma-separated values (shown above)
- **JSON** - One JSON object per line
- **JSONL** - JSON Lines format
- **TSV** - Tab-separated values

See [Input File Formats](../reference/input-formats.md) for details.

## What just happened?

You just:

1. Created a CSV file with threat data
2. Built a binary database (`threats.mxy`)
3. Queried IPs, CIDR ranges, patterns, and exact strings
4. Inspected the database structure
5. Benchmarked query performance

The database loads in under 1ms using memory mapping, making it perfect for
production use in high-throughput applications.

## Going further

* [CLI Commands Reference](../commands/index.md) - Complete CLI documentation
* [Input File Formats](../reference/input-formats.md) - All supported input formats
* [Matchy Guide](../guide/index.md) - Deeper dive into Matchy concepts

To integrate Matchy into your application code, see [Using the API](api.md).

[def-database]: ../appendix/glossary.md#database '"database" (glossary entry)'
[def-entry]: ../appendix/glossary.md#entry '"entry" (glossary entry)'
