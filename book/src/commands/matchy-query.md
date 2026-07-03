# matchy query

Query a database for matches.

## Synopsis

```console
matchy query <DATABASE> <QUERY>
```

## Description

The `matchy query` command searches a database for entries matching the query string.

## Arguments

### `<DATABASE>`

Path to the database file to query.

### `<QUERY>`

The string to search for. Can be an IP address, domain, or any string.

## Options

### `-q, --quiet`

Suppress output and use only the exit status.

## Examples

### Query an IP Address

```console
$ matchy query threats.mxy 192.0.2.1
[
  {
    "category": "malware",
    "cidr": "192.0.2.1/32",
    "prefix_len": 32,
    "threat_level": "high"
  }
]
```

### Query a CIDR Range

```console
$ matchy query threats.mxy 10.5.5.5
[
  {
    "category": "internal",
    "cidr": "10.0.0.0/8",
    "prefix_len": 8,
    "threat_level": "medium"
  }
]
```

### Query a Pattern

```console
$ matchy query threats.mxy phishing.evil.com
[
  {
    "category": "phishing",
    "threat_level": "high"
  }
]
```

### Query an Exact String

```console
$ matchy query threats.mxy evil.com
[
  {
    "category": "domain",
    "threat_level": "critical"
  }
]
```

### No Match

```console
$ matchy query threats.mxy safe.com
[]
```

## Output Format

The output is a JSON array of matching data objects. IP matches include the
matched `cidr` and `prefix_len` fields in addition to the entry data.

## Exit Status

- `0` - Match found
- `1` - No match or error

## See Also

- [matchy build](matchy-build.md) - Build databases
- [matchy inspect](matchy-inspect.md) - Inspect databases
- [Entry Types](../guide/entry-types.md) - Understanding matches
