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

## Examples

### Query an IP Address

```console
$ matchy query threats.mxy 192.0.2.1
Found: IP address 192.0.2.1/32
  threat_level: "high"
  category: "malware"
```

### Query a CIDR Range

```console
$ matchy query threats.mxy 10.5.5.5
Found: IP address 10.5.5.5 (matched 10.0.0.0/8)
  threat_level: "medium"
  category: "internal"
```

### Query a Pattern

```console
$ matchy query threats.mxy phishing.evil.com
Found: Pattern match
  Matched patterns: *.evil.com
  threat_level: "high"
  category: "phishing"
```

### Query an Exact String

```console
$ matchy query threats.mxy evil.com
Found: Exact string match
  threat_level: "critical"
```

### No Match

```console
$ matchy query threats.mxy safe.com
Not found
```

## Output Format

The output shows:
- Match type (IP, CIDR, pattern, exact string)
- Matched entry details
- Associated data fields

## Exit Status

- `0` - Match found
- `1` - No match or error

## See Also

- [matchy build](matchy-build.md) - Build databases
- [matchy inspect](matchy-inspect.md) - Inspect databases
- [Entry Types](../guide/entry-types.md) - Understanding matches
