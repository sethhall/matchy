# matchy match

Scan log files or streams for threats by matching against a database.

## Synopsis

```console
matchy match [OPTIONS] <DATABASE> <INPUT>
```

## Description

The `matchy match` command processes log files or stdin, automatically extracting IP addresses, domains, and email addresses from each line and checking them against the database. This is designed for operational testing and real-time threat detection in log streams.

**Key features:**
- Automatic extraction of IPs, domains, and emails from unstructured logs
- SIMD-accelerated scanning (200-500 MB/sec typical throughput)
- Outputs JSON (NDJSON format) to stdout for easy parsing
- Statistics and diagnostics to stderr
- Memory-efficient streaming processing

## Arguments

### `<DATABASE>`

Path to the database file to query (.mxy file).

### `<INPUT>`

Input file containing log data (one line per entry), or `-` for stdin.

## Options

### `-f, --format <FORMAT>`

Output format (default: `json`):
- `json` - NDJSON format (one JSON object per match on stdout)
- `summary` - Statistics only (no match output)

```console
$ matchy match threats.mxy access.log --format json
$ matchy match threats.mxy access.log --format summary --stats
```

### `-s, --stats`

Show detailed statistics to stderr including:
- Lines processed and match rate
- Candidate extraction breakdown (IPv4, IPv6, domains, emails)
- Throughput (MB/s)
- Timing samples (extraction and lookup)
- Cache hit rate

```console
$ matchy match threats.mxy access.log --stats
```

### `--trusted`

Skip UTF-8 validation for faster processing. Only use with trusted data sources.

```console
$ matchy match threats.mxy trusted.log --trusted
```

### `--cache-size <SIZE>`

Set LRU cache capacity for query results (default: 10000). Use `0` to disable caching.

```console
$ matchy match threats.mxy access.log --cache-size 50000
$ matchy match threats.mxy access.log --cache-size 0  # No cache
```

## Examples

### Scan Apache Access Log

```console
$ matchy match threats.mxy /var/log/apache2/access.log --stats
[INFO] Loaded database: threats.mxy
[INFO] Load time: 12.45ms
[INFO] Cache: 10000 entries
[INFO] Extractor configured for: IPs, strings
[INFO] Processing stdin...

{"timestamp":"1697500800.123","line_number":1,"matched_text":"192.0.2.1","input_line":"192.0.2.1 - - [17/Oct/2024:10:00:00 +0000] \"GET /login HTTP/1.1\" 200 1234","match_type":"ip","prefix_len":32,"cidr":"192.0.2.1/32","data":{"threat_level":"high","category":"malware"}}
{"timestamp":"1697500800.456","line_number":5,"matched_text":"evil.com","input_line":"Request from evil.com blocked","match_type":"pattern","pattern_count":1,"data":[{"threat_level":"critical"}]}

[INFO] Processing complete
[INFO] Lines processed: 15,234
[INFO] Lines with matches: 127 (0.8%)
[INFO] Total matches: 145
[INFO] Candidates tested: 18,456
[INFO]   IPv4: 15,234
[INFO]   Domains: 3,222
[INFO] Throughput: 450.23 MB/s
[INFO] Total time: 0.15s
[INFO] Cache: 10,000 entries (92.3% hit rate)
```

### Process stdin Stream

```console
$ tail -f /var/log/syslog | matchy match threats.mxy - --stats
```

### Extract Only Matches

```console
$ matchy match threats.mxy access.log | jq -r '.matched_text'
192.0.2.1
evil.com
phishing.example.com
```

### Count Matches by Type

```console
$ matchy match threats.mxy access.log | jq -r '.match_type' | sort | uniq -c
  89 ip
  38 pattern
```

## Output Format

### JSON Output (NDJSON)

Each match is a JSON object on a single line:

```json
{
  "timestamp": "1697500800.123",
  "line_number": 42,
  "matched_text": "192.0.2.1",
  "input_line": "Original log line containing the match...",
  "match_type": "ip",
  "prefix_len": 24,
  "cidr": "192.0.2.0/24",
  "data": {
    "threat_level": "high",
    "category": "malware"
  }
}
```

**For pattern matches:**
```json
{
  "timestamp": "1697500800.456",
  "line_number": 127,
  "matched_text": "evil.example.com",
  "input_line": "DNS query for evil.example.com",
  "match_type": "pattern",
  "pattern_count": 2,
  "data": [
    {"threat_level": "high"},
    {"category": "phishing"}
  ]
}
```

### Field Reference

| Field | Type | Description |
|-------|------|-------------|
| `timestamp` | string | Unix timestamp with milliseconds |
| `line_number` | number | Line number in input file |
| `matched_text` | string | The extracted text that matched |
| `input_line` | string | Complete original log line |
| `match_type` | string | `"ip"` or `"pattern"` |
| `prefix_len` | number | IP: CIDR prefix length |
| `cidr` | string | IP: Canonical CIDR notation |
| `pattern_count` | number | Pattern: Number of patterns matched |
| `data` | object/array | Associated metadata from database |

## Pattern Extraction

The command automatically extracts and tests:

- **IPv4 addresses**: 192.0.2.1, 10.0.0.0
- **IPv6 addresses**: 2001:db8::1, ::ffff:192.0.2.1
- **Domain names**: example.com, sub.domain.com
- **Email addresses**: user@example.com

Extraction is context-aware with word boundaries and validates format (TLD checks for domains, etc.).

## Performance

Typical throughput: **200-500 MB/s** on modern hardware.

## Exit Status

- `0` - Success (even if no matches found)
- `1` - Error (file not found, invalid database, etc.)

## See Also

- [matchy query](matchy-query.md) - Single query testing
- [matchy build](matchy-build.md) - Build databases
- [Pattern Extraction Guide](../guide/extraction.md) - Details on extraction
- [Query Result Caching](../guide/caching.md) - Cache optimization
