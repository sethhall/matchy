# `matchy build` - Build Databases

Build `.mxy` databases from input files containing IP addresses, CIDR ranges, exact strings, and glob patterns.

## Synopsis

```bash
matchy build [OPTIONS] <INPUT>... -o <OUTPUT>
```

## Arguments

- `<INPUT>...` - One or more input files (can be repeated to combine multiple files)

## Options

| Option | Description | Default |
|--------|-------------|---------|
| `-o, --output <FILE>` | Output database file (`.mxy` extension) | *Required* |
| `-f, --format <FORMAT>` | Input format: `text`, `csv`, `json`, or `misp` | `text` |
| `-t, --database-type <TYPE>` | Database type name (e.g., "MyCompany-ThreatIntel") | None |
| `-d, --description <TEXT>` | Description text | None |
| `--desc-lang <LANG>` | Language code for description | `en` |
| `-i, --case-insensitive` | Use case-insensitive pattern matching | Case-sensitive |
| `-v, --verbose` | Verbose output during build | Off |

## Input Formats

### Text Format (Simple)

One entry per line. Auto-detects IP addresses, CIDR ranges, and glob patterns. Lines starting with `#` are comments.

**Example: `blocklist.txt`**
```text
# IP addresses and CIDR ranges
1.2.3.4
10.0.0.0/8
192.168.0.0/16

# Exact domain matches
evil.example.com
malware-site.net

# Glob patterns
*.phishing-site.com
http://*/admin/config.php
*.evil.com
```

**Build command:**
```bash
matchy build -o blocklist.mxy blocklist.txt
```

### CSV Format (With Metadata)

CSV file with headers. The first column must be named `entry` or `key` and contains the IP/CIDR/pattern. All other columns become metadata fields.

Values are automatically typed:
- Integers → `Int32`
- Large unsigned integers → `Uint64`
- Floating point → `Double`
- `true`/`false` → `Bool`
- Everything else → `String`

**Example: `threats.csv`**
```csv
entry,threat_level,category,first_seen,blocked,confidence
1.2.3.4,high,malware,2025-01-01,true,95
10.0.0.0/8,low,internal,2024-12-15,false,100
*.evil.com,critical,phishing,2025-01-10,true,88
malware.example.com,high,malware,2025-01-05,true,92
```

**Build command:**
```bash
matchy build -o threats.mxy --format csv \
  --database-type "ThreatIntel" \
  --description "Combined threat indicators" \
  --verbose \
  threats.csv
```

**Example: `geoip.csv`**
```csv
entry,country,city,latitude,longitude,continent
8.8.8.0/24,US,Mountain View,37.386,-122.084,NA
1.1.1.0/24,AU,Sydney,-33.868,151.209,OC
185.199.108.0/22,US,San Francisco,37.774,-122.419,NA
```

### JSON Format (With Complex Metadata)

JSON array where each entry has a `key` (IP/CIDR/pattern) and optional `data` (arbitrary JSON object). Use this for nested structures or arrays.

**Example: `threats.json`**
```json
[
  {
    "key": "1.2.3.4",
    "data": {
      "threat_level": "high",
      "category": "malware",
      "first_seen": "2025-01-01",
      "tags": ["botnet", "ddos", "apt29"],
      "attribution": {
        "actor": "Storm-0558",
        "confidence": 0.85,
        "country": "RU"
      },
      "iocs": [
        {"type": "md5", "value": "abc123..."},
        {"type": "sha256", "value": "def456..."}
      ]
    }
  },
  {
    "key": "*.evil.com",
    "data": {
      "threat_level": "critical",
      "category": "phishing",
      "blocked": true
    }
  }
]
```

**Build command:**
```bash
matchy build -o threats.mxy --format json threats.json
```

### MISP Format (Threat Intelligence)

MISP (Malware Information Sharing Platform) JSON export format. Automatically extracts IP addresses, domains, URLs, and associated threat intelligence metadata.

**Build command:**
```bash
# Single MISP export
matchy build -o threats.mxy --format misp misp-event.json

# Multiple MISP exports (combined)
matchy build -o threats.mxy --format misp --verbose \
  ./misp-exports/*.json
```

The MISP importer uses streaming mode to keep memory usage low even with very large datasets.

## Controlling Entry Type (Advanced)

Matchy automatically detects whether entries are IP addresses, exact strings, or glob patterns. For edge cases, use explicit prefixes:

| Prefix | Purpose | Example |
|--------|---------|---------|
| `literal:` | Force exact string matching | `literal:*.actually-in-domain.com` |
| `glob:` | Force glob pattern matching | `glob:test.com` |
| `ip:` | Force IP address parsing | `ip:10.0.0.0/8` |

**When you need this:**

1. **Domain names with wildcard characters**: If a domain literally contains `*`, `?`, or `[`
   ```csv
   entry,category,note
   literal:*.cdn.example.com,infrastructure,Asterisk is part of the domain name
   literal:file[1].txt,testing,Brackets are literal characters
   ```

2. **Testing glob behavior**: Force glob matching without wildcards
   ```text
   glob:test.com
   glob:example.org
   ```

**Note:** The prefix is stripped before storage, so queries use the actual key without the prefix.

## Multiple Input Files

Combine multiple input files into a single database:

```bash
# Combine multiple text files
matchy build -o combined.mxy ips.txt domains.txt urls.txt

# Combine multiple CSV files
matchy build -o threats.mxy --format csv \
  threats1.csv threats2.csv threats3.csv

# Combine multiple JSON files
matchy build -o threats.mxy --format json \
  threat1.json threat2.json threat3.json

# Combine all MISP exports in a directory
matchy build -o misp-threats.mxy --format misp ./misp-exports/*.json
```

## Build Output

The build command shows statistics about the database:

```
Building database:
  Total entries:   15,234
  IP entries:      5,678
  Literal entries: 4,321
  Glob entries:    5,235

✓ Database built successfully!
  Output:        threats.mxy
  Database size: 2.45 MB (2,568,192 bytes)
```

With `--verbose`, you'll see progress updates during build:

```
Building unified MMDB database (IP + patterns)...
  Input files: 3
    - ips.txt
    - domains.txt
    - patterns.txt
  Output: combined.mxy
  Format: text
  Match mode: case-sensitive

  Reading: ips.txt...
    Added 1000 entries...
    Added 2000 entries...
    5,678 entries from this file
  Reading: domains.txt...
    Added 3000 entries...
    4,321 entries from this file
  Reading: patterns.txt...
    Added 4000 entries...
    5,235 entries from this file
  Total: 15,234 entries

Serializing...
Writing to disk...

✓ Database built successfully!
```

## Case Sensitivity

By default, pattern matching is **case-sensitive**. Use `-i` or `--case-insensitive` for case-insensitive matching:

```bash
# Case-sensitive (default): *.Evil.com matches "test.Evil.com" but NOT "test.evil.com"
matchy build -o threats.mxy patterns.txt

# Case-insensitive: *.Evil.com matches both "test.Evil.com" AND "test.evil.com"
matchy build -o threats.mxy --case-insensitive patterns.txt
```

## Read-Only Protection

After building, the database file is automatically set to read-only permissions (`0444` on Unix, read-only attribute on Windows) to protect memory-mapped integrity.

## Examples

### Simple blocklist

```bash
matchy build -o blocklist.mxy blocklist.txt
```

### Threat intelligence with metadata

```bash
matchy build -o threats.mxy --format csv \
  --database-type "ThreatIntel-Premium" \
  --description "Combined IP and domain threat indicators" \
  --verbose \
  threats.csv
```

### GeoIP database

```bash
matchy build -o geoip.mxy --format csv \
  --database-type "GeoIP-Lite" \
  --description "Custom GeoIP database" \
  geoip.csv
```

### MISP threat feed

```bash
matchy build -o misp-threats.mxy --format misp --verbose \
  --database-type "MISP-ThreatFeed" \
  --description "Daily MISP threat intelligence" \
  ./misp-exports/*.json
```

### Case-insensitive domain matching

```bash
matchy build -o domains.mxy --case-insensitive domains.txt
```

## Troubleshooting

### "Failed to open input file"

```
Error: Failed to open input file: threats.txt
```
**Solution:** Check file path and permissions

### "Missing 'entry' or 'key' column"

```
Error: CSV must have an 'entry' or 'key' column
```
**Solution:** CSV files must have a column named `entry` or `key` as the first column

### "Unknown format"

```
Error: Unknown format: xlsx. Use 'text', 'csv', 'json', or 'misp'
```
**Solution:** Only `text`, `csv`, `json`, and `misp` formats are supported

### Slow build times

**Solution:**
- Use `--verbose` to see where time is spent
- Break large files into smaller chunks and combine
- Use text format instead of JSON/CSV if you don't need metadata

## See Also

- [CLI Overview](cli.md) - Command line tool overview
- [Query Command](cli-query.md) - Querying databases
- [Inspect Command](cli-inspect.md) - Inspecting databases
- [Input Formats](input-formats.md) - Detailed format specifications
