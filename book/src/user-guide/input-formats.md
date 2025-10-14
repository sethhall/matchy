# Input Formats

Matchy supports multiple input formats for building databases: text, CSV, JSON, and MISP.

## Text Format

Simple line-based format. Best for lists without metadata.

### Format

- One entry per line
- Lines starting with `#` are comments
- Empty lines are ignored
- Auto-detects IP addresses, CIDR ranges, and glob patterns

### Example

```text
# IP addresses
1.2.3.4
10.20.30.40

# CIDR ranges
10.0.0.0/8
192.168.0.0/16

# Glob patterns
*.evil.com
*.phishing-site.com
http://*/admin/config.php

# Exact strings
exact.match.com
malware.example.com
```

### Build Command

```bash
matchy build -o database.mxy entries.txt
```

## CSV Format

Comma-separated values with headers. Best for structured metadata.

### Format

- First row contains headers
- First column must be named `entry` or `key`
- Additional columns become metadata fields
- Values are auto-typed (numbers, booleans, strings)

### Example

```csv
entry,threat_level,category,first_seen,blocked
1.2.3.4,high,malware,2025-01-01,true
10.0.0.0/8,low,internal,2024-12-15,false
*.evil.com,critical,phishing,2025-01-10,true
malware.example.com,high,malware,2025-01-05,true
```

### Type Conversion

| CSV Value | DataValue Type |
|-----------|----------------|
| `123` | `Uint16/32/64` (auto-sized) |
| `-123` | `Int32` |
| `3.14` | `Double` |
| `true`/`false` | `Bool` |
| `"text"` | `String` |

### Build Command

```bash
matchy build -o threats.mxy --format csv threats.csv
```

## JSON Format

JSON arrays with complex metadata. Best for nested structures.

### Format

Array of objects, each with:
- `key` - IP, CIDR, pattern, or string
- `data` - Optional metadata (any JSON object)

### Example

```json
[
  {
    "key": "1.2.3.4",
    "data": {
      "threat_level": "high",
      "category": "malware",
      "tags": ["botnet", "ddos"],
      "attribution": {
        "actor": "Storm-0558",
        "confidence": 0.85
      }
    }
  },
  {
    "key": "*.evil.com",
    "data": {
      "threat_level": "critical",
      "category": "phishing"
    }
  }
]
```

### Build Command

```bash
matchy build -o threats.mxy --format json threats.json
```

## MISP Format

MISP (Malware Information Sharing Platform) threat intelligence exports.

### Features

- Automatically extracts IP addresses, domains, and URLs
- Preserves threat intelligence metadata
- Streaming mode for large files (low memory)
- Supports multiple MISP export files

### Build Command

```bash
# Single MISP file
matchy build -o threats.mxy --format misp misp-event.json

# Multiple MISP files
matchy build -o threats.mxy --format misp ./misp-exports/*.json
```

## Entry Type Control

Matchy auto-detects whether an entry is an IP, pattern, or exact string. Use **type prefixes**
to override this behavior:

| Prefix | Purpose | Example |
|--------|---------|----------|
| `literal:` | Force exact match | `literal:*.actually-in-domain.com` |
| `glob:` | Force glob pattern | `glob:test.com` |
| `ip:` | Force IP parsing | `ip:10.0.0.0/8` |

The prefix is automatically stripped before storage.

### When to Use

**Literal prefix:**
When a string contains `*`, `?`, or `[` that should be matched literally:

```csv
entry,type
literal:*.cdn.example.com,CDN (asterisk in name)
literal:file[1].txt,File with brackets
literal:test?.log,Question mark in filename
```

**Glob prefix:**
Force pattern matching even without wildcards:

```text
glob:test.com
glob:example.org
```

**IP prefix:**
Explicitly mark as IP address:

```text
ip:192.168.1.1
ip:10.0.0.0/8
```

**See also:** [Entry Types - Prefix Technique](../guide/entry-types.md#explicit-type-control-prefix-technique)
for complete documentation and examples.

## Multiple Input Files

Combine multiple files into one database:

```bash
# Multiple text files
matchy build -o combined.mxy ips.txt domains.txt urls.txt

# Multiple CSV files
matchy build -o threats.mxy --format csv \
  threats1.csv threats2.csv threats3.csv

# Multiple JSON files  
matchy build -o threats.mxy --format json \
  threat1.json threat2.json threat3.json
```

## Format Comparison

| Format | Metadata | Nested Data | Complexity | Best For |
|--------|----------|-------------|------------|----------|
| **Text** | No | No | Simple | Basic lists |
| **CSV** | Yes | No | Medium | Flat structured data |
| **JSON** | Yes | Yes | Complex | Rich nested data |
| **MISP** | Yes | Yes | Auto | Threat intel feeds |

## Best Practices

1. **Use text format** for simple blocklists
2. **Use CSV** for structured data with flat fields
3. **Use JSON** for complex nested metadata
4. **Use MISP** for threat intelligence feeds
5. **Combine formats** - build from multiple format types

## See Also

- [Build Command](cli-build.md) - CLI build options
- [Database Builder](database-builder.md) - Rust API for building
- [Data Types](data-types.md) - Supported data types
