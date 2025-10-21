# Input Formats Reference

Technical specification of supported input formats for building Matchy databases.

## Overview

Matchy supports four input formats:
1. **Text** - Simple line-based
2. **CSV** - Comma-separated with metadata
3. **JSON** - Structured data
4. **MISP** - Threat intelligence format

All formats support mixing IPs, patterns, and exact strings.

## Text Format

### Specification

```ebnf
file        = (entry | comment | blank)* ;
entry       = ip | cidr | pattern | exact ;
comment     = "#" .* "\n" ;
blank       = "\n" ;

ip          = ipv4 | ipv6 ;
ipv4        = digit{1,3} "." digit{1,3} "." digit{1,3} "." digit{1,3} ;
ipv6        = /* RFC 4291 IPv6 address */ ;
cidr        = ip "/" digit{1,3} ;
pattern     = .* ( "*" | "?" | "[" ) .* ;
exact       = .* ;
```

### Entry Classification

Entries are automatically classified:
1. Contains `/` → CIDR range
2. Valid IPv4/IPv6 → IP address
3. Contains `*`, `?`, `[` → Glob pattern
4. Otherwise → Exact string

### Type Prefixes

Override auto-detection with explicit type prefixes:

| Prefix | Type | Example |
|--------|------|----------|
| `literal:` | Exact string | `literal:*.txt` |
| `glob:` | Pattern | `glob:test.com` |
| `ip:` | IP/CIDR | `ip:10.0.0.1` |

The prefix is automatically stripped before storage:

```text
literal:file*.txt      # Stored as exact string "file*.txt"
glob:simple.com        # Stored as pattern "simple.com"
ip:192.168.1.1         # Stored as IP address 192.168.1.1
```

See [Entry Types - Prefix Technique](../guide/entry-types.md#explicit-type-control-prefix-technique) for details.

### Examples

```text
# IPv4 addresses
192.0.2.1
10.0.0.1

# IPv6 addresses
2001:db8::1
::1

# CIDR ranges
10.0.0.0/8
192.168.0.0/16
2001:db8::/32

# Glob patterns
*.example.com
test-*.domain.com
http://*/admin/*
[a-z]*.evil.com

# Exact strings
exact.match.com
specific-domain.com
```

### Limitations

- No metadata support
- No per-entry JSON data
- Whitespace-only lines ignored
- UTF-8 encoding required

### CLI Usage

```bash
matchy build -o output.mxy input.txt
```

## CSV Format

### Specification

```
file = header row* ;
header = "entry" ("," column_name)* "\n" ;
row = entry_value ("," value)* "\n" ;
```

### Required Columns

| Column | Required | Description |
|--------|----------|-------------|
| `entry` or `key` | Yes | IP, pattern, or exact string |
| Other columns | No | Converted to JSON metadata |

### Data Type Mapping

| CSV Value | JSON Type |
|-----------|----------|
| `"text"` | String |
| `123` | Number |
| `true`/`false` | Boolean |
| Empty | Null |

### Examples

#### Simple CSV

```csv
entry,category,threat_level
192.0.2.1,malware,high
*.phishing.com,phishing,medium
exact.com,suspicious,low
```

Generates:
```json
{
  "192.0.2.1": {
    "category": "malware",
    "threat_level": "high"
  }
}
```

#### Complex CSV

```csv
entry,type,score,tags,verified
10.0.0.1,botnet,95,"c2,trojan",true
*.evil.com,phishing,87,spam,false
```

#### CSV with Type Prefixes

```csv
entry,category,note
literal:test[1].txt,filesystem,Filename with brackets
glob:*.example.com,domain,Pattern match
ip:192.168.1.0/24,network,Private range
```

### Quoting Rules

- Values with commas must be quoted: `"value,with,comma"`
- Quotes inside values: `"value with ""quote"""`
- Empty values allowed: `entry,,value`

### CLI Usage

```bash
matchy build -i csv -o output.mxy input.csv
```

## JSON Format

### Specification

```typescript
// Object format (recommended)
{
  "entry1": { /* metadata */ },
  "entry2": { /* metadata */ },
  ...
}

// Array format
[
  { "entry": "entry1", /* metadata */ },
  { "entry": "entry2", /* metadata */ },
  ...
]
```

### Object Format (Recommended)

**Keys** are entries (IPs, patterns, strings)  
**Values** are metadata objects

```json
{
  "192.0.2.1": {
    "category": "malware",
    "threat_level": "high",
    "first_seen": "2024-01-15",
    "tags": ["botnet", "c2"]
  },
  "*.phishing.com": {
    "category": "phishing",
    "threat_level": "medium",
    "verified": true
  },
  "10.0.0.0/8": {
    "category": "internal",
    "allow": true
  }
}
```

### Array Format

Each object must have `entry` or `key` field:

```json
[
  {
    "entry": "192.0.2.1",
    "category": "malware",
    "score": 95
  },
  {
    "entry": "*.evil.com",
    "category": "phishing",
    "score": 87
  }
]
```

### Array Format with Type Prefixes

```json
[
  {
    "entry": "literal:file*.backup",
    "category": "filesystem",
    "note": "Match literal asterisk"
  },
  {
    "entry": "glob:example.com",
    "category": "domain",
    "note": "Force pattern matching"
  },
  {
    "entry": "ip:10.0.0.0/8",
    "category": "network",
    "note": "Explicit IP range"
  }
]
```

### Supported Types

| JSON Type | Stored As | Notes |
|-----------|-----------|-------|
| `string` | UTF-8 string | Max 64KB |
| `number` | Float64 or Int32 | Depends on value |
| `boolean` | Boolean | 1 byte |
| `null` | Null marker | 1 byte |
| `array` | Array | Nested arrays supported |
| `object` | Map | Nested objects supported |

### Nested Structures

```json
{
  "192.0.2.1": {
    "threat": {
      "category": "malware",
      "subcategory": "trojan",
      "details": {
        "variant": "emotet",
        "version": "3.2"
      }
    },
    "tags": ["c2", "botnet", "high-confidence"],
    "scores": {
      "static": 95,
      "dynamic": 87,
      "reputation": 92
    }
  }
}
```

### CLI Usage

```bash
matchy build -i json -o output.mxy input.json
```

## MISP Format

### Specification

Subset of MISP (Malware Information Sharing Platform) JSON format.

```typescript
{
  "Event": {
    "Attribute": [
      {
        "type": "ip-dst" | "domain" | "url" | /* ... */,
        "value": string,
        "category": string,
        "comment": string,
        /* ... additional MISP fields */
      }
    ]
  }
}
```

### Supported Attribute Types

| MISP Type | Matchy Classification |
|-----------|----------------------|
| `ip-src`, `ip-dst` | IP address |
| `ip-src\|port`, `ip-dst\|port` | IP address (port ignored) |
| `domain`, `hostname` | Exact string or pattern |
| `url` | Pattern if contains wildcards |
| `email` | Pattern if contains wildcards |
| `other` | Auto-detect |

### Example

```json
{
  "Event": {
    "info": "Malware Campaign 2024-01",
    "Attribute": [
      {
        "type": "ip-dst",
        "value": "192.0.2.1",
        "category": "Network activity",
        "comment": "C2 server",
        "to_ids": true
      },
      {
        "type": "domain",
        "value": "evil.example.com",
        "category": "Network activity",
        "comment": "Phishing domain"
      },
      {
        "type": "url",
        "value": "http://*/admin/config.php",
        "category": "Payload delivery",
        "comment": "Malicious URL pattern"
      }
    ]
  }
}
```

### Metadata Extraction

MISP attributes are converted to Matchy metadata:

```json
{
  "misp_type": "ip-dst",
  "misp_category": "Network activity",
  "misp_comment": "C2 server",
  "misp_to_ids": true
}
```

### CLI Usage

```bash
matchy build -i misp -o output.mxy threat-feed.json
```

## Format Comparison

| Feature | Text | CSV | JSON | MISP |
|---------|------|-----|------|------|
| Metadata | ❌ | ✅ Simple | ✅ Rich | ✅ Structured |
| Nested data | ❌ | ❌ | ✅ | ✅ |
| Arrays | ❌ | ❌ | ✅ | ✅ |
| Auto-type | ✅ | ✅ | ✅ | Partial |
| Size | Smallest | Small | Medium | Large |
| Readability | High | High | Medium | Low |
| Standard | No | RFC 4180 | RFC 8259 | MISP spec |

## Auto-Detection

### By Extension

| Extension | Format |
|-----------|--------|
| `.txt` | Text |
| `.csv` | CSV |
| `.json` | JSON (auto-detect object vs. array) |
| `.misp` | MISP |

### By Content

If extension unknown, inspects content:
1. Starts with `{` → JSON or MISP
2. Starts with `[` → JSON array
3. Contains `,` → CSV
4. Otherwise → Text

## Character Encoding

### Requirement

All formats **must** be UTF-8 encoded.

### Validation

- Automatic UTF-8 validation during build
- Invalid UTF-8 → build error
- Use `--trusted` to skip validation (unsafe)

### BOM Handling

UTF-8 BOM (Byte Order Mark) is:
- Detected and skipped
- Not required
- Not preserved in database

## Size Limits

| Component | Limit | Notes |
|-----------|-------|-------|
| File size | 4GB | Total input file |
| Entry key | 64KB | Single IP/pattern/string |
| JSON value | 16MB | Per-entry metadata |
| Entries | 4B | Total entries in database |

## Error Handling

### Parse Errors

```bash
$ matchy build -i csv bad.csv
Error: Parse error at line 42: Unclosed quote
```

### Encoding Errors

```bash
$ matchy build input.txt
Error: Invalid UTF-8 at byte offset 1234
```

### Format Errors

```bash
$ matchy build -i json bad.json
Error: Expected object or array at root
```

## Best Practices

### Choose the Right Format

- **Text**: Simple lists without metadata
- **CSV**: Tabular data with simple metadata
- **JSON**: Rich structured metadata
- **MISP**: Threat intelligence feeds

### Optimize for Size

1. Use text format when no metadata needed
2. Avoid deeply nested JSON
3. Keep metadata minimal
4. Compress input files (gzip)

### Validate Before Building

```bash
# Validate CSV
csv-validator input.csv

# Validate JSON
jq empty input.json

# Test build
matchy build --dry-run input.json
```

## See Also

- [Input Formats Guide](input-formats.md) - User-friendly examples
- [matchy build command](../commands/matchy-build.md) - Build command reference
- [Database Builder API](database-builder.md) - Programmatic building
- [Data Types Reference](data-types-ref.md) - Supported data types
