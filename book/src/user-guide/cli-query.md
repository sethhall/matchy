# `matchy query` - Query Databases

Query a database for IP addresses, exact strings, or glob pattern matches.

## Synopsis

```bash
matchy query [OPTIONS] <DATABASE> <QUERY>
```

## Arguments

- `<DATABASE>` - Path to the `.mxy` database file
- `<QUERY>` - Query string (IP address, domain, URL, etc.)

## Options

| Option | Description |
|--------|-------------|
| `-q, --quiet` | Quiet mode - no output, only exit code (0=found, 1=not found) |

## Output Format

The query command returns JSON arrays:

**Match found:**
```json
[
  {
    "threat_level": "high",
    "category": "malware",
    "first_seen": "2025-01-01",
    "blocked": true
  }
]
```

**No match:**
```json
[]
```

**Multiple pattern matches:**
```json
[
  {"category": "phishing", "threat_level": "critical"},
  {"category": "malware", "threat_level": "high"}
]
```

## IP Address Queries

For IP queries, the result includes CIDR information:

```bash
matchy query threats.mxy 8.8.8.8
```

**Output:**
```json
[
  {
    "country": "US",
    "city": "Mountain View",
    "latitude": 37.386,
    "longitude": -122.084,
    "cidr": "8.8.8.0/24",
    "prefix_len": 24
  }
]
```

## Pattern Matching Queries

Pattern queries return data for all matching patterns:

```bash
matchy query threats.mxy evil.malicious.com
```

If the database contains patterns like:
- `*.malicious.com`
- `evil.*`
- `*.com`

All matching patterns' data will be returned in the array.

## Exit Codes

| Exit Code | Meaning |
|-----------|----------|
| `0` | Match found |
| `1` | No match found |

## Quiet Mode

Use quiet mode for scripting - no JSON output, just exit codes:

```bash
if matchy query threats.mxy 1.2.3.4 --quiet; then
    echo "Threat detected!"
    # Take action...
else
    echo "No threat found"
fi
```

## Examples

### Query an IP address

```bash
matchy query threats.mxy 1.2.3.4
# Output: [{"threat_level":"high","category":"malware"}]
```

### Query a domain

```bash
matchy query threats.mxy evil.example.com
# Output: [{"threat_level":"critical","category":"phishing"}]
```

### Query with no match

```bash
matchy query threats.mxy benign.example.com
# Output: []
```

### Quiet mode for scripting

```bash
matchy query threats.mxy 1.2.3.4 --quiet
echo $?  # 0 if found, 1 if not found
```

### Pipeline usage

```bash
# Check multiple IPs
cat suspicious-ips.txt | while read ip; do
    if matchy query threats.mxy "$ip" --quiet; then
        echo "THREAT: $ip"
    fi
done
```

### Parse JSON output

```bash
# Using jq to extract specific fields
matchy query threats.mxy 1.2.3.4 | jq '.[0].threat_level'
# Output: "high"

matchy query geoip.mxy 8.8.8.8 | jq '.[0] | {country, city}'
# Output: {"country": "US", "city": "Mountain View"}
```

### Batch processing

```bash
#!/bin/bash
# check-threats.sh - Check multiple entries

DATABASE="threats.mxy"
INPUT_FILE="$1"

while IFS= read -r line; do
    if matchy query "$DATABASE" "$line" --quiet; then
        DATA=$(matchy query "$DATABASE" "$line")
        LEVEL=$(echo "$DATA" | jq -r '.[0].threat_level')
        echo "$line: THREAT ($LEVEL)"
    else
        echo "$line: clean"
    fi
done < "$INPUT_FILE"
```

### Integration with monitoring

```bash
#!/bin/bash
# Real-time threat check

QUERY="$1"

if matchy query threats.mxy "$QUERY" --quiet; then
    # Get threat details
    DATA=$(matchy query threats.mxy "$QUERY")
    LEVEL=$(echo "$DATA" | jq -r '.[0].threat_level')
    CATEGORY=$(echo "$DATA" | jq -r '.[0].category')
    
    # Alert
    echo "ALERT: Threat detected!"
    echo "  Query: $QUERY"
    echo "  Level: $LEVEL"
    echo "  Category: $CATEGORY"
    
    # Take action (e.g., block, log, notify)
    # ...
    
    exit 1
else
    exit 0
fi
```

## Troubleshooting

### "Failed to load database"

```
Error: Failed to load database: database.mxy
```

**Solution:** 
- Check file exists and is readable
- Verify file is a valid `.mxy` database (use `matchy inspect`)
- Check for file corruption

### Always returns empty array `[]`

```bash
matchy query threats.mxy 1.2.3.4
# Output: []
```

**Solution:**
- Check what data is in the database: `matchy inspect threats.mxy`
- Verify the query string matches the data type (IP vs string vs pattern)
- For case-insensitive databases, check if the query uses the right case

### Slow queries

**Solution:**
- Use `matchy bench` to establish baseline performance
- Check database size with `matchy inspect`
- Use trusted mode if you control the database
- Simplify glob patterns if possible

## Performance Tips

1. **Use quiet mode for scripting** - faster when you only need exit codes
2. **Batch queries efficiently** - minimize database opens/closes
3. **Use trusted mode** - 15-20% faster for pattern-heavy databases (only for databases you control)
4. **Leverage memory mapping** - multiple processes share the same database in RAM

## See Also

- [CLI Overview](cli.md) - Command line tool overview
- [Build Command](cli-build.md) - Building databases
- [Inspect Command](cli-inspect.md) - Inspecting databases
- [Workflows](cli-workflows.md) - Common usage patterns
