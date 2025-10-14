# CLI Workflows & Best Practices

Common workflows and best practices for using the Matchy CLI tool.

## Common Workflows

### Building a Threat Intelligence Database

```bash
# 1. Build from multiple sources
matchy build -o threats.mxy --format csv \
  --database-type "ThreatIntel" \
  --description "Combined threat indicators" \
  --verbose \
  ips.csv domains.csv urls.csv

# 2. Inspect the result
matchy inspect threats.mxy

# 3. Test queries
matchy query threats.mxy 1.2.3.4
matchy query threats.mxy evil.example.com

# 4. Benchmark performance
matchy bench combined --count 50000 --keep \
  --output test-threats.mxy
```

### Integrating with Monitoring Systems

```bash
#!/bin/bash
# check-threat.sh - Check if an IP/domain is a threat

DATABASE="/opt/security/threats.mxy"
QUERY="$1"

if matchy query "$DATABASE" "$QUERY" --quiet; then
    # Threat found - get details
    DATA=$(matchy query "$DATABASE" "$QUERY")
    LEVEL=$(echo "$DATA" | jq -r '.[0].threat_level')
    CATEGORY=$(echo "$DATA" | jq -r '.[0].category')
    
    echo "THREAT DETECTED"
    echo "Query: $QUERY"
    echo "Level: $LEVEL"
    echo "Category: $CATEGORY"
    exit 1
else
    echo "No threat found"
    exit 0
fi
```

### Building a GeoIP Database

```bash
# 1. Prepare CSV with IP ranges and location data
cat > geoip.csv << 'EOF'
entry,country,city,latitude,longitude,continent
8.8.8.0/24,US,Mountain View,37.386,-122.084,NA
1.1.1.0/24,AU,Sydney,-33.868,151.209,OC
185.199.108.0/22,US,San Francisco,37.774,-122.419,NA
EOF

# 2. Build database
matchy build -o geoip.mxy --format csv \
  --database-type "GeoIP-Lite" \
  --description "Custom GeoIP database" \
  geoip.csv

# 3. Query IP addresses
matchy query geoip.mxy 8.8.8.8 | jq '.[0] | {country, city}'
```

### Automated Database Updates

```bash
#!/bin/bash
# update-threats.sh - Update threat database daily

DATE=$(date +%Y%m%d)
OUTPUT="/opt/security/threats-${DATE}.mxy"
CURRENT="/opt/security/threats.mxy"

# Download latest threat feeds
curl -o /tmp/threats.csv "https://example.com/api/threats/daily.csv"

# Build new database
matchy build -o "$OUTPUT" --format csv \
  --database-type "ThreatIntel" \
  --description "Daily threat feed $DATE" \
  --verbose \
  /tmp/threats.csv

if [ $? -eq 0 ]; then
    # Success - update symlink
    ln -sf "$OUTPUT" "$CURRENT"
    echo "Database updated: $OUTPUT"
    
    # Clean up old databases (keep last 7 days)
    find /opt/security -name 'threats-*.mxy' -mtime +7 -delete
else
    echo "Database build failed"
    exit 1
fi
```

### Batch Processing

```bash
#!/bin/bash
# batch-check.sh - Check multiple entries

DATABASE="threats.mxy"
INPUT="suspicious-entries.txt"
OUTPUT="results.json"

echo "[" > "$OUTPUT"
FIRST=true

while IFS= read -r entry; do
    if matchy query "$DATABASE" "$entry" --quiet; then
        DATA=$(matchy query "$DATABASE" "$entry")
        
        # Add comma before all but first entry
        if [ "$FIRST" = false ]; then
            echo "," >> "$OUTPUT"
        fi
        FIRST=false
        
        # Add entry with query info
        echo "$DATA" | jq --arg q "$entry" '.[0] + {query: $q}' >> "$OUTPUT"
    fi
done < "$INPUT"

echo "]" >> "$OUTPUT"
echo "Results saved to $OUTPUT"
```

## Best Practices

### Performance

1. **Use case-sensitive matching** unless specifically needed
   ```bash
   # Faster (default)
   matchy build -o db.mxy patterns.txt
   
   # Slower but case-insensitive
   matchy build -o db.mxy --case-insensitive patterns.txt
   ```

2. **Keep glob patterns simple**
   - Prefix patterns (`prefix-*`) are fastest
   - Suffix patterns (`*.domain.com`) are next fastest
   - Complex patterns with multiple wildcards are slowest

3. **Use literal matches** instead of patterns when you don't need wildcards

4. **Use trusted mode** for databases you control
   ```bash
   # 15-20% faster, but only for trusted databases
   matchy bench pattern --count 200000 --trusted
   ```

5. **Leverage memory mapping**
   - Multiple processes share the same database in RAM
   - No need to worry about loading databases multiple times

### Building Databases

1. **Use CSV for structured metadata** - easiest format

2. **Use JSON for complex nested data**

3. **Use text format for simple lists** - fastest to build

4. **Combine multiple sources** into a single database

5. **Set database type and description**
   ```bash
   matchy build -o db.mxy --format csv \
     --database-type "MyDatabase" \
     --description "Production database" \
     data.csv
   ```

6. **Use verbose mode** for large builds
   ```bash
   matchy build -o db.mxy --verbose data.csv
   ```

### Querying

1. **Use quiet mode for scripting**
   ```bash
   if matchy query db.mxy "$QUERY" --quiet; then
       # Found
   fi
   ```

2. **Parse JSON with jq**
   ```bash
   LEVEL=$(matchy query db.mxy "$IP" | jq -r '.[0].threat_level')
   ```

3. **Batch process efficiently**
   ```bash
   # Reuse database handle when possible
   while read entry; do
       matchy query db.mxy "$entry" --quiet && echo "THREAT: $entry"
   done < entries.txt
   ```

4. **Check exit codes**
   - 0 = found
   - 1 = not found

### Automation

1. **Automate database updates** - rebuild daily/weekly

2. **Version your databases** - include date in filename
   ```bash
   OUTPUT="threats-$(date +%Y%m%d).mxy"
   ```

3. **Keep backups** - maintain the last N days

4. **Monitor build times** - watch for performance regressions

5. **Test after building**
   ```bash
   matchy build -o new.mxy data.csv
   matchy inspect new.mxy
   matchy query new.mxy test-entry
   ```

## Integration Examples

### Web Service Integration

```python
#!/usr/bin/env python3
# threat-api.py - Simple Flask API for threat checking

from flask import Flask, jsonify, request
import subprocess
import json

app = Flask(__name__)
DATABASE = "/opt/security/threats.mxy"

@app.route('/check/<query>')
def check_threat(query):
    result = subprocess.run(
        ['matchy', 'query', DATABASE, query, '--quiet'],
        capture_output=True
    )
    
    if result.returncode == 0:
        # Threat found - get details
        data_result = subprocess.run(
            ['matchy', 'query', DATABASE, query],
            capture_output=True,
            text=True
        )
        return jsonify(json.loads(data_result.stdout))
    else:
        return jsonify([])

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
```

### Nginx Integration

```nginx
# nginx.conf - Block requests based on threat database

map $remote_addr $is_threat {
    default 0;
    
    # Dynamic threat check (requires nginx-lua-module)
    # Check IP against matchy database
}

server {
    listen 80;
    
    # Check if IP is a threat
    if ($is_threat) {
        return 403 "Access Denied";
    }
    
    location / {
        # Normal processing
        proxy_pass http://backend;
    }
}
```

### Log Analysis

```bash
#!/bin/bash
# analyze-logs.sh - Check access logs for threats

DATABASE="threats.mxy"
ACCESS_LOG="/var/log/nginx/access.log"

# Extract unique IPs from logs
awk '{print $1}' "$ACCESS_LOG" | sort -u | while read ip; do
    if matchy query "$DATABASE" "$ip" --quiet; then
        DATA=$(matchy query "$DATABASE" "$ip")
        LEVEL=$(echo "$DATA" | jq -r '.[0].threat_level')
        echo "THREAT: $ip (Level: $LEVEL)"
    fi
done
```

## Troubleshooting

### Performance Issues

**Problem:** Slow build times

**Solutions:**
- Use `--verbose` to identify bottlenecks
- Break large files into smaller chunks
- Use text format if metadata isn't needed

**Problem:** Slow queries

**Solutions:**
- Run `matchy bench` to establish baseline
- Check database size with `matchy inspect`
- Use trusted mode (if you control the database)
- Simplify glob patterns

### Memory Issues

**Problem:** High memory usage

**Solution:** Memory mapping uses virtual memory, not RAM. OS automatically shares pages between processes. Check actual RAM usage, not virtual memory.

### Build Failures

**Common errors and solutions:**

```bash
# Missing column error
Error: CSV must have an 'entry' or 'key' column
# Solution: First column must be named 'entry' or 'key'

# Unknown format error
Error: Unknown format: xlsx
# Solution: Only text, csv, json, and misp are supported

# File not found error
Error: Failed to open input file: data.txt
# Solution: Check file path and permissions
```

## Exit Codes Reference

| Command | Exit Code | Meaning |
|---------|-----------|---------|
| `build` | 0 | Success |
| `build` | 1 | Build failed |
| `query` | 0 | Match found |
| `query` | 1 | No match found |
| `inspect` | 0 | Success |
| `inspect` | 1 | Failed to load database |
| `bench` | 0 | Benchmark completed |
| `bench` | 1 | Benchmark failed |

## See Also

- [CLI Overview](cli.md) - Command line tool overview
- [Build Command](cli-build.md) - Building databases
- [Query Command](cli-query.md) - Querying databases
- [Inspect Command](cli-inspect.md) - Inspecting databases
- [Bench Command](cli-bench.md) - Benchmarking
