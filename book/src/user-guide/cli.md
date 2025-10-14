# Command Line Tool

The `matchy` command-line tool provides a complete interface for building, querying, inspecting, and benchmarking Matchy databases. It's designed for both interactive use and automation in CI/CD pipelines.

## Installation

```bash
# Install from source
cd matchy
cargo install --path .

# Or run directly without installing
cargo build --release
./target/release/matchy --help
```

After installation, the `matchy` binary will be available in your PATH.

## Commands

The CLI tool has four main commands:

### [`matchy build`](cli-build.md)

Build `.mxy` databases from various input formats:
- Text files (simple lists)
- CSV files (with metadata)
- JSON files (with complex metadata)
- MISP exports (threat intelligence)

```bash
matchy build -o threats.mxy --format csv threats.csv
```

**[Read the full build documentation →](cli-build.md)**

### [`matchy query`](cli-query.md)

Query databases for IP addresses, exact strings, or glob pattern matches:

```bash
# Query an IP address
matchy query threats.mxy 1.2.3.4

# Query a domain
matchy query threats.mxy evil.example.com

# Quiet mode for scripting
matchy query threats.mxy 1.2.3.4 --quiet
```

**[Read the full query documentation →](cli-query.md)**

### [`matchy inspect`](cli-inspect.md)

View database information, capabilities, and statistics:

```bash
# Human-readable output
matchy inspect threats.mxy

# JSON output for scripting
matchy inspect threats.mxy --json

# Verbose mode with full metadata
matchy inspect threats.mxy --verbose
```

**[Read the full inspect documentation →](cli-inspect.md)**

### [`matchy bench`](cli-bench.md)

Run comprehensive performance benchmarks:

```bash
# Benchmark IP lookups
matchy bench ip --count 100000

# Benchmark pattern matching
matchy bench pattern --count 50000

# Benchmark combined database
matchy bench combined --count 100000
```

**[Read the full bench documentation →](cli-bench.md)**

## Getting Help

```bash
# General help
matchy --help

# Command-specific help
matchy build --help
matchy query --help
matchy inspect --help
matchy bench --help
```

## Quick Examples

### Build a Simple Blocklist

```bash
# Create a text file with entries
cat > blocklist.txt << 'EOF'
1.2.3.4
10.0.0.0/8
*.evil.com
malware.example.com
EOF

# Build the database
matchy build -o blocklist.mxy blocklist.txt

# Query it
matchy query blocklist.mxy 1.2.3.4
matchy query blocklist.mxy test.evil.com
```

### Build a Threat Intelligence Database

```bash
# CSV with metadata
cat > threats.csv << 'EOF'
entry,threat_level,category,blocked
1.2.3.4,high,malware,true
*.phishing.com,critical,phishing,true
EOF

# Build with metadata
matchy build -o threats.mxy --format csv \
  --database-type "ThreatIntel" \
  --description "Daily threat indicators" \
  threats.csv

# Query and inspect
matchy query threats.mxy 1.2.3.4
matchy inspect threats.mxy
```

### Scripting with Quiet Mode

```bash
#!/bin/bash
# Check if an IP is a threat

if matchy query threats.mxy "$1" --quiet; then
    echo "THREAT DETECTED: $1"
    exit 1
else
    echo "No threat: $1"
    exit 0
fi
```
