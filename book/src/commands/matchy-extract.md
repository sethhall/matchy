# matchy extract

Extract patterns (domains, IPs, emails, hashes, cryptocurrency addresses) from log files or unstructured text.

## Synopsis

```console
matchy extract [OPTIONS] <INPUT>...
```

## Description

The `matchy extract` command scans log files or streams to automatically extract IP addresses, domain names, email addresses, file hashes, and cryptocurrency addresses from unstructured text. This is useful for:

- Generating threat intelligence feeds from logs
- Building input lists for `matchy build`
- Analyzing log data for patterns
- Pre-filtering data before database matching

**Key features:**
- SIMD-accelerated extraction (200-500 MB/sec typical throughput)
- Multiple output formats: JSON, CSV, plain text
- Configurable extraction types
- Unicode/IDN domain support with automatic punycode conversion
- Word boundary detection for accurate extraction
- Deduplication with `--unique` flag

## Arguments

### `<INPUT>...`

One or more log files to process (one entry per line), or `-` for stdin.

```console
$ matchy extract access.log
$ matchy extract log1.txt log2.txt log3.txt
$ cat access.log | matchy extract -
```

## Options

### `--format <FORMAT>`

Output format (default: `json`):
- `json` - NDJSON format (one JSON object per pattern)
- `csv` - CSV format with header (type, value columns)
- `text` - Plain text (one pattern per line, no metadata)

```console
$ matchy extract access.log --format json
{"type":"domain","value":"example.com"}
{"type":"ipv4","value":"192.0.2.1"}

$ matchy extract access.log --format csv
type,value
domain,"example.com"
ipv4,"192.0.2.1"

$ matchy extract access.log --format text
example.com
192.0.2.1
```

### `--types <TYPES>`

Comma-separated extraction types (default: `all`):
- `ipv4` or `ip4` - IPv4 addresses only
- `ipv6` or `ip6` - IPv6 addresses only
- `ip` - Both IPv4 and IPv6
- `domain` or `domains` - Domain names
- `email` or `emails` - Email addresses
- `hash` or `hashes` - File hashes (MD5, SHA1, SHA256, SHA384)
- `bitcoin` or `btc` - Bitcoin addresses (all formats)
- `ethereum` or `eth` - Ethereum addresses
- `monero` or `xmr` - Monero addresses
- `crypto` - All cryptocurrency addresses
- `all` - Extract everything (default)

```console
$ matchy extract access.log --types ipv4,domain
$ matchy extract access.log --types ip        # IPv4 + IPv6
$ matchy extract access.log --types all       # Everything
```

### `--min-labels <NUMBER>`

Minimum number of domain labels to extract (default: `2`).

```console
$ matchy extract access.log --min-labels 2    # example.com (default)
$ matchy extract access.log --min-labels 3    # sub.example.com
```

This is useful to filter out bare hostnames or require fully-qualified domain names.

### `--no-boundaries`

Disable word boundary requirements, allowing patterns to be extracted from the middle of text.

By default, extraction requires word boundaries (whitespace, punctuation) around patterns. Use this flag to extract patterns embedded in other text.

```console
$ matchy extract access.log --no-boundaries
```

### `-u, --unique`

Output only unique patterns (deduplicate across all input).

```console
$ matchy extract access.log --unique
```

This maintains a hash set of seen patterns and outputs each unique pattern only once.

### `-s, --stats`

Show extraction statistics to stderr.

```console
$ matchy extract access.log --stats
[INFO] Extracting: IPv4, IPv6, domains, emails
[INFO] Min domain labels: 2
[INFO] Word boundaries: true
[INFO] Unique mode: false

[INFO] === Extraction Complete ===
[INFO] Lines processed: 15,234
[INFO] Patterns found: 3,456
[INFO]   IPv4: 2,100
[INFO]   IPv6: 23
[INFO]   Domains: 1,200
[INFO]   Emails: 133
[INFO] Throughput: 450.23 MB/s
[INFO] Total time: 0.15s
```

Statistics are always written to stderr, leaving stdout clean for piped output.

### `--show-candidates`

Show candidate extraction details for debugging (output to stderr).

```console
$ matchy extract access.log --show-candidates
[CANDIDATE] Domain at 45-61: example.com
[CANDIDATE] IPv4 at 0-10: 192.0.2.1
[CANDIDATE] Email at 23-42: user@example.com
```

## Examples

### Extract All Patterns (JSON)

```console
$ matchy extract access.log
{"type":"ipv4","value":"192.0.2.1"}
{"type":"domain","value":"example.com"}
{"type":"email","value":"user@example.com"}
{"type":"ipv6","value":"2001:db8::1"}
```

### Extract Only Domains

```console
$ matchy extract access.log --types domain --format text
example.com
subdomain.example.org
malware.net
```

### Build Threat Intel Database from Logs

Extract unique domains and build a database:

```console
$ matchy extract suspicious.log \
    --types domain \
    --unique \
    --format text \
    > domains.txt

$ echo "key,threat_level" > threats.csv
$ cat domains.txt | sed 's/^/&,high/' >> threats.csv

$ matchy build threats.csv -o threats.mxy
```

### Extract IPs with Statistics

```console
$ matchy extract access.log --types ip --stats --unique
{"type":"ipv4","value":"192.0.2.1"}
{"type":"ipv4","value":"198.51.100.42"}
{"type":"ipv6","value":"2001:db8::1"}

[INFO] Lines processed: 10,000
[INFO] Patterns found: 2,345
[INFO]   IPv4: 2,320
[INFO]   IPv6: 25
[INFO] Throughput: 380.15 MB/s
[INFO] Total time: 0.08s
```

### CSV Output for Spreadsheet Import

```console
$ matchy extract firewall.log --format csv > patterns.csv
$ open patterns.csv  # Opens in Excel/Numbers/etc.
```

### Extract from stdin Stream

```console
$ tail -f /var/log/syslog | matchy extract - --types domain --stats
```

### Process Multiple Files

```console
$ matchy extract *.log --stats --unique > all_patterns.json
```

## Output Formats

### JSON (NDJSON)

One JSON object per line with type and value:

```json
{"type":"domain","value":"example.com"}
{"type":"ipv4","value":"192.0.2.1"}
{"type":"ipv6","value":"2001:db8::1"}
{"type":"email","value":"user@example.com"}
```

### CSV

Header row followed by data rows:

```csv
type,value
domain,"example.com"
ipv4,"192.0.2.1"
ipv6,"2001:db8::1"
email,"user@example.com"
```

Values are properly escaped (quotes doubled for embedded quotes).

### Text

One pattern per line, no metadata:

```text
example.com
192.0.2.1
2001:db8::1
user@example.com
```

## Pattern Extraction Details

### IPv4 Addresses

Extracts standard IPv4 addresses: `192.0.2.1`, `10.0.0.1`

Validates format and rejects invalid addresses (e.g., `999.999.999.999`).

### IPv6 Addresses

Extracts IPv6 addresses in all standard formats:
- Full: `2001:0db8:0000:0000:0000:0000:0000:0001`
- Compressed: `2001:db8::1`
- IPv4-mapped: `::ffff:192.0.2.1`

### Domain Names

Extracts domain names with proper TLD validation:
- `example.com`
- `subdomain.example.org`
- `multi.level.subdomain.co.uk`

**Unicode/IDN support:** International domain names are automatically converted to punycode:
- Input: `münchen.de`
- Output: `xn--mnchen-3ya.de`

**TLD validation:** Only domains with valid top-level domains are extracted (uses embedded TLD automaton with Public Suffix List data).

### Email Addresses

Extracts email addresses with format validation:
- `user@example.com`
- `first.last@subdomain.example.org`
- `admin+tag@example.net`

### File Hashes

Extracts common cryptographic hashes:
- **MD5**: 32 hex characters (e.g., `5d41402abc4b2a76b9719d911017c592`)
- **SHA1**: 40 hex characters (e.g., `2fd4e1c67a2d28fced849ee1bb76e7391b93eb12`)
- **SHA256**: 64 hex characters
- **SHA384**: 96 hex characters

Useful for malware analysis and threat intelligence feeds.

### Cryptocurrency Addresses

Extracts blockchain addresses with checksum validation:

**Bitcoin (all formats):**
- Legacy (P2PKH): `1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa`
- P2SH: `3Cbq7aT1tY8kMxWLbitaG7yT6bPbKChq64`
- Bech32 (SegWit): `bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq`

**Ethereum:**
- Format: `0x5aeda56215b167893e80b4fe645ba6d5bab767de` (42 chars)
- Validates EIP-55 checksum for mixed-case addresses
- Accepts all-lowercase addresses without checksum

**Monero:**
- Standard addresses starting with `4` or `8` (~95 characters)
- Integrated addresses (~106 characters)

**Validation:** All addresses are validated with cryptographic checksums:
- Bitcoin: Base58Check (double SHA256) or Bech32
- Ethereum: Keccak256-based EIP-55 checksum
- Monero: Keccak256 checksum

Useful for ransomware analysis, fraud investigation, and darknet marketplace intelligence.

## Performance

Typical throughput: **200-500 MB/s** on modern hardware.

Performance factors:
- **Extraction types**: Fewer types = faster (skip unnecessary checks)
- **Word boundaries**: Enabled (default) = faster (reduces false matches)
- **Unique mode**: Enabled = slower (hash set overhead for deduplication)
- **Output format**: Text = fastest, JSON = moderate, CSV = moderate

## Exit Status

- `0` - Success (even if no patterns found)
- `1` - Error (file not found, invalid arguments, etc.)

## See Also

- [matchy match](matchy-match.md) - Match extracted patterns against database
- [matchy build](matchy-build.md) - Build database from extracted patterns
- [Pattern Extraction Guide](../guide/extraction.md) - Detailed extraction documentation
