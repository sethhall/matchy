# MMDB Quick Start

Quick start guide for using Matchy with existing MaxMind DB tools.

## Overview

Matchy databases use the `.mxy` extension but are based on the MMDB format:

- **IP-only databases** are fully MMDB-compatible
- **String/pattern databases** use an extended MMDB format
- **Standard `.mmdb` files** can be read by Matchy

## Using Standard MMDB Files

```rust
use matchy::Database;

// Matchy can read standard MMDB files
let db = Database::open("GeoLite2-City.mmdb")?;
let result = db.lookup("8.8.8.8")?;
```

## Creating MMDB-Compatible Databases

Build IP-only databases that work with standard MMDB readers:

```bash
# Build IP-only database
cat > ips.csv << 'EOF'
entry,country,city
8.8.8.0/24,US,Mountain View
EOF

matchy build -o geoip.mxy --format csv ips.csv
```

This creates a database that:
- Can be read by Matchy
- Can be read by MaxMind's libmaxminddb
- Works with other MMDB tools

## Extended Features

Matchy extends MMDB with:

1. **String matching** - Literal string lookups
2. **Glob patterns** - Wildcard pattern matching
3. **Combined databases** - IPs + patterns in one file

These features are stored in a separate section that standard MMDB readers ignore.

## Compatibility

| Feature | Matchy | libmaxminddb | Other MMDB Tools |
|---------|--------|--------------|------------------|
| IP lookups | ✓ | ✓ | ✓ |
| Metadata | ✓ | ✓ | ✓ |
| String matching | ✓ | ✗ | ✗ |
| Glob patterns | ✓ | ✗ | ✗ |

## See Also

- [MMDB Integration Design](mmdb-integration-design.md)
- [Binary Format](architecture/binary-format.md)
- [Building Databases](user-guide/database-builder.md)
