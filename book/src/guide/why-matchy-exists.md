# Why Matchy Exists

## The Problem

Many applications need to match IP addresses and strings against large datasets. Common
use cases include:

- Threat intelligence: checking IPs and domains against blocklists
- GeoIP lookups: finding location data for IP addresses
- Domain categorization: classifying websites by patterns
- Network security: matching against indicators of compromise

Traditional approaches have significant limitations:

**Hash tables** provide fast exact lookups, but can't match patterns. You can't use a hash
table to match `phishing.evil.com` against a pattern like `*.evil.com`.

**Sequential scanning** works for patterns but doesn't scale. With 10,000 patterns, you
perform 10,000 comparisons per lookup. This approach quickly becomes a bottleneck.

**Multiple data structures** add complexity. Using a hash table for exact matches, a tree
for IP ranges, and pattern matching for domains means maintaining three separate systems.

**Serialization overhead** slows down loading. Traditional databases need to parse and
deserialize data on startup, which can take hundreds of milliseconds or more.

**Memory duplication** wastes resources. In multi-process applications, each process loads
its own copy of the database, multiplying memory usage.

## The Solution

Matchy addresses these problems with a unified approach:

**Automatic type detection** means one database holds IPs, CIDR ranges, exact strings, and
patterns. You don't need to know which type you're querying - Matchy figures it out.

**Optimized data structures** provide efficient lookups for each type. IPs use a binary
search tree. Exact strings use hash tables. Patterns use the Aho-Corasick algorithm.

**Memory mapping** eliminates deserialization. Databases are memory-mapped files that load
in under a millisecond. The operating system shares pages across processes automatically.

**Compact binary format** reduces size. Matchy uses a space-efficient binary representation
similar to MaxMind's MMDB format.

## Performance

A typical Matchy database can perform:

- 7M+ IP address lookups per second
- 1M+ pattern matches per second (with 50,000 patterns)
- Sub-microsecond latency for individual queries
- Sub-millisecond loading time

## Compatibility

Matchy can read standard MaxMind MMDB files, making it a drop-in replacement for GeoIP
databases. It extends the MMDB format to support string matching and patterns while
maintaining compatibility with existing files.

## When to Use Matchy

Matchy is designed for applications that need:

- Fast lookups against large datasets
- Pattern matching in addition to exact matches
- IP address and string matching in the same database
- Minimal memory overhead in multi-process architectures
- Quick database loading without deserialization

If you only need exact string matching and already have a solution that works, Matchy
might be overkill. But if you need patterns, IPs, and efficiency at scale, Matchy was
built for you.
