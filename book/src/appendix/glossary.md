# Glossary

### Database

A *database* is a binary file containing entries for IP addresses, CIDR ranges, exact
strings, and glob patterns, along with associated data. Databases are created with a
[*database builder*](#database-builder) and queried with the `Database::lookup()` method.

### Database Builder

A *database builder* (`DatabaseBuilder`) is used to construct a new [*database*](#database).
You add [*entries*](#entry) to the builder, then call `.build()` to produce the final
database bytes.

### Entry

An *entry* is a single item added to a [*database*](#database). An entry consists of a key
(IP address, CIDR range, exact string, or glob pattern) and associated data. Matchy
automatically detects the entry type based on the key format.

### CIDR

*CIDR* (Classless Inter-Domain Routing) is a notation for specifying IP address ranges,
such as `192.0.2.0/24`. The number after the slash indicates how many bits of the address
are fixed. Matchy supports both IPv4 and IPv6 CIDR ranges.

### Pattern

A *pattern* is a string containing wildcard characters (`*` or `?`) that can match multiple
input strings. For example, `*.example.com` matches `foo.example.com`, `bar.example.com`,
and any other subdomain of `example.com`.

### Query

A *query* is a lookup operation on a [*database*](#database). You pass a string to
`Database::lookup()`, and Matchy returns matching data if found. The query automatically
checks IP addresses, CIDR ranges, exact strings, and patterns.

### Match Mode

*Match mode* determines how string comparisons are performed. `MatchMode::CaseSensitive`
treats `"ABC"` and `"abc"` as different. `MatchMode::CaseInsensitive` treats them as the same.
Match mode is set when creating a [*database builder*](#database-builder).

### Memory Mapping

*Memory mapping* (mmap) is a technique that maps file contents directly into a process's
address space. Matchy uses memory mapping to load [*databases*](#database) instantly without
deserialization. The operating system shares memory-mapped pages across processes, reducing
memory usage.

### MMDB

*MMDB* (MaxMind Database) is a binary format for storing IP geolocation data, created by
MaxMind. Matchy can read standard MMDB files and extends the format to support string
matching and glob patterns.

### Data Value

A *data value* is a piece of structured data associated with an [*entry*](#entry). Matchy
supports several data types including strings, integers, floats, booleans, arrays, and maps.
Data values are stored in a compact binary format within the [*database*](#database).
