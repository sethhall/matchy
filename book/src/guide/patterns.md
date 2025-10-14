# Pattern Matching

Matchy uses **glob patterns** for flexible string matching. This chapter explains pattern syntax and matching rules.

## Glob Syntax

### Asterisk (`*`)
Matches zero or more of any character.

Pattern: `*.example.com` matches `foo.example.com`, `bar.example.com`

### Question Mark (`?`)
Matches exactly one character.

Pattern: `test-?` matches `test-1`, `test-a` but not `test-ab`

### Character Sets (`[abc]`)
Matches one character from the set.

Pattern: `test-[abc].com` matches `test-a.com`, `test-b.com`, `test-c.com`

### Negated Sets (`[!abc]`)
Matches one character NOT in the set.

### Ranges (`[a-z]`, `[0-9]`)
Matches one character in the range.

## Case Sensitivity

Matching behavior depends on the match mode set when building the database.

**CaseInsensitive** (recommended): `*.Example.COM` matches `foo.example.com`
**CaseSensitive**: Must match exact case

## Common Patterns

Domain suffixes: `*.example.com`, `*.*.example.com`
URL patterns: `http://*/admin/*`
Flexible matching: `malware-*`, `*-[0-9][0-9][0-9]`

## Performance

Patterns use Aho-Corasick algorithm - all patterns searched simultaneously.
Typical: 1-2 microseconds for 50,000 patterns.

See [Entry Types](entry-types.md) and [Performance Considerations](performance.md) for more details.

[def-match-mode]: ../appendix/glossary.md#match-mode '"match mode" (glossary entry)'
