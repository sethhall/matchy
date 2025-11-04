# Update PSL Tool

**Development tool** to update the Public Suffix List (PSL) Aho-Corasick automaton.

## Purpose

This tool downloads the latest Public Suffix List from [publicsuffix.org](https://publicsuffix.org/list/) and rebuilds the pre-compiled Aho-Corasick automaton used for TLD matching in matchy's domain extractor.

The built automaton is saved to `src/data/tld_automaton.ac` and committed to the repository, so end users never need to run this tool.

## Usage

```bash
cd tools/update-psl
cargo run
```

The tool will:
1. Download the latest PSL from publicsuffix.org
2. Parse all TLD patterns (including Unicode TLDs)
3. Convert Unicode TLDs to punycode
4. Build an Aho-Corasick automaton
5. Save to `../../src/data/tld_automaton.ac`

After running, commit the updated automaton:

```bash
git add ../../src/data/tld_automaton.ac
git commit -m "Update Public Suffix List automaton"
```

## Why Separate?

This tool uses the `idna` crate which pulls in 74+ transitive dependencies (ICU internationalization stack). Since this is only run occasionally during development, keeping it separate prevents bloating matchy's dependency tree.

## Dependencies

- `idna` - Unicode domain name to punycode conversion
- `matchy` - For Paraglob and serialization APIs
