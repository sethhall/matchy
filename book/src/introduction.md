<div style="text-align: center; margin: 2em 0;">
  <img src="images/logo.jpg" alt="Matchy Logo" style="width: 180px; height: 180px; border-radius: 16px;" />
</div>

# The Matchy Book

Matchy is a [*database*][def-database] for IP address and string matching. Matchy supports
matching IP addresses, CIDR ranges, exact strings, and glob patterns like `*.evil.com` with
microsecond-level query performance. You can build databases with structured data, query them
efficiently, and deploy them in multi-process applications with minimal memory overhead.

## Sections

**[Getting Started](getting-started/index.md)**

To get started with Matchy, install Matchy and create your first
[*database*][def-database].

**[Matchy Guide](guide/index.md)**

The guide will give you all you need to know about how to use Matchy to create
and query databases for IP matching, string matching, and pattern matching.

**[Matchy Reference](reference/index.md)**

The reference covers the details of various areas of Matchy, including the Rust API,
C API, binary format, and architecture.

**[CLI Commands](commands/index.md)**

The commands will let you interact with Matchy databases using the command-line interface.

**[Contributing to Matchy](contributing.md)**

Learn how to contribute to Matchy development.

**[Frequently Asked Questions](faq.md)**

**Appendices:**
* [Glossary](appendix/glossary.md)
* [Examples](appendix/examples.md)

**Other Documentation:**
* [Changelog](changelog.md)
  --- Detailed notes about changes in Matchy in each release.

[def-database]: ./appendix/glossary.md#database '"database" (glossary entry)'
