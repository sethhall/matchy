# Getting Started

This section provides a quick introduction to Matchy. Choose your path based on how
you plan to use Matchy:

## Using the CLI

If you want to build and query databases from the command line, or integrate Matchy
into shell scripts and workflows:

* [Using the CLI](cli.md)
    * [Installing the CLI](cli-installation.md)
    * [First Database with CLI](cli-first-database.md)

**Best for**: Operations, DevOps, quick prototyping, standalone tools

## Using the API

If you're building an application that needs to query databases programmatically:

* [Using the API](api.md)
    * [Installing as a Library](api-installation.md)
    * [First Database with Rust](api-rust-first.md)
    * [First Database with C](api-c-first.md)

**Best for**: Application development, embedded systems, language integration

---

Both paths create compatible [*databases*][def-database] - a database built with the
CLI can be queried by the API and vice versa.

[def-database]: ../appendix/glossary.md#database '"database" (glossary entry)'
