# Using the CLI

The Matchy command-line interface lets you build and query [*databases*][def-database]
without writing code. This is perfect for:

- Operations and DevOps workflows
- Quick prototyping and testing
- Shell scripts and automation
- One-off queries and analysis

## What You'll Learn

* [Installing the CLI](cli-installation.md) - Install the `matchy` command-line tool
* [First Database with CLI](cli-first-database.md) - Build and query your first database

## Example Workflow

```console
$ # Build a database from a CSV file
$ matchy build threats.csv -o threats.mxy

$ # Query it
$ matchy query threats.mxy 192.0.2.1
Found: IP address 192.0.2.1
  threat_level: "high"
  category: "malware"

$ # Benchmark performance
$ matchy bench threats.mxy
Queries per second: 7,234,891
Average latency: 138ns
```

After completing this section, check out the [CLI Commands](../commands/index.md)
reference for detailed documentation on all available commands.

[def-database]: ../appendix/glossary.md#database '"database" (glossary entry)'
