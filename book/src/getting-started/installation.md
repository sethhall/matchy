# Installation

To start using Matchy, you'll need to install Rust.

## Installing Rust

Matchy requires Rust 1.70 or later. If you don't have Rust installed:

```console
$ curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

This will download and install the Rust toolchain. You can verify your installation:

```console
$ rustc --version
rustc 1.70.0 (or later)
$ cargo --version
cargo 1.70.0 (or later)
```

## Installing Matchy

### As a Rust library

Add Matchy to your `Cargo.toml`:

```toml
[dependencies]
matchy = "{{version_minor}}"
```

Then run `cargo build`:

```console
$ cargo build
    Updating crates.io index
   Downloading matchy v{{version_minor}}
     Compiling matchy v{{version_minor}}
     Compiling your-project v0.1.0
```

### As a command-line tool

Install the `matchy` CLI from crates.io:

```console
$ cargo install matchy
```

This will build and install the `matchy` binary. Verify installation:

```console
$ matchy --version
matchy {{version}}
```

## Next Steps

Now that you have Matchy installed, the next section will walk you through creating
your first database.

* [First Steps with Matchy](first-steps.md)
