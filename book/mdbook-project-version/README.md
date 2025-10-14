# mdbook-project-version

A simple mdbook preprocessor that injects the project version from `Cargo.toml` into your documentation.

## Usage

### Installation

The preprocessor is built and run automatically when building the book. No separate installation needed.

### Placeholders

Use these placeholders in your markdown files:

- `{{version}}` - Full version (e.g., "0.5.2")
- `{{version_minor}}` - Minor version (e.g., "0.5")

### Example

In your markdown:

```markdown
Current version: **{{version}}**

Add to your `Cargo.toml`:
\`\`\`toml
[dependencies]
matchy = "{{version_minor}}"
\`\`\`
```

When built, this becomes:

```markdown
Current version: **0.5.2**

Add to your `Cargo.toml`:
\`\`\`toml
[dependencies]
matchy = "0.5"
\`\`\`
```

## How It Works

1. Reads the version from `../Cargo.toml` (relative to book directory)
2. Replaces all occurrences of `{{version}}` and `{{version_minor}}` in all chapters
3. Outputs the modified book to mdbook

## Building the Preprocessor

```bash
cargo build --release
```

The preprocessor is automatically invoked by mdbook via the configuration in `book.toml`:

```toml
[preprocessor.project-version]
command = "cargo run --manifest-path mdbook-project-version/Cargo.toml --quiet"
```

## Testing

To test the preprocessor manually:

```bash
# Build it first
cargo build --release

# Run mdbook (which will use the preprocessor)
cd ..
mdbook build

# Check the output
grep -A2 "Current version" book/installation.html
```

You should see the actual version number (e.g., "0.5.2") instead of the placeholder.
