# Matchy Documentation

This directory contains the source for the Matchy book, built with [mdbook](https://rust-lang.github.io/mdBook/).

## Quick Start

**Important**: All mdbook commands must be run from the `book/` directory.

### Build the book

```bash
cd book
mdbook build
```

Or from project root:
```bash
(cd book && mdbook build)
```

### Serve locally with live reload

```bash
cd book
mdbook serve
```

Then open http://localhost:3000

## Structure

```
book/
├── src/                    # Markdown source files
│   ├── introduction.md     # Book introduction
│   ├── getting-started/    # Two-path Getting Started
│   │   ├── cli*.md         # CLI path (3 chapters)
│   │   └── api*.md         # API path (4 chapters)
│   ├── guide/              # Unified conceptual guide
│   │   └── *.md            # 7 concept chapters
│   ├── commands/           # CLI command reference
│   │   └── *.md            # 5 command pages
│   ├── reference/          # API and format reference
│   │   └── *.md            # Detailed technical docs
│   └── appendix/           # Glossary and examples
├── book.toml               # mdbook configuration
└── book/                   # Generated HTML (ignored)
```

## Documentation Philosophy

Following the Cargo book model:

- **Getting Started** - Split by tool (CLI vs API)
- **Guide** - Unified concepts (tool-agnostic)
- **Reference** - Split by tool (CLI/Rust/C)
- **Commands** - CLI reference
- **Appendices** - Glossary and examples

## Status

- ✅ Getting Started: 100% complete (8 chapters)
- ✅ Guide: 100% complete (7 chapters)
- ✅ CLI Commands: 100% complete (5 pages)
- ⚠️ Reference: Stub files (ready to fill)
- ✅ Appendices: 100% complete

**Total**: 89 markdown files, ~15,000 words

## Key Documents

- `DOCUMENTATION_COMPLETE.md` - Complete summary of all work
- `INFORMATION_ARCHITECTURE.md` - Visual architecture diagrams
- `TWO_PATH_SUMMARY.md` - Getting Started bifurcation details
- `GUIDE_RESTRUCTURE_PROPOSAL.md` - Guide design rationale

## Command Output Management

Command examples with the ✓ indicator have their output committed to the repository. You control when to update them.

### Normal Build (Fast)

```bash
cd book
mdbook build
```

Uses saved command outputs from `command-outputs/` directory. Fast builds for everyday use.

### Update Command Outputs

```bash
# First, ensure matchy is built
cargo build --release

# Run commands and save outputs (from book/ directory)
cd book
RUN_CMDS=1 mdbook build
```

This:
1. Executes all `<!-- cmdrun ... -->` commands
2. Saves outputs to `command-outputs/*.txt` files
3. Saves metadata to `command-outputs/*.meta` files
4. Commits these files to the repository

### How It Works

- Commands marked with `<!-- cmdrun ... -->` are processed by `mdbook-cmdrun`
- The `run-cmdrun.sh` wrapper (located in `book/` directory) intercepts commands:
  - **Normal mode**: Returns saved output from `command-outputs/`
  - **RUN_CMDS=1**: Runs commands and saves new outputs
- Output files are committed to the repo for reproducibility
- The wrapper script ensures `matchy` is in PATH during execution
- **Note**: mdbook must be run from the `book/` directory for the wrapper to be found

### Managing Command Outputs

```bash
# View what commands are saved
cat command-outputs/*.meta

# List saved outputs
ls -lh command-outputs/

# Clear all saved outputs (requires RUN_CMDS=1 rebuild)
rm -rf command-outputs/
```

### Adding New Commands

To add a command with auto-generated output:

```markdown
Output: <sup title="Auto-generated on build">✓</sup>

```
<!-- cmdrun matchy bench ip --count 1000 -->
```
```

Then run `RUN_CMDS=1 mdbook build` to generate and commit the output.

### Files with Generated Output

These files contain command output from `command-outputs/`:

- `src/commands/matchy-bench.md` - Benchmark examples
- `src/commands/matchy-validate.md` - Validation examples
- Other command files as marked with ✓

## Contributing

When adding content:
1. Follow the Cargo book prose style (direct, educational)
2. Show examples with output
3. Cross-link to related content
4. Use glossary links for key terms
5. Build and preview before committing
6. Regenerate command examples if output format changed

## Building

Requires:
- `mdbook` - Install with `cargo install mdbook`
- `mdbook-mermaid` - For diagrams (optional)

Build commands (run from `book/` directory):
```bash
cd book
mdbook build              # Build once
mdbook serve              # Serve with live reload
mdbook test               # Test code examples
mdbook clean              # Clean build artifacts
```

## Deployment

The book can be deployed to:
- GitHub Pages
- Netlify
- Any static hosting

The `book/` directory contains the complete static site.
