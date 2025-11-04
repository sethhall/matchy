#!/bin/bash
# Wrapper script for mdbook-cmdrun preprocessor
# Ensures matchy is in PATH when commands execute

# Add cargo bin to PATH if not already present
export PATH="$HOME/.cargo/bin:$PATH"

# Run mdbook-cmdrun with all arguments
exec mdbook-cmdrun "$@"
