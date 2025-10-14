#!/bin/sh
# Wrapper to run mdbook-cmdrun with matchy in PATH
# Set RUN_CMDS=1 to actually run commands and save outputs to repo
# Otherwise, commands return saved outputs from command-outputs/ directory
set -e

# Go to project root
cd "$(dirname "$0")/.." || exit 1
PROJECT_ROOT="$(pwd)"

# Directory for committed output files
OUTPUT_DIR="$PROJECT_ROOT/book/command-outputs"
mkdir -p "$OUTPUT_DIR"

# Create a wrapper for matchy that either runs or returns saved output
WRAPPER_DIR="$PROJECT_ROOT/book/.cmdrun-wrapper"
mkdir -p "$WRAPPER_DIR"
MATCHY_WRAPPER="$WRAPPER_DIR/matchy"

cat > "$MATCHY_WRAPPER" << 'WRAPPER_EOF'
#!/bin/sh
# Wrapper for matchy commands - either run or use saved output
set -e

# Generate filename from command arguments
CMD_HASH=$(echo "$*" | shasum -a 256 | cut -d' ' -f1)
OUTPUT_FILE="${OUTPUT_DIR}/${CMD_HASH}.txt"
META_FILE="${OUTPUT_DIR}/${CMD_HASH}.meta"

if [ "$RUN_CMDS" = "1" ]; then
    # RUN_CMDS=1: Actually run the command and save output
    REAL_MATCHY="$MATCHY_REAL_PATH"
    if [ ! -x "$REAL_MATCHY" ]; then
        echo "Error: matchy binary not found at $REAL_MATCHY" >&2
        echo "Run: cargo build --release" >&2
        exit 1
    fi
    
    OUTPUT=$("$REAL_MATCHY" "$@" 2>&1)
    EXIT_CODE=$?
    
    if [ $EXIT_CODE -eq 0 ]; then
        # Save to committed output files
        echo "$OUTPUT" > "$OUTPUT_FILE"
        echo "command=matchy $*" > "$META_FILE"
        echo "timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$META_FILE"
        echo "hash=$CMD_HASH" >> "$META_FILE"
        echo "$OUTPUT"
        echo "[cmdrun] Saved output to command-outputs/$CMD_HASH.txt" >&2
    else
        echo "$OUTPUT" >&2
        exit $EXIT_CODE
    fi
else
    # Normal mode: Use saved output file
    if [ -f "$OUTPUT_FILE" ]; then
        cat "$OUTPUT_FILE"
    else
        echo "Error: No saved output for 'matchy $*'" >&2
        echo "Run: RUN_CMDS=1 mdbook build" >&2
        echo "Output file would be: command-outputs/$CMD_HASH.txt" >&2
        exit 1
    fi
fi
WRAPPER_EOF

chmod +x "$MATCHY_WRAPPER"

# Set up environment
export OUTPUT_DIR
export MATCHY_REAL_PATH="$PROJECT_ROOT/target/release/matchy"
export PATH="$WRAPPER_DIR:$PATH"

# Run mdbook-cmdrun from book directory
cd "$PROJECT_ROOT/book" || exit 1
exec mdbook-cmdrun "$@"
