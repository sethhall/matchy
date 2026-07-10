#!/bin/bash
# Quick-start fuzzing for matchy
# Run this to set up and test fuzzing in 5 minutes!

set -e

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_ROOT"

echo "🔧 Fuzzing Quick-Start for matchy"
echo "================================="
echo ""

# Check that the undated `+nightly` alias used below is installed.
if ! rustup run nightly rustc --version &> /dev/null; then
    echo "📦 Installing Rust nightly..."
    rustup toolchain install nightly --profile minimal
else
    echo "✓ Rust nightly already installed"
fi

# Check if cargo-fuzz is installed
if ! command -v cargo-fuzz &> /dev/null; then
    echo "📦 Installing cargo-fuzz (this may take a few minutes)..."
    cargo install cargo-fuzz --locked
else
    echo "✓ cargo-fuzz already installed"
fi

if [ ! -f "fuzz/Cargo.toml" ]; then
    echo "❌ Run this script from a Matchy checkout containing fuzz/Cargo.toml"
    exit 1
fi

echo "✓ Found the checked-in fuzz workspace"
echo "✓ fuzz_database_load includes a deterministic mixed database seed"

echo ""
echo "🚀 Setup complete! Ready to fuzz."
echo ""
echo "To run fuzzing:"
echo "  Quick test (60 seconds):  cargo +nightly fuzz run fuzz_database_load -- -max_total_time=60"
echo "  5 minute test:            cargo +nightly fuzz run fuzz_database_load -- -max_total_time=300"
echo "  Overnight (8 hours):      cargo +nightly fuzz run fuzz_database_load -- -max_total_time=28800"
echo "  With all CPU cores:       cargo +nightly fuzz run fuzz_database_load -- -jobs=8"
echo ""
echo "📊 To see what fuzzing found:"
echo "  ls fuzz/artifacts/        # Crashes will be saved here"
echo "  ls fuzz/corpus/           # Generated test cases"
echo ""

# Offer to run a quick test
read -p "🎲 Run a quick 60-second fuzz test now? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo ""
    echo "🔍 Starting 60-second fuzz campaign..."
    echo "   (This will generate random databases and test loading)"
    echo ""
    cargo +nightly fuzz run fuzz_database_load -- -max_total_time=60 || {
        echo ""
        echo "⚠️  Fuzzer stopped (may have found a bug!)"
        if [ -d "fuzz/artifacts/fuzz_database_load" ]; then
            echo "🐛 Found crashes in: fuzz/artifacts/fuzz_database_load/"
            ls -lh fuzz/artifacts/fuzz_database_load/
            echo ""
            echo "To reproduce a crash:"
            echo "  cargo +nightly fuzz run fuzz_database_load fuzz/artifacts/fuzz_database_load/crash-<file>"
        fi
        exit 1
    }
    
    echo ""
    echo "✅ 60-second fuzz test completed successfully!"
    echo ""
    echo "📈 Stats:"
    echo "  Corpus size: $(find fuzz/corpus/fuzz_database_load -type f | wc -l) test cases"
    echo "  Total size:  $(du -sh fuzz/corpus/fuzz_database_load | cut -f1)"
    echo ""
    echo "💡 No crashes found (good!). Run longer to test more thoroughly."
fi

echo ""
echo "📚 For more info, see fuzz/README.md"
