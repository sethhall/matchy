#!/bin/bash
set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== Matchy Benchmark Comparison ===${NC}"
echo

# Check if we're in the right directory
if [[ ! -f "Cargo.toml" ]] || [[ ! -d "benches" ]]; then
    echo -e "${RED}Error: Must be run from matchy project root${NC}"
    exit 1
fi

# Parse arguments
BASELINE_NAME="${1:-pre-optimization}"

# Setup symlink if not already set up
if [[ ! -L "target/criterion" ]]; then
    echo -e "${YELLOW}Setting up persistent benchmark storage...${NC}"
    mkdir -p benchmarks/criterion_data
    mkdir -p target
    ln -s ../benchmarks/criterion_data target/criterion
    echo
fi

# Check if baseline exists
if [[ ! -d "target/criterion" ]]; then
    echo -e "${RED}Error: Benchmark directory not found${NC}"
    echo "Run: ./scripts/benchmark_baseline.sh ${BASELINE_NAME}"
    exit 1
fi

# Find baseline data (use find -L to follow symlinks)
BASELINE_FOUND=false
if find -L target/criterion -maxdepth 3 -type d -name "${BASELINE_NAME}" 2>/dev/null | grep -q "${BASELINE_NAME}"; then
    BASELINE_FOUND=true
fi

if [[ "$BASELINE_FOUND" = false ]]; then
    echo -e "${RED}Error: Baseline '${BASELINE_NAME}' not found${NC}"
    echo
    echo "Available baselines in benchmarks/criterion_data:"
    find benchmarks/criterion_data -type d -name "*" -maxdepth 2 | 
        xargs -I{} basename {} 2>/dev/null | 
        grep -v "criterion_data" | 
        sort | uniq | head -20
    echo
    echo "To create a baseline, run:"
    echo "  ./scripts/benchmark_baseline.sh ${BASELINE_NAME}"
    exit 1
fi

echo -e "${YELLOW}Comparing against baseline: ${BASELINE_NAME}${NC}"
echo

# Clean build
echo -e "${GREEN}Step 1: Clean build${NC}"
cargo build --release
echo

# Run comparison
echo -e "${GREEN}Step 2: Running comparison benchmarks${NC}"
cargo bench --bench matchy_bench -- --baseline "${BASELINE_NAME}"
echo

# Create comparison report
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
COMPARISON_DIR="benchmarks/comparison_${TIMESTAMP}"
mkdir -p "${COMPARISON_DIR}"

# Save comparison metadata
cat > "${COMPARISON_DIR}/metadata.json" <<EOF
{
  "comparison_timestamp": "${TIMESTAMP}",
  "baseline_name": "${BASELINE_NAME}",
  "current_commit": "$(git rev-parse HEAD)",
  "current_commit_short": "$(git rev-parse --short HEAD)",
  "current_branch": "$(git branch --show-current)",
  "git_dirty": $(git diff --quiet && echo "false" || echo "true")
}
EOF

echo -e "${GREEN}=== Comparison Complete ===${NC}"
echo
echo "Baseline: ${BASELINE_NAME}"
echo "Current commit: $(git rev-parse --short HEAD)"
echo "Comparison saved to: ${COMPARISON_DIR}/"
echo
echo -e "${YELLOW}Next steps:${NC}"
echo "1. Review HTML report: open target/criterion/report/index.html"
echo "2. Check for regressions in load time (critical!)"
echo "3. Verify statistical significance (p < 0.05)"
echo "4. Document results in commit message"
echo

# Attempt to extract key metrics
echo -e "${BLUE}=== Quick Summary ===${NC}"
echo "Looking for significant changes..."
echo

# This is a simplified extraction - you might want to enhance it
if command -v jq &> /dev/null; then
    echo -e "${YELLOW}Note: Install 'jq' for better metric extraction${NC}"
fi

# Open HTML report
if [[ "$OSTYPE" == "darwin"* ]]; then
    read -p "Open HTML report now? (y/N) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        open target/criterion/report/index.html
    fi
fi
