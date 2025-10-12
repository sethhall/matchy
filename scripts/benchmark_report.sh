#!/bin/bash
set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== Matchy Benchmark Report ===${NC}"
echo

# Check if we're in the right directory
if [[ ! -f "Cargo.toml" ]] || [[ ! -d "benches" ]]; then
    echo -e "${RED}Error: Must be run from matchy project root${NC}"
    exit 1
fi

# List available baselines
echo -e "${BLUE}=== Available Baselines ===${NC}"
if [[ -d "benchmarks" ]]; then
    for dir in benchmarks/baseline_*; do
        if [[ -d "$dir" ]]; then
            BASELINE_DIR=$(basename "$dir")
            if [[ -f "$dir/metadata.json" ]]; then
                echo
                echo -e "${YELLOW}${BASELINE_DIR}${NC}"
                if command -v jq &> /dev/null; then
                    jq -r '. | "  Timestamp: \(.timestamp)\n  Commit: \(.git_commit_short)\n  Branch: \(.git_branch)"' "$dir/metadata.json"
                else
                    grep -E '"timestamp"|"git_commit_short"|"git_branch"' "$dir/metadata.json" | sed 's/^/  /'
                fi
            else
                echo -e "${YELLOW}${BASELINE_DIR}${NC} (no metadata)"
            fi
        fi
    done
else
    echo "No baselines found. Run: ./scripts/benchmark_baseline.sh"
fi
echo

# List recent comparisons
echo -e "${BLUE}=== Recent Comparisons ===${NC}"
if [[ -d "benchmarks" ]]; then
    COMPARISON_COUNT=0
    for dir in benchmarks/comparison_*; do
        if [[ -d "$dir" ]]; then
            COMPARISON_DIR=$(basename "$dir")
            if [[ -f "$dir/metadata.json" ]]; then
                echo
                echo -e "${YELLOW}${COMPARISON_DIR}${NC}"
                if command -v jq &> /dev/null; then
                    jq -r '. | "  Timestamp: \(.comparison_timestamp)\n  Baseline: \(.baseline_name)\n  Commit: \(.current_commit_short)\n  Branch: \(.current_branch)"' "$dir/metadata.json"
                else
                    grep -E '"comparison_timestamp"|"baseline_name"|"current_commit_short"|"current_branch"' "$dir/metadata.json" | sed 's/^/  /'
                fi
            fi
            COMPARISON_COUNT=$((COMPARISON_COUNT + 1))
            if [[ $COMPARISON_COUNT -ge 5 ]]; then
                echo "  ... (showing last 5)"
                break
            fi
        fi
    done
    
    if [[ $COMPARISON_COUNT -eq 0 ]]; then
        echo "No comparisons found. Run: ./scripts/benchmark_compare.sh <baseline-name>"
    fi
else
    echo "No comparisons found."
fi
echo

# System info
echo -e "${BLUE}=== Current System Info ===${NC}"
echo "CPU: $(sysctl -n machdep.cpu.brand_string 2>/dev/null || echo 'N/A')"
echo "CPU Count: $(sysctl -n hw.ncpu 2>/dev/null || nproc 2>/dev/null || echo 'N/A')"
echo "Memory: $(( $(sysctl -n hw.memsize 2>/dev/null || echo 0) / 1024 / 1024 / 1024 )) GB"
echo "Rustc: $(rustc --version)"
echo "Cargo: $(cargo --version)"
echo

# Git status
echo -e "${BLUE}=== Current Git Status ===${NC}"
echo "Branch: $(git branch --show-current)"
echo "Commit: $(git rev-parse --short HEAD)"
if [[ -n $(git status -s) ]]; then
    echo -e "${YELLOW}Status: Uncommitted changes present${NC}"
else
    echo -e "${GREEN}Status: Clean working directory${NC}"
fi
echo

# Quick actions
echo -e "${BLUE}=== Quick Actions ===${NC}"
echo "1. View latest results: open target/criterion/report/index.html"
echo "2. Capture new baseline: ./scripts/benchmark_baseline.sh <name>"
echo "3. Run comparison: ./scripts/benchmark_compare.sh <baseline-name>"
echo "4. Run quick test: cargo bench --bench matchy_bench match/p100_t1000"
echo

# Check for jq installation
if ! command -v jq &> /dev/null; then
    echo -e "${YELLOW}Tip: Install 'jq' for better JSON parsing${NC}"
    echo "  brew install jq"
    echo
fi
