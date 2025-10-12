#!/bin/bash
set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== Save Current Run as Baseline ===${NC}"
echo

# Check if we're in the right directory
if [[ ! -f "Cargo.toml" ]] || [[ ! -d "benches" ]]; then
    echo -e "${RED}Error: Must be run from matchy project root${NC}"
    exit 1
fi

# Parse arguments
BASELINE_NAME="${1:-}"

if [[ -z "$BASELINE_NAME" ]]; then
    echo -e "${RED}Error: Baseline name required${NC}"
    echo
    echo "Usage: $0 <baseline-name>"
    echo
    echo "Examples:"
    echo "  $0 post-state-encoding"
    echo "  $0 after-loop-unroll"
    echo "  $0 v2-baseline"
    exit 1
fi

# Check if criterion_data exists
if [[ ! -d "benchmarks/criterion_data" ]]; then
    echo -e "${RED}Error: No benchmark data found${NC}"
    echo "Run benchmarks first with: cargo bench"
    exit 1
fi

echo -e "${YELLOW}This will save the current 'new' benchmark data as baseline: ${BASELINE_NAME}${NC}"
echo

# Check if baseline already exists
BASELINE_EXISTS=false
if find benchmarks/criterion_data -type d -name "${BASELINE_NAME}" 2>/dev/null | grep -q .; then
    echo -e "${YELLOW}Warning: Baseline '${BASELINE_NAME}' already exists!${NC}"
    read -p "Overwrite? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
    BASELINE_EXISTS=true
fi

echo -e "${GREEN}Copying 'new' data to '${BASELINE_NAME}' in all benchmarks...${NC}"

# Find all 'new' directories and copy them to the baseline name
COPIED=0
FAILED=0

while IFS= read -r -d '' new_dir; do
    # Get parent directory
    parent_dir=$(dirname "$new_dir")
    baseline_dir="${parent_dir}/${BASELINE_NAME}"
    
    # Remove old baseline if it exists
    if [[ -d "$baseline_dir" ]]; then
        rm -rf "$baseline_dir"
    fi
    
    # Copy new to baseline
    if cp -r "$new_dir" "$baseline_dir" 2>/dev/null; then
        ((COPIED++))
    else
        echo -e "${RED}Failed to copy: $new_dir${NC}"
        ((FAILED++))
    fi
done < <(find benchmarks/criterion_data -type d -name "new" -print0)

echo
echo -e "${GREEN}Copied ${COPIED} benchmark(s)${NC}"
if [[ $FAILED -gt 0 ]]; then
    echo -e "${RED}Failed: ${FAILED}${NC}"
fi

# Create timestamped backup
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="benchmarks/baseline_${BASELINE_NAME}_${TIMESTAMP}"

echo
echo -e "${GREEN}Creating timestamped backup...${NC}"
mkdir -p "${BACKUP_DIR}"
cp -r benchmarks/criterion_data/* "${BACKUP_DIR}/"

# Save metadata
cat > "${BACKUP_DIR}/metadata.json" <<EOF
{
  "baseline_name": "${BASELINE_NAME}",
  "timestamp": "${TIMESTAMP}",
  "git_commit": "$(git rev-parse HEAD)",
  "git_commit_short": "$(git rev-parse --short HEAD)",
  "git_branch": "$(git branch --show-current)",
  "git_dirty": $(git diff --quiet && echo "false" || echo "true"),
  "rustc_version": "$(rustc --version)",
  "cargo_version": "$(cargo --version)",
  "system": "$(uname -a)",
  "cpu_info": "$(sysctl -n machdep.cpu.brand_string 2>/dev/null || echo 'N/A')",
  "cpu_count": "$(sysctl -n hw.ncpu 2>/dev/null || nproc 2>/dev/null || echo 'N/A')",
  "memory_gb": "$(( $(sysctl -n hw.memsize 2>/dev/null || echo 0) / 1024 / 1024 / 1024 ))"
}
EOF

echo -e "Metadata saved to: ${BACKUP_DIR}/metadata.json"
echo

# Summary
echo -e "${GREEN}=== Baseline Saved ===${NC}"
echo
echo "Baseline name: ${BASELINE_NAME}"
echo "Backup location: ${BACKUP_DIR}/"
echo "Git commit: $(git rev-parse --short HEAD)"
echo
echo -e "${YELLOW}Available baselines:${NC}"
find benchmarks/criterion_data -type d -maxdepth 3 -mindepth 3 | 
    xargs -I{} basename {} 2>/dev/null | 
    grep -v "^new$" | grep -v "^report$" | grep -v "^change$" | 
    sort | uniq
echo
echo -e "${YELLOW}Next steps:${NC}"
echo "1. Compare against this baseline: ./scripts/benchmark_compare.sh ${BASELINE_NAME}"
echo "2. Or run: cargo bench -- --baseline ${BASELINE_NAME}"
echo
