#!/bin/bash
set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== Matchy Baseline Benchmark Capture ===${NC}"
echo

# Check if we're in the right directory
if [[ ! -f "Cargo.toml" ]] || [[ ! -d "benches" ]]; then
    echo -e "${RED}Error: Must be run from matchy project root${NC}"
    exit 1
fi

# Parse arguments
BASELINE_NAME="${1:-pre-optimization}"
echo -e "${YELLOW}Baseline name: ${BASELINE_NAME}${NC}"
echo

# Check for uncommitted changes
if [[ -n $(git status -s) ]]; then
    echo -e "${YELLOW}Warning: You have uncommitted changes.${NC}"
    echo "It's recommended to commit or stash changes before capturing baseline."
    read -p "Continue anyway? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# System preparation reminder
echo -e "${YELLOW}System Preparation Checklist:${NC}"
echo "  [ ] Close unnecessary applications"
echo "  [ ] Plug in power (no battery throttling)"
echo "  [ ] Disable Wi-Fi/Bluetooth if possible"
echo "  [ ] Close Docker, VMs, IDEs"
echo
read -p "Ready to proceed? (y/N) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    exit 1
fi

# Clean build
echo -e "${GREEN}Step 1: Clean build${NC}"
cargo clean
cargo build --release
echo

# Setup symlink for persistent criterion data if not already set up
if [[ ! -L "target/criterion" ]]; then
    echo -e "${YELLOW}Setting up persistent benchmark storage...${NC}"
    mkdir -p benchmarks/criterion_data
    mkdir -p target
    if [[ -d "target/criterion" ]]; then
        # Migrate existing data
        cp -r target/criterion/* benchmarks/criterion_data/ 2>/dev/null || true
        rm -rf target/criterion
    fi
    ln -s ../benchmarks/criterion_data target/criterion
    echo -e "${GREEN}Benchmark data will persist across cargo clean${NC}"
    echo
fi

# Run benchmarks
echo -e "${GREEN}Step 2: Running benchmarks (this will take ~5-10 minutes)${NC}"
cargo bench --bench matchy_bench -- --save-baseline "${BASELINE_NAME}"
echo

# Create timestamped backup for safety
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="benchmarks/baseline_${BASELINE_NAME}_${TIMESTAMP}"

echo -e "${GREEN}Step 3: Creating timestamped backup${NC}"
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
cat "${BACKUP_DIR}/metadata.json"
echo

# Git tag recommendation
GIT_COMMIT=$(git rev-parse --short HEAD)
TAG_NAME="baseline-${BASELINE_NAME}-${GIT_COMMIT}"

echo -e "${GREEN}Step 4: Git tagging (optional)${NC}"
echo "Recommended tag: ${TAG_NAME}"
read -p "Create git tag? (y/N) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    git tag -a "${TAG_NAME}" -m "Performance baseline: ${BASELINE_NAME}"
    echo -e "${GREEN}Tag created: ${TAG_NAME}${NC}"
    echo "Push with: git push origin ${TAG_NAME}"
fi
echo

# Summary
echo -e "${GREEN}=== Baseline Capture Complete ===${NC}"
echo
echo "Baseline name: ${BASELINE_NAME}"
echo "Backup location: ${BACKUP_DIR}/"
echo "Git commit: $(git rev-parse --short HEAD)"
echo
echo -e "${YELLOW}Next steps:${NC}"
echo "1. Review HTML report: open target/criterion/report/index.html"
echo "2. Implement optimizations"
echo "3. Compare with: cargo bench -- --baseline ${BASELINE_NAME}"
echo

# Open HTML report
if [[ "$OSTYPE" == "darwin"* ]]; then
    read -p "Open HTML report now? (y/N) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        open target/criterion/report/index.html
    fi
fi
