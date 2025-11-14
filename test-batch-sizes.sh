#!/bin/bash
# Test different batch sizes to find optimal balance

DB="$1"
shift
FILES="$@"

if [ -z "$DB" ] || [ -z "$FILES" ]; then
    echo "Usage: $0 <database.mxy> <file1> [file2...]"
    exit 1
fi

echo "Testing batch sizes to optimize system time..."
echo ""

for BATCH_KB in 128 256 512 1024 2048; do
    BATCH_BYTES=$((BATCH_KB * 1024))
    echo "========================================"
    echo "Batch size: ${BATCH_KB}KB"
    echo "========================================"
    
    /usr/bin/time -v ./target/release/matchy match --stats \
        --batch-bytes=$BATCH_BYTES \
        "$DB" $FILES 2>&1 | grep -E "(User time|System time|Percent of CPU|Throughput)"
    
    echo ""
done

echo ""
echo "Recommendation: Choose batch size with lowest 'System time' and highest throughput"
echo "Lower system time = less time in kernel (futex, allocations)"
