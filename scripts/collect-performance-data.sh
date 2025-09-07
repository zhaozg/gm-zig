#!/bin/bash
# CI Performance Data Collection Script
# This script runs benchmarks and stores performance data for tracking changes

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PERF_DATA_DIR="$PROJECT_ROOT/.performance-data"
CURRENT_COMMIT=$(git rev-parse HEAD 2>/dev/null || echo "unknown")
CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")
TIMESTAMP=$(date +%s)
DATE_READABLE=$(date -d "@$TIMESTAMP" '+%Y-%m-%d %H:%M:%S UTC')

# Create performance data directory if it doesn't exist
mkdir -p "$PERF_DATA_DIR"

# File naming
JSON_FILE="$PERF_DATA_DIR/perf-$TIMESTAMP-$CURRENT_COMMIT.json"
SUMMARY_FILE="$PERF_DATA_DIR/latest-summary.json"
HISTORY_FILE="$PERF_DATA_DIR/performance-history.jsonl"

echo "=== CI Performance Data Collection ==="
echo "Commit: $CURRENT_COMMIT"
echo "Branch: $CURRENT_BRANCH"
echo "Date: $DATE_READABLE"
echo "Data dir: $PERF_DATA_DIR"
echo ""

# Build the benchmark tool
echo "Building benchmark tool..."
cd "$PROJECT_ROOT"
zig build benchmark > /dev/null 2>&1

# Run benchmarks and capture JSON output
echo "Running performance benchmarks..."
BENCHMARK_JSON=$(./zig-out/bin/benchmark --json 2>&1)

# Validate the JSON was captured correctly
if [[ -z "$BENCHMARK_JSON" ]]; then
    echo "Error: Failed to capture JSON from benchmark tool"
    exit 1
fi

# Test if it's valid JSON
if ! echo "$BENCHMARK_JSON" | jq empty > /dev/null 2>&1; then
    echo "Error: Invalid JSON captured from benchmark tool"
    echo "Output was: $BENCHMARK_JSON"
    exit 1
fi

# Create enhanced performance data with CI metadata
cat > "$JSON_FILE" << EOF
{
  "metadata": {
    "commit": "$CURRENT_COMMIT",
    "branch": "$CURRENT_BRANCH",
    "timestamp": $TIMESTAMP,
    "date": "$DATE_READABLE",
    "ci_run": "${CI:-false}",
    "github_run_id": "${GITHUB_RUN_ID:-}",
    "github_workflow": "${GITHUB_WORKFLOW:-}"
  },
  "results": $BENCHMARK_JSON
}
EOF

# Update latest summary
cp "$JSON_FILE" "$SUMMARY_FILE"

# Append to history file (JSONL format)
echo "{\"timestamp\":$TIMESTAMP,\"commit\":\"$CURRENT_COMMIT\",\"branch\":\"$CURRENT_BRANCH\",\"results\":$BENCHMARK_JSON}" >> "$HISTORY_FILE"

echo "Performance data saved to: $JSON_FILE"

# Extract key performance metrics for CI display
echo ""
echo "=== Performance Summary ==="
echo "$BENCHMARK_JSON" | jq -r '.[] | "\(.algorithm) \(.operation): \(.data_size_kb) KB -> \(.performance_value | tonumber | . * 100 | round / 100) \(.performance_unit)"'

# If we have historical data, show comparison
if [[ -f "$HISTORY_FILE" ]] && [[ $(wc -l < "$HISTORY_FILE") -gt 1 ]]; then
    echo ""
    echo "=== Performance Comparison (vs previous run) ==="
    
    # Get previous run data
    PREV_LINE=$(tail -n 2 "$HISTORY_FILE" | head -n 1)
    if [[ -n "$PREV_LINE" ]]; then
        PREV_RESULTS=$(echo "$PREV_LINE" | jq -r '.results')
        
        # Compare key metrics
        echo "$BENCHMARK_JSON" | jq -r --argjson prev "$PREV_RESULTS" '
        . as $current | $prev as $previous |
        $current[] | . as $curr |
        ($previous[] | select(.algorithm == $curr.algorithm and .operation == $curr.operation)) as $prev |
        if $prev then
            (($curr.performance_value - $prev.performance_value) / $prev.performance_value * 100) as $change |
            "\($curr.algorithm) \($curr.operation) (\($curr.data_size_kb) KB): \($change | . * 100 | round / 100)% change"
        else
            "\($curr.algorithm) \($curr.operation) (\($curr.data_size_kb) KB): NEW"
        end'
    fi
fi

# Set output for GitHub Actions
if [[ "${GITHUB_ACTIONS:-}" == "true" ]]; then
    echo "perf_data_file=$JSON_FILE" >> "$GITHUB_OUTPUT"
    echo "perf_summary_file=$SUMMARY_FILE" >> "$GITHUB_OUTPUT"
fi

echo ""
echo "Performance data collection completed successfully!"
echo ""
echo "To analyze performance trends, run:"
echo "  zig build analyze                    # Generate text report"
echo "  zig build analyze -- --format json  # Generate JSON report"
echo "  ./zig-out/bin/analyze-performance --help  # See all options"