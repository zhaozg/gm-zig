# GM-Zig Performance Monitoring System

This document describes the CI-based performance monitoring system implemented to support data-driven performance optimization.

## Overview

The performance monitoring system provides:
- **Automated Performance Benchmarks**: Run in CI on every commit
- **Structured Data Collection**: JSON format for analysis and visualization  
- **Performance Trend Analysis**: Track changes over time
- **Regression Detection**: Alert on performance degradations
- **Optimization Guidance**: Data-driven recommendations

## Components

### 1. Benchmark Framework (`src/benchmark.zig`)

Core benchmarking infrastructure that:
- Measures SM3 hash performance across multiple data sizes (64KB, 1MB, 10MB)
- Measures SM4 encrypt/decrypt performance across multiple data sizes (16KB, 1MB, 10MB)
- Outputs structured JSON data with metadata (timestamp, commit, platform, build mode)
- Provides human-readable summary format

**Usage:**
```bash
# Human-readable output
zig build benchmark

# JSON output for CI/automation
./zig-out/bin/benchmark --json
```

**Example JSON Output:**
```json
[
  {
    "algorithm": "SM3",
    "operation": "hash", 
    "data_size_kb": 64.0,
    "throughput_mb_s": 19.16,
    "timestamp": 1757226360,
    "build_mode": "Debug",
    "platform": "x86_64-linux"
  }
]
```

### 2. CI Data Collection (`scripts/collect-performance-data.sh`)

Automated script that:
- Builds and runs benchmarks in CI environment
- Captures performance data with CI metadata
- Stores data in structured format for analysis
- Compares performance vs previous runs
- Provides immediate feedback in CI logs

**CI Integration Features:**
- Automatic commit and branch detection
- GitHub Actions metadata integration
- Performance comparison with previous runs
- Error handling and validation

**Data Storage Structure:**
```
.performance-data/
├── perf-{timestamp}-{commit}.json    # Individual run data
├── latest-summary.json               # Latest run summary
└── performance-history.jsonl        # Complete history
```

### 3. Performance Analysis (`scripts/analyze-performance.py`)

Python script for advanced analysis:
- Trend analysis across multiple runs
- Performance regression detection
- Optimization recommendations
- Flexible output formats (text/JSON)

**Usage:**
```bash
# Generate text report
python3 scripts/analyze-performance.py

# Generate JSON analysis  
python3 scripts/analyze-performance.py --format json

# Save to file
python3 scripts/analyze-performance.py --output performance-report.txt
```

## CI Integration

### GitHub Actions Workflow

The CI workflow (`.github/workflows/ci.yml`) now includes:

1. **Performance Benchmarks**: Run after tests pass
2. **Data Collection**: Structured performance data capture
3. **Artifact Upload**: Store performance data for 90 days
4. **Immediate Feedback**: Performance comparison in CI logs

### Performance Data Artifacts

Each CI run uploads performance data as artifacts:
- **Name Pattern**: `performance-data-{zig-version}-{commit-sha}`
- **Retention**: 90 days
- **Contents**: Complete performance data and metadata

## Performance Baselines

### Current Performance (Debug Mode)

| Algorithm | Operation | Data Size | Throughput |
|-----------|-----------|-----------|------------|
| SM3       | hash      | 64 KB     | ~19 MB/s   |
| SM3       | hash      | 1 MB      | ~19 MB/s   |
| SM3       | hash      | 10 MB     | ~19 MB/s   |
| SM4       | encrypt   | 16 KB     | ~12 MB/s   |
| SM4       | encrypt   | 1 MB      | ~12 MB/s   |
| SM4       | encrypt   | 10 MB     | ~12 MB/s   |
| SM4       | decrypt   | 16 KB     | ~11 MB/s   |
| SM4       | decrypt   | 1 MB      | ~11 MB/s   |
| SM4       | decrypt   | 10 MB     | ~11 MB/s   |

**Note**: Performance in ReleaseFast mode is significantly higher (~10x improvement).

## Usage for Performance Optimization

### 1. Local Development

Before making performance-related changes:

```bash
# Establish baseline
./scripts/collect-performance-data.sh

# Make your changes
# ... 

# Measure impact
./scripts/collect-performance-data.sh

# Analyze trends
python3 scripts/analyze-performance.py
```

### 2. CI-Based Monitoring

- Every commit automatically runs performance benchmarks
- Performance data is collected and stored as CI artifacts
- Immediate comparison with previous commit is shown in CI logs
- Download artifacts for detailed analysis

### 3. Performance Analysis Workflow

```bash
# Download CI artifacts containing performance data
# Extract to .performance-data/ directory

# Generate comprehensive analysis report
python3 scripts/analyze-performance.py --output perf-analysis.txt

# Get JSON data for custom analysis tools
python3 scripts/analyze-performance.py --format json > perf-data.json
```

## Performance Optimization Guidance

### Interpreting Results

- **Improvements (📈)**: Performance increase compared to previous run
- **Regressions (📉)**: Performance decrease - investigate recent changes
- **Stable (➡️)**: Minimal change (< 1% variation)

### Optimization Priorities

Based on the analysis output:

1. **Address Regressions**: Focus on code changes that caused performance drops
2. **Optimize Bottlenecks**: Target algorithms with lowest throughput
3. **Validate Improvements**: Ensure optimizations show measurable gains

### Performance Testing Best Practices

1. **Consistent Environment**: Use ReleaseFast builds for optimization work
2. **Multiple Runs**: Account for measurement variance
3. **Data-Driven Decisions**: Use collected data to guide optimization efforts
4. **Regression Prevention**: Monitor CI for performance impacts

## Technical Implementation

### Benchmark Accuracy

- **Warm-up Runs**: Reduce measurement noise
- **Aligned Memory**: Optimal performance measurement
- **Deterministic Data**: Consistent input across runs
- **Multiple Sizes**: Identify scaling characteristics

### Data Collection Robustness

- **Error Handling**: Validates JSON output and build success
- **Metadata Capture**: Complete context for analysis
- **Storage Format**: JSONL for efficient historical analysis
- **CI Integration**: Seamless workflow integration

### Analysis Capabilities

- **Trend Detection**: Identify performance patterns over time
- **Regression Alerts**: Automatic detection of performance issues
- **Recommendation Engine**: Actionable guidance for optimization
- **Flexible Output**: Support for various analysis workflows

## Future Enhancements

### Planned Features

1. **Regression Thresholds**: Configurable performance degradation alerts
2. **Visualization Dashboard**: Web-based performance trend visualization  
3. **Benchmark Expansion**: Additional algorithms and test scenarios
4. **Platform Comparison**: Multi-platform performance analysis
5. **Integration Testing**: End-to-end performance validation

### Optimization Opportunities

Based on current analysis framework:

1. **Memory Allocation**: Arena allocators for reduced overhead
2. **SIMD Instructions**: Hardware acceleration for cryptographic operations
3. **Algorithm Improvements**: Montgomery multiplication, windowed scalar operations
4. **Compiler Optimizations**: Profile-guided optimization techniques

## Contributing

When contributing performance-related changes:

1. **Baseline Measurement**: Run benchmarks before changes
2. **Impact Assessment**: Measure performance delta
3. **Documentation**: Update baselines and analysis in PR description
4. **CI Validation**: Ensure CI performance tests pass

## Troubleshooting

### Common Issues

1. **Build Failures**: Ensure Zig 0.14.1+ is installed
2. **Missing jq**: Install `jq` for JSON processing
3. **Permission Issues**: Ensure scripts are executable
4. **Data Directory**: Check `.performance-data/` exists and is writable

### Debug Commands

```bash
# Test benchmark tool directly
./zig-out/bin/benchmark --json

# Validate JSON output
./zig-out/bin/benchmark --json | jq .

# Check data collection
ls -la .performance-data/

# Manual analysis
python3 scripts/analyze-performance.py --data-dir .performance-data
```