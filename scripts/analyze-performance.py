#!/usr/bin/env python3
"""
Performance Analysis and Visualization Script
Analyzes performance data collected by CI and generates reports and visualizations.
"""

import json
import os
import sys
import argparse
from datetime import datetime
from typing import List, Dict, Any
import subprocess

def load_performance_history(data_dir: str) -> List[Dict[str, Any]]:
    """Load performance history from JSONL file."""
    history_file = os.path.join(data_dir, "performance-history.jsonl")
    
    if not os.path.exists(history_file):
        return []
    
    history = []
    with open(history_file, 'r') as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    history.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    
    return history

def analyze_performance_trends(history: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Analyze performance trends over time."""
    if len(history) < 2:
        return {"error": "Insufficient data for trend analysis"}
    
    # Group by algorithm and operation
    trends = {}
    
    for record in history:
        timestamp = record["timestamp"]
        commit = record["commit"]
        
        for result in record["results"]:
            key = f"{result['algorithm']}_{result['operation']}"
            if key not in trends:
                trends[key] = []
            
            trends[key].append({
                "timestamp": timestamp,
                "commit": commit,
                "data_size_kb": result["data_size_kb"],
                "throughput_mb_s": result["throughput_mb_s"],
                "build_mode": result["build_mode"],
                "platform": result["platform"]
            })
    
    # Calculate trend statistics
    analysis = {}
    for key, data in trends.items():
        # Sort by timestamp
        data.sort(key=lambda x: x["timestamp"])
        
        # Calculate performance changes
        if len(data) >= 2:
            latest = data[-1]
            previous = data[-2]
            
            change_percent = ((latest["throughput_mb_s"] - previous["throughput_mb_s"]) 
                             / previous["throughput_mb_s"] * 100)
            
            analysis[key] = {
                "latest_performance": latest["throughput_mb_s"],
                "previous_performance": previous["throughput_mb_s"],
                "change_percent": change_percent,
                "trend_direction": "improvement" if change_percent > 0 else "regression" if change_percent < 0 else "stable",
                "data_points": len(data)
            }
    
    return analysis

def generate_performance_report(data_dir: str, output_format: str = "text") -> str:
    """Generate performance analysis report."""
    history = load_performance_history(data_dir)
    
    if not history:
        return "No performance data available for analysis."
    
    analysis = analyze_performance_trends(history)
    
    if "error" in analysis:
        return f"Analysis error: {analysis['error']}"
    
    if output_format == "json":
        return json.dumps(analysis, indent=2)
    
    # Generate text report
    report = []
    report.append("=== GM-Zig Performance Analysis Report ===")
    report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}")
    report.append(f"Data points analyzed: {len(history)} runs")
    report.append("")
    
    # Summary statistics
    improvements = sum(1 for v in analysis.values() if v["trend_direction"] == "improvement")
    regressions = sum(1 for v in analysis.values() if v["trend_direction"] == "regression")
    stable = sum(1 for v in analysis.values() if v["trend_direction"] == "stable")
    
    report.append("=== Performance Trend Summary ===")
    report.append(f"Improvements: {improvements}")
    report.append(f"Regressions: {regressions}")
    report.append(f"Stable: {stable}")
    report.append("")
    
    # Detailed analysis by algorithm
    report.append("=== Detailed Performance Analysis ===")
    
    for key, data in sorted(analysis.items()):
        algorithm, operation = key.split('_', 1)
        
        trend_emoji = {
            "improvement": "📈",
            "regression": "📉", 
            "stable": "➡️"
        }[data["trend_direction"]]
        
        report.append(f"{trend_emoji} {algorithm} {operation}")
        report.append(f"  Latest: {data['latest_performance']:.2f} MB/s")
        report.append(f"  Previous: {data['previous_performance']:.2f} MB/s")
        report.append(f"  Change: {data['change_percent']:.2f}%")
        report.append("")
    
    # Performance recommendations
    report.append("=== Performance Optimization Recommendations ===")
    
    regressions_list = [(k, v) for k, v in analysis.items() if v["trend_direction"] == "regression"]
    if regressions_list:
        report.append("⚠️  Performance regressions detected:")
        for key, data in sorted(regressions_list, key=lambda x: x[1]["change_percent"]):
            algorithm, operation = key.split('_', 1)
            report.append(f"  • {algorithm} {operation}: {data['change_percent']:.2f}% slower")
        report.append("")
        report.append("Recommended actions:")
        report.append("  1. Review recent changes for performance impact")
        report.append("  2. Run profiling tools to identify bottlenecks")
        report.append("  3. Consider algorithmic optimizations")
        report.append("")
    
    improvements_list = [(k, v) for k, v in analysis.items() if v["trend_direction"] == "improvement"]
    if improvements_list:
        report.append("✅ Performance improvements detected:")
        for key, data in sorted(improvements_list, key=lambda x: x[1]["change_percent"], reverse=True):
            algorithm, operation = key.split('_', 1)
            report.append(f"  • {algorithm} {operation}: {data['change_percent']:.2f}% faster")
        report.append("")
    
    return "\n".join(report)

def main():
    parser = argparse.ArgumentParser(description="Analyze GM-Zig performance data")
    parser.add_argument("--data-dir", default=".performance-data", 
                       help="Directory containing performance data")
    parser.add_argument("--format", choices=["text", "json"], default="text",
                       help="Output format")
    parser.add_argument("--output", help="Output file (default: stdout)")
    
    args = parser.parse_args()
    
    if not os.path.exists(args.data_dir):
        print(f"Error: Performance data directory '{args.data_dir}' not found")
        sys.exit(1)
    
    report = generate_performance_report(args.data_dir, args.format)
    
    if args.output:
        with open(args.output, 'w') as f:
            f.write(report)
        print(f"Performance report written to {args.output}")
    else:
        print(report)

if __name__ == "__main__":
    main()