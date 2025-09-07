const std = @import("std");
const print = std.debug.print;
const builtin = @import("builtin");

/// Conditional compilation for Zig version compatibility
const isZig015OrNewer = blk: {
    const version = builtin.zig_version;
    break :blk (version.major == 0 and version.minor >= 15);
};

// Performance record structure that matches the JSONL format
const PerformanceRecord = struct {
    timestamp: i64,
    commit: []const u8,
    branch: []const u8,
    build_mode: []const u8,
    platform: []const u8,
    results: []BenchmarkResult,

    const BenchmarkResult = struct {
        algorithm: []const u8,
        operation: []const u8,
        data_size_kb: f64,
        performance_value: f64,
        performance_unit: []const u8,
        timestamp: i64,
        build_mode: []const u8,
        platform: []const u8,
    };
};

const TrendAnalysis = struct {
    latest_performance: f64,
    previous_performance: f64,
    change_percent: f64,
    trend_direction: []const u8,
    data_points: usize,
};

const AnalysisReport = struct {
    performance_trends: std.StringHashMap(TrendAnalysis),
    total_data_points: usize,
    improvements: usize,
    regressions: usize,
    stable: usize,
    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .performance_trends = if (isZig015OrNewer)
                std.StringHashMap(TrendAnalysis).empty
            else
                std.StringHashMap(TrendAnalysis).init(allocator),
            .total_data_points = 0,
            .improvements = 0,
            .regressions = 0,
            .stable = 0,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        var iterator = self.performance_trends.iterator();
        while (iterator.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        if (isZig015OrNewer) {
            self.performance_trends.deinit(self.allocator);
        } else {
            self.performance_trends.deinit();
        }
    }
};

fn loadPerformanceHistory(allocator: std.mem.Allocator, data_dir: []const u8) !std.ArrayList(PerformanceRecord) {
    var history = if (isZig015OrNewer)
        std.ArrayList(PerformanceRecord).empty
    else
        std.ArrayList(PerformanceRecord).init(allocator);

    const history_path = try std.fmt.allocPrint(allocator, "{s}/performance-history.jsonl", .{data_dir});
    defer allocator.free(history_path);

    const file = std.fs.cwd().openFile(history_path, .{}) catch |err| switch (err) {
        error.FileNotFound => return history,
        else => return err,
    };
    defer file.close();

    const file_size = try file.getEndPos();
    const content = try allocator.alloc(u8, file_size);
    defer allocator.free(content);
    _ = try file.readAll(content);

    var lines = std.mem.splitScalar(u8, content, '\n');
    while (lines.next()) |line| {
        const trimmed_line = std.mem.trim(u8, line, " \t\r\n");
        if (trimmed_line.len == 0) continue;

        const parsed = std.json.parseFromSlice(PerformanceRecord, allocator, trimmed_line, .{}) catch continue;
        defer parsed.deinit();

        // Deep copy the record to avoid use-after-free
        const record = try copyPerformanceRecord(allocator, parsed.value);
        if (isZig015OrNewer) {
            try history.append(allocator, record);
        } else {
            try history.append(record);
        }
    }

    return history;
}

fn copyPerformanceRecord(allocator: std.mem.Allocator, record: PerformanceRecord) !PerformanceRecord {
    const commit = try allocator.dupe(u8, record.commit);
    const branch = try allocator.dupe(u8, record.branch);
    const build_mode = try allocator.dupe(u8, record.build_mode);
    const platform = try allocator.dupe(u8, record.platform);

    const results = try allocator.alloc(PerformanceRecord.BenchmarkResult, record.results.len);
    for (record.results, 0..) |result, i| {
        results[i] = PerformanceRecord.BenchmarkResult{
            .algorithm = try allocator.dupe(u8, result.algorithm),
            .operation = try allocator.dupe(u8, result.operation),
            .data_size_kb = result.data_size_kb,
            .performance_value = result.performance_value,
            .performance_unit = try allocator.dupe(u8, result.performance_unit),
            .timestamp = result.timestamp,
            .build_mode = try allocator.dupe(u8, result.build_mode),
            .platform = try allocator.dupe(u8, result.platform),
        };
    }

    return PerformanceRecord{
        .timestamp = record.timestamp,
        .commit = commit,
        .branch = branch,
        .build_mode = build_mode,
        .platform = platform,
        .results = results,
    };
}

fn freePerformanceRecord(allocator: std.mem.Allocator, record: PerformanceRecord) void {
    allocator.free(record.commit);
    allocator.free(record.branch);
    allocator.free(record.build_mode);
    allocator.free(record.platform);

    for (record.results) |result| {
        allocator.free(result.algorithm);
        allocator.free(result.operation);
        allocator.free(result.performance_unit);
        allocator.free(result.build_mode);
        allocator.free(result.platform);
    }
    allocator.free(record.results);
}

const PerformanceDataPoint = struct {
    timestamp: i64,
    performance_value: f64,
};

fn analyzePerformanceTrends(allocator: std.mem.Allocator, history: std.ArrayList(PerformanceRecord)) !AnalysisReport {
    if (history.items.len < 2) {
        return error.InsufficientData;
    }

    var report = AnalysisReport.init(allocator);
    var trends = if (isZig015OrNewer)
        std.StringHashMap(std.ArrayList(PerformanceDataPoint)).empty
    else
        std.StringHashMap(std.ArrayList(PerformanceDataPoint)).init(allocator);
    
    defer {
        var trend_iter = trends.iterator();
        while (trend_iter.next()) |entry| {
            allocator.free(entry.key_ptr.*);
            if (isZig015OrNewer) {
                entry.value_ptr.deinit(allocator);
            } else {
                entry.value_ptr.deinit();
            }
        }
        if (isZig015OrNewer) {
            trends.deinit(allocator);
        } else {
            trends.deinit();
        }
    }

    // Group performance data by algorithm_operation key
    for (history.items) |record| {
        for (record.results) |result| {
            const key = try std.fmt.allocPrint(allocator, "{s}_{s}", .{ result.algorithm, result.operation });

            const get_result = try trends.getOrPut(key);
            if (!get_result.found_existing) {
                get_result.value_ptr.* = if (isZig015OrNewer)
                    std.ArrayList(PerformanceDataPoint).empty
                else
                    std.ArrayList(PerformanceDataPoint).init(allocator);
            } else {
                allocator.free(key);
            }

            if (isZig015OrNewer) {
                try get_result.value_ptr.append(allocator, .{
                    .timestamp = result.timestamp,
                    .performance_value = result.performance_value,
                });
            } else {
                try get_result.value_ptr.append(.{
                    .timestamp = result.timestamp,
                    .performance_value = result.performance_value,
                });
            }
        }
    }

    // Calculate trend analysis for each algorithm_operation
    var trend_iter = trends.iterator();
    while (trend_iter.next()) |entry| {
        const key = entry.key_ptr.*;
        const data_points = entry.value_ptr.*;

        if (data_points.items.len >= 2) {
            // Sort by timestamp
            std.mem.sort(PerformanceDataPoint, data_points.items, {}, struct {
                fn lessThan(_: void, a: PerformanceDataPoint, b: PerformanceDataPoint) bool {
                    return a.timestamp < b.timestamp;
                }
            }.lessThan);

            const latest = data_points.items[data_points.items.len - 1];
            const previous = data_points.items[data_points.items.len - 2];

            const change_percent = if (previous.performance_value != 0)
                ((latest.performance_value - previous.performance_value) / previous.performance_value * 100)
            else
                0;

            const trend_direction = if (change_percent > 0.1) "improvement" else if (change_percent < -0.1) "regression" else "stable";

            const analysis = TrendAnalysis{
                .latest_performance = latest.performance_value,
                .previous_performance = previous.performance_value,
                .change_percent = change_percent,
                .trend_direction = trend_direction,
                .data_points = data_points.items.len,
            };

            const owned_key = try allocator.dupe(u8, key);
            try report.performance_trends.put(owned_key, analysis);

            // Update counters
            if (std.mem.eql(u8, trend_direction, "improvement")) {
                report.improvements += 1;
            } else if (std.mem.eql(u8, trend_direction, "regression")) {
                report.regressions += 1;
            } else {
                report.stable += 1;
            }
        }
    }

    report.total_data_points = history.items.len;
    return report;
}

fn generateTextReport(allocator: std.mem.Allocator, report: AnalysisReport) ![]u8 {
    var output = if (isZig015OrNewer)
        std.ArrayList(u8).empty
    else
        std.ArrayList(u8).init(allocator);
    
    if (isZig015OrNewer) {
        defer output.deinit(allocator);
    } else {
        defer output.deinit();
    }

    const writer = if (isZig015OrNewer)
        output.writer(allocator)
    else
        output.writer();

    try writer.print("=== GM-Zig Performance Analysis Report ===\n", .{});
    try writer.print("Generated: {}\n", .{std.time.timestamp()});
    try writer.print("Data points analyzed: {} runs\n\n", .{report.total_data_points});

    // Summary statistics
    try writer.print("=== Performance Trend Summary ===\n", .{});
    try writer.print("Improvements: {}\n", .{report.improvements});
    try writer.print("Regressions: {}\n", .{report.regressions});
    try writer.print("Stable: {}\n\n", .{report.stable});

    // Detailed analysis
    try writer.print("=== Detailed Performance Analysis ===\n", .{});

    var iterator = report.performance_trends.iterator();
    while (iterator.next()) |entry| {
        const key = entry.key_ptr.*;
        const data = entry.value_ptr.*;

        var key_parts = std.mem.splitScalar(u8, key, '_');
        const algorithm = key_parts.next() orelse "unknown";
        const operation = key_parts.rest();

        const trend_emoji = if (std.mem.eql(u8, data.trend_direction, "improvement")) "📈" else if (std.mem.eql(u8, data.trend_direction, "regression")) "📉" else "➡️";

        try writer.print("{s} {s} {s}\n", .{ trend_emoji, algorithm, operation });
        try writer.print("  Latest: {d:.2}\n", .{data.latest_performance});
        try writer.print("  Previous: {d:.2}\n", .{data.previous_performance});
        try writer.print("  Change: {d:.2}%\n\n", .{data.change_percent});
    }

    // Performance recommendations
    try writer.print("=== Performance Optimization Recommendations ===\n", .{});

    const has_regressions = report.regressions > 0;
    if (has_regressions) {
        try writer.print("⚠️  Performance regressions detected:\n", .{});

        var reg_iterator = report.performance_trends.iterator();
        while (reg_iterator.next()) |entry| {
            const data = entry.value_ptr.*;
            if (std.mem.eql(u8, data.trend_direction, "regression")) {
                const key = entry.key_ptr.*;
                var key_parts = std.mem.splitScalar(u8, key, '_');
                const algorithm = key_parts.next() orelse "unknown";
                const operation = key_parts.rest();

                try writer.print("  • {s} {s}: {d:.2}% slower\n", .{ algorithm, operation, data.change_percent });
            }
        }

        try writer.print("\nRecommended actions:\n", .{});
        try writer.print("  1. Review recent changes for performance impact\n", .{});
        try writer.print("  2. Run profiling tools to identify bottlenecks\n", .{});
        try writer.print("  3. Consider algorithmic optimizations\n\n", .{});
    }

    const has_improvements = report.improvements > 0;
    if (has_improvements) {
        try writer.print("✅ Performance improvements detected:\n", .{});

        var imp_iterator = report.performance_trends.iterator();
        while (imp_iterator.next()) |entry| {
            const data = entry.value_ptr.*;
            if (std.mem.eql(u8, data.trend_direction, "improvement")) {
                const key = entry.key_ptr.*;
                var key_parts = std.mem.splitScalar(u8, key, '_');
                const algorithm = key_parts.next() orelse "unknown";
                const operation = key_parts.rest();

                try writer.print("  • {s} {s}: {d:.2}% faster\n", .{ algorithm, operation, data.change_percent });
            }
        }
        try writer.print("\n", .{});
    }

    return try allocator.dupe(u8, output.items);
}

fn generateJsonReport(allocator: std.mem.Allocator, report: AnalysisReport) ![]u8 {
    // Convert HashMap to an array of key-value pairs for JSON serialization
    var trends_array = if (isZig015OrNewer)
        std.ArrayList(struct {
            algorithm_operation: []const u8,
            analysis: TrendAnalysis,
        }).empty
    else
        std.ArrayList(struct {
            algorithm_operation: []const u8,
            analysis: TrendAnalysis,
        }).init(allocator);
    
    if (isZig015OrNewer) {
        defer trends_array.deinit(allocator);
    } else {
        defer trends_array.deinit();
    }

    var iterator = report.performance_trends.iterator();
    while (iterator.next()) |entry| {
        if (isZig015OrNewer) {
            try trends_array.append(allocator, .{
                .algorithm_operation = entry.key_ptr.*,
                .analysis = entry.value_ptr.*,
            });
        } else {
            try trends_array.append(.{
                .algorithm_operation = entry.key_ptr.*,
                .analysis = entry.value_ptr.*,
            });
        }
    }

    const json_data = struct {
        trends: @TypeOf(trends_array.items),
        summary: struct {
            total_data_points: usize,
            improvements: usize,
            regressions: usize,
            stable: usize,
        },
    }{
        .trends = trends_array.items,
        .summary = .{
            .total_data_points = report.total_data_points,
            .improvements = report.improvements,
            .regressions = report.regressions,
            .stable = report.stable,
        },
    };

    // Manual JSON serialization for simplicity
    var output = if (isZig015OrNewer)
        std.ArrayList(u8).empty
    else
        std.ArrayList(u8).init(allocator);
    
    if (isZig015OrNewer) {
        defer output.deinit(allocator);
    } else {
        defer output.deinit();
    }

    const writer = if (isZig015OrNewer)
        output.writer(allocator)
    else
        output.writer();

    try writer.print("{{", .{});
    try writer.print("\"summary\":{{", .{});
    try writer.print("\"total_data_points\":{},", .{json_data.summary.total_data_points});
    try writer.print("\"improvements\":{},", .{json_data.summary.improvements});
    try writer.print("\"regressions\":{},", .{json_data.summary.regressions});
    try writer.print("\"stable\":{}", .{json_data.summary.stable});
    try writer.print("}},", .{});
    try writer.print("\"trends\":[", .{});

    for (json_data.trends, 0..) |trend, i| {
        if (i > 0) try writer.print(",", .{});
        try writer.print("{{", .{});
        try writer.print("\"algorithm_operation\":\"{s}\",", .{trend.algorithm_operation});
        try writer.print("\"analysis\":{{", .{});
        try writer.print("\"trend_direction\":\"{s}\",", .{trend.analysis.trend_direction});
        try writer.print("\"latest_performance\":{d},", .{trend.analysis.latest_performance});
        try writer.print("\"previous_performance\":{d},", .{trend.analysis.previous_performance});
        try writer.print("\"change_percent\":{d}", .{trend.analysis.change_percent});
        try writer.print("}}", .{});
        try writer.print("}}", .{});
    }

    try writer.print("]", .{});
    try writer.print("}}", .{});

    return if (isZig015OrNewer)
        try output.toOwnedSlice(allocator)
    else
        try output.toOwnedSlice();
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Parse command line arguments
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    var data_dir: []const u8 = ".performance-data";
    var output_format: []const u8 = "text";
    var output_file: ?[]const u8 = null;

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--data-dir") and i + 1 < args.len) {
            i += 1;
            data_dir = args[i];
        } else if (std.mem.eql(u8, args[i], "--format") and i + 1 < args.len) {
            i += 1;
            output_format = args[i];
        } else if (std.mem.eql(u8, args[i], "--output") and i + 1 < args.len) {
            i += 1;
            output_file = args[i];
        } else if (std.mem.eql(u8, args[i], "--help") or std.mem.eql(u8, args[i], "-h")) {
            print("Usage: analyze-performance [OPTIONS]\n", .{});
            print("\nOptions:\n", .{});
            print("  --data-dir DIR    Directory containing performance data (default: .performance-data)\n", .{});
            print("  --format FORMAT   Output format: text or json (default: text)\n", .{});
            print("  --output FILE     Output file (default: stdout)\n", .{});
            print("  --help, -h        Show this help message\n", .{});
            return;
        }
    }

    // Check if data directory exists
    std.fs.cwd().access(data_dir, .{}) catch |err| switch (err) {
        error.FileNotFound => {
            print("Error: Performance data directory '{s}' not found\n", .{data_dir});
            std.process.exit(1);
        },
        else => return err,
    };

    // Load performance history
    var history = loadPerformanceHistory(allocator, data_dir) catch |err| switch (err) {
        else => {
            print("Error loading performance history: {}\n", .{err});
            std.process.exit(1);
        },
    };
    defer {
        for (history.items) |record| {
            freePerformanceRecord(allocator, record);
        }
        if (isZig015OrNewer) {
            history.deinit(allocator);
        } else {
            history.deinit();
        }
    }

    if (history.items.len == 0) {
        print("No performance data available for analysis.\n", .{});
        return;
    }

    // Analyze performance trends
    var report = analyzePerformanceTrends(allocator, history) catch |err| switch (err) {
        error.InsufficientData => {
            print("Analysis error: Insufficient data for trend analysis\n", .{});
            return;
        },
        else => return err,
    };
    defer report.deinit();

    // Generate report
    const report_content = if (std.mem.eql(u8, output_format, "json"))
        try generateJsonReport(allocator, report)
    else
        try generateTextReport(allocator, report);
    defer allocator.free(report_content);

    // Output report
    if (output_file) |file_path| {
        const file = try std.fs.cwd().createFile(file_path, .{});
        defer file.close();
        try file.writeAll(report_content);
        print("Performance report written to {s}\n", .{file_path});
    } else {
        print("{s}", .{report_content});
    }
}
