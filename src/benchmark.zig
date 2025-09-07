const std = @import("std");
const root = @import("./root.zig");
const sm3 = root.sm3;
const sm4 = root.sm4;

// Benchmark result structure for structured output
pub const BenchmarkResult = struct {
    algorithm: []const u8,
    operation: []const u8,
    data_size_kb: f64,
    throughput_mb_s: f64,
    timestamp: i64,
    build_mode: []const u8,
    platform: []const u8,

    pub fn toJson(self: BenchmarkResult, allocator: std.mem.Allocator) ![]u8 {
        return try std.json.stringifyAlloc(allocator, self, .{});
    }
};

pub const BenchmarkSuite = struct {
    results: std.ArrayList(BenchmarkResult),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) BenchmarkSuite {
        return BenchmarkSuite{
            .results = std.ArrayList(BenchmarkResult).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *BenchmarkSuite) void {
        self.results.deinit();
    }

    pub fn addResult(self: *BenchmarkSuite, result: BenchmarkResult) !void {
        try self.results.append(result);
    }

    pub fn toJsonArray(self: *BenchmarkSuite) ![]u8 {
        return try std.json.stringifyAlloc(self.allocator, self.results.items, .{});
    }

    // Print human-readable summary
    pub fn printSummary(self: *BenchmarkSuite) void {
        std.debug.print("\n=== Performance Benchmark Summary ===\n", .{});
        for (self.results.items) |result| {
            std.debug.print("{s} {s}: {d:.2} KB -> {d:.2} MB/s\n", .{
                result.algorithm,
                result.operation,
                result.data_size_kb,
                result.throughput_mb_s,
            });
        }
    }
};

// Get current build mode as string
fn getBuildMode() []const u8 {
    return switch (@import("builtin").mode) {
        .Debug => "Debug",
        .ReleaseSafe => "ReleaseSafe",
        .ReleaseFast => "ReleaseFast",
        .ReleaseSmall => "ReleaseSmall",
    };
}

// Get platform information
fn getPlatform() []const u8 {
    const target = @import("builtin").target;
    return std.fmt.comptimePrint("{s}-{s}", .{ @tagName(target.cpu.arch), @tagName(target.os.tag) });
}

// Benchmark SM3 hash performance
pub fn benchmarkSM3(allocator: std.mem.Allocator, suite: *BenchmarkSuite) !void {
    const test_sizes = [_]usize{
        64 * 1024, // 64KB
        1024 * 1024, // 1MB
        10 * 1024 * 1024, // 10MB
    };

    const timestamp = std.time.timestamp();

    for (test_sizes) |size| {
        // Allocate aligned memory
        const alignment = 16;
        const buffer = try allocator.alignedAlloc(u8, alignment, size);
        defer allocator.free(buffer);

        // Fill with random data
        var prng = std.Random.DefaultPrng.init(0);
        prng.random().bytes(buffer);

        var out: [32]u8 = undefined;

        // Warm up
        sm3.SM3.hash(buffer[0..1024], &out, .{});

        // Benchmark
        const start_time = std.time.nanoTimestamp();
        sm3.SM3.hash(buffer, &out, .{});
        const end_time = std.time.nanoTimestamp();

        const duration_ns = @as(f64, @floatFromInt(end_time - start_time));
        const bytes_per_mb = 1024.0 * 1024.0;
        const ns_per_s = 1_000_000_000.0;
        const throughput = (@as(f64, @floatFromInt(size)) / duration_ns) * ns_per_s / bytes_per_mb;

        const result = BenchmarkResult{
            .algorithm = "SM3",
            .operation = "hash",
            .data_size_kb = @as(f64, @floatFromInt(size)) / 1024.0,
            .throughput_mb_s = throughput,
            .timestamp = timestamp,
            .build_mode = getBuildMode(),
            .platform = getPlatform(),
        };

        try suite.addResult(result);
    }
}

// Benchmark SM4 encryption performance
pub fn benchmarkSM4(allocator: std.mem.Allocator, suite: *BenchmarkSuite) !void {
    const key = [16]u8{
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
    };
    const ctx = sm4.SM4.init(&key);

    const test_sizes = [_]usize{
        1024 * 16, // 16KB
        1024 * 1024, // 1MB
        10 * 1024 * 1024, // 10MB
    };

    const timestamp = std.time.timestamp();

    for (test_sizes) |size| {
        const alignment = 16;
        const buffer = try allocator.alignedAlloc(u8, alignment, size);
        defer allocator.free(buffer);

        // Fill with random data
        var prng = std.Random.DefaultPrng.init(0);
        prng.random().bytes(buffer);

        const out = try allocator.alignedAlloc(u8, alignment, size);
        defer allocator.free(out);

        // Warm up
        ctx.encryptBlock(buffer[0..16], out[0..16]);

        // Benchmark encryption
        const encrypt_start = std.time.nanoTimestamp();
        const blocks = size / 16; // SM4 block size
        for (0..blocks) |i| {
            const start = i * 16;
            ctx.encryptBlock(
                buffer[start..][0..16],
                out[start..][0..16],
            );
        }
        const encrypt_end = std.time.nanoTimestamp();

        const encrypt_duration = @as(f64, @floatFromInt(encrypt_end - encrypt_start));
        const bytes_per_mb = 1024.0 * 1024.0;
        const ns_per_s = 1_000_000_000.0;
        const encrypt_throughput = (@as(f64, @floatFromInt(size)) / encrypt_duration) * ns_per_s / bytes_per_mb;

        const encrypt_result = BenchmarkResult{
            .algorithm = "SM4",
            .operation = "encrypt",
            .data_size_kb = @as(f64, @floatFromInt(size)) / 1024.0,
            .throughput_mb_s = encrypt_throughput,
            .timestamp = timestamp,
            .build_mode = getBuildMode(),
            .platform = getPlatform(),
        };

        try suite.addResult(encrypt_result);

        // Benchmark decryption
        const decrypt_start = std.time.nanoTimestamp();
        for (0..blocks) |i| {
            const start = i * 16;
            ctx.decryptBlock(
                out[start..][0..16],
                buffer[start..][0..16],
            );
        }
        const decrypt_end = std.time.nanoTimestamp();

        const decrypt_duration = @as(f64, @floatFromInt(decrypt_end - decrypt_start));
        const decrypt_throughput = (@as(f64, @floatFromInt(size)) / decrypt_duration) * ns_per_s / bytes_per_mb;

        const decrypt_result = BenchmarkResult{
            .algorithm = "SM4",
            .operation = "decrypt",
            .data_size_kb = @as(f64, @floatFromInt(size)) / 1024.0,
            .throughput_mb_s = decrypt_throughput,
            .timestamp = timestamp,
            .build_mode = getBuildMode(),
            .platform = getPlatform(),
        };

        try suite.addResult(decrypt_result);
    }
}

// Run all benchmarks and output JSON
pub fn runBenchmarks(allocator: std.mem.Allocator, output_json: bool) !void {
    var suite = BenchmarkSuite.init(allocator);
    defer suite.deinit();

    try benchmarkSM3(allocator, &suite);
    try benchmarkSM4(allocator, &suite);

    if (output_json) {
        // Output JSON for CI consumption
        const json_output = try suite.toJsonArray();
        defer allocator.free(json_output);
        std.debug.print("{s}\n", .{json_output});
    } else {
        // Human-readable output
        suite.printSummary();
    }
}

// Command-line benchmark runner
pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Check command line arguments
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    const output_json = args.len > 1 and std.mem.eql(u8, args[1], "--json");

    try runBenchmarks(allocator, output_json);
}