const std = @import("std");
const root = @import("./root.zig");
const sm3 = root.sm3;
const sm4 = root.sm4;
const sm2 = root.sm2;
const sm9 = root.sm9;

// Benchmark result structure for structured output
pub const BenchmarkResult = struct {
    algorithm: []const u8,
    operation: []const u8,
    data_size_kb: f64,
    performance_value: f64,
    performance_unit: []const u8,
    timestamp: i64,
    build_mode: []const u8,
    platform: []const u8,

    pub fn toJson(self: BenchmarkResult, allocator: std.mem.Allocator) ![]u8 {
        var output: std.ArrayList(u8) = .empty;
        defer output.deinit(allocator);
        
        const writer = output.writer(allocator);
        try writer.print("{{", .{});
        try writer.print("\"algorithm\":\"{s}\",", .{self.algorithm});
        try writer.print("\"operation\":\"{s}\",", .{self.operation});
        try writer.print("\"performance_value\":{d},", .{self.performance_value});
        try writer.print("\"performance_unit\":\"{s}\",", .{self.performance_unit});
        try writer.print("\"data_size_kb\":{d},", .{self.data_size_kb});
        try writer.print("\"timestamp\":{},", .{self.timestamp});
        try writer.print("\"build_mode\":\"{s}\",", .{self.build_mode});
        try writer.print("\"platform\":\"{s}\"", .{self.platform});
        try writer.print("}}", .{});
        
        return try output.toOwnedSlice(allocator);
    }
};

pub const BenchmarkSuite = struct {
    results: std.ArrayList(BenchmarkResult),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) BenchmarkSuite {
        return BenchmarkSuite{
            .results = .empty,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *BenchmarkSuite) void {
        self.results.deinit(self.allocator);
    }

    pub fn addResult(self: *BenchmarkSuite, result: BenchmarkResult) !void {
        try self.results.append(self.allocator, result);
    }

    pub fn toJsonArray(self: *BenchmarkSuite) ![]u8 {
        var output: std.ArrayList(u8) = .empty;
        defer output.deinit(self.allocator);
        
        const writer = output.writer(self.allocator);
        try writer.print("[", .{});
        
        for (self.results.items, 0..) |result, i| {
            if (i > 0) try writer.print(",", .{});
            const result_json = try result.toJson(self.allocator);
            defer self.allocator.free(result_json);
            try writer.print("{s}", .{result_json});
        }
        
        try writer.print("]", .{});
        return try output.toOwnedSlice(self.allocator);
    }

    // Print human-readable summary
    pub fn printSummary(self: *BenchmarkSuite) void {
        std.debug.print("\n=== Performance Benchmark Summary ===\n", .{});
        for (self.results.items) |result| {
            std.debug.print("{s} {s}: {d:.2} KB -> {d:.2} {s}\n", .{
                result.algorithm,
                result.operation,
                result.data_size_kb,
                result.performance_value,
                result.performance_unit,
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
        const alignment: std.mem.Alignment = @enumFromInt(16);
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
            .performance_value = throughput,
            .performance_unit = "MB/s",
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
        const alignment: std.mem.Alignment = @enumFromInt(16);
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
            .performance_value = encrypt_throughput,
            .performance_unit = "MB/s",
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
            .performance_value = decrypt_throughput,
            .performance_unit = "MB/s",
            .timestamp = timestamp,
            .build_mode = getBuildMode(),
            .platform = getPlatform(),
        };

        try suite.addResult(decrypt_result);
    }
}

// Benchmark SM2 elliptic curve cryptography performance
pub fn benchmarkSM2(allocator: std.mem.Allocator, suite: *BenchmarkSuite) !void {
    const timestamp = std.time.timestamp();

    // Test message sizes for encryption/signature operations
    const test_messages = [_][]const u8{
        "Hello SM2!", // Small message
        "This is a medium length message for SM2 testing that contains multiple words and sentences to provide a realistic benchmark scenario.",
        // Large message (1KB)
        "A" ** 1024,
    };

    // 1. Benchmark key pair generation
    {
        const iterations = 100;
        const start_time = std.time.nanoTimestamp();

        for (0..iterations) |_| {
            _ = sm2.kp.generateKeyPair();
        }

        const end_time = std.time.nanoTimestamp();
        const duration_ns = @as(f64, @floatFromInt(end_time - start_time));
        const ops_per_second = (@as(f64, @floatFromInt(iterations)) / duration_ns) * 1_000_000_000.0;

        const result = BenchmarkResult{
            .algorithm = "SM2",
            .operation = "keypair_generation",
            .data_size_kb = 0, // Not applicable for key generation
            .performance_value = ops_per_second,
            .performance_unit = "ops/s",
            .timestamp = timestamp,
            .build_mode = getBuildMode(),
            .platform = getPlatform(),
        };

        try suite.addResult(result);
    }

    // Generate a key pair for subsequent operations
    const key_pair = sm2.kp.generateKeyPair();
    const sign_options = sm2.signature.SignatureOptions{
        .user_id = "benchmark@test.com",
        .hash_type = .sm3,
    };

    // 2. Benchmark digital signature operations
    for (test_messages, 0..) |message, i| {
        const data_size_kb = @as(f64, @floatFromInt(message.len)) / 1024.0;

        // Signature creation
        {
            const iterations: u32 = if (i == 2) 10 else 50; // Fewer iterations for large messages
            const start_time = std.time.nanoTimestamp();

            for (0..iterations) |_| {
                _ = sm2.signature.sign(message, key_pair.private_key, key_pair.public_key, sign_options) catch continue;
            }

            const end_time = std.time.nanoTimestamp();
            const duration_ns = @as(f64, @floatFromInt(end_time - start_time));
            const ops_per_second = (@as(f64, @floatFromInt(iterations)) / duration_ns) * 1_000_000_000.0;

            const result = BenchmarkResult{
                .algorithm = "SM2",
                .operation = "sign",
                .data_size_kb = data_size_kb,
                .performance_value = ops_per_second,
                .performance_unit = "ops/s",
                .timestamp = timestamp,
                .build_mode = getBuildMode(),
                .platform = getPlatform(),
            };

            try suite.addResult(result);
        }

        // Signature verification
        {
            const signature = sm2.signature.sign(message, key_pair.private_key, key_pair.public_key, sign_options) catch continue;
            const iterations: u32 = if (i == 2) 10 else 50;
            const start_time = std.time.nanoTimestamp();

            for (0..iterations) |_| {
                _ = sm2.signature.verify(message, signature, key_pair.public_key, sign_options) catch continue;
            }

            const end_time = std.time.nanoTimestamp();
            const duration_ns = @as(f64, @floatFromInt(end_time - start_time));
            const ops_per_second = (@as(f64, @floatFromInt(iterations)) / duration_ns) * 1_000_000_000.0;

            const result = BenchmarkResult{
                .algorithm = "SM2",
                .operation = "verify",
                .data_size_kb = data_size_kb,
                .performance_value = ops_per_second,
                .performance_unit = "ops/s",
                .timestamp = timestamp,
                .build_mode = getBuildMode(),
                .platform = getPlatform(),
            };

            try suite.addResult(result);
        }

        // Encryption/Decryption operations
        {
            const iterations: u32 = if (i == 2) 5 else 20;

            // Encryption
            const encrypt_start = std.time.nanoTimestamp();
            for (0..iterations) |_| {
                const ciphertext = sm2.encryption.encrypt(allocator, message, key_pair.public_key, .c1c3c2) catch continue;
                ciphertext.deinit(allocator);
            }
            const encrypt_end = std.time.nanoTimestamp();

            const encrypt_duration = @as(f64, @floatFromInt(encrypt_end - encrypt_start));
            const encrypt_ops_per_second = (@as(f64, @floatFromInt(iterations)) / encrypt_duration) * 1_000_000_000.0;

            const encrypt_result = BenchmarkResult{
                .algorithm = "SM2",
                .operation = "encrypt",
                .data_size_kb = data_size_kb,
                .performance_value = encrypt_ops_per_second,
                .performance_unit = "ops/s",
                .timestamp = timestamp,
                .build_mode = getBuildMode(),
                .platform = getPlatform(),
            };

            try suite.addResult(encrypt_result);

            // Decryption
            const ciphertext = sm2.encryption.encrypt(allocator, message, key_pair.public_key, .c1c3c2) catch return;
            defer ciphertext.deinit(allocator);

            const decrypt_start = std.time.nanoTimestamp();
            for (0..iterations) |_| {
                const plaintext = sm2.encryption.decrypt(allocator, ciphertext, key_pair.private_key) catch continue;
                allocator.free(plaintext);
            }
            const decrypt_end = std.time.nanoTimestamp();

            const decrypt_duration = @as(f64, @floatFromInt(decrypt_end - decrypt_start));
            const decrypt_ops_per_second = (@as(f64, @floatFromInt(iterations)) / decrypt_duration) * 1_000_000_000.0;

            const decrypt_result = BenchmarkResult{
                .algorithm = "SM2",
                .operation = "decrypt",
                .data_size_kb = data_size_kb,
                .performance_value = decrypt_ops_per_second,
                .performance_unit = "ops/s",
                .timestamp = timestamp,
                .build_mode = getBuildMode(),
                .platform = getPlatform(),
            };

            try suite.addResult(decrypt_result);
        }
    }
}

// Benchmark SM9 identity-based cryptography performance
pub fn benchmarkSM9(allocator: std.mem.Allocator, suite: *BenchmarkSuite) !void {
    const timestamp = std.time.timestamp();

    // Initialize SM9 system
    const system = sm9.params.SM9System.init();
    const key_context = sm9.key_extract.KeyExtractionContext.init(system, allocator);
    const sign_context = sm9.sign.SignatureContext.init(system, allocator);
    const encrypt_context = sm9.encrypt.EncryptionContext.init(system, allocator);

    const test_user_id = "benchmark@test.edu.cn";
    const test_messages = [_][]const u8{
        "Hello SM9!",
        "This is a medium length message for SM9 identity-based cryptography testing.",
        "A" ** 512, // Large message (512 bytes for SM9)
    };

    // 1. Benchmark key extraction
    {
        const iterations = 20;

        // Signing key extraction
        const sign_extract_start = std.time.nanoTimestamp();
        for (0..iterations) |_| {
            _ = key_context.extractSignKey(test_user_id) catch continue;
        }
        const sign_extract_end = std.time.nanoTimestamp();

        const sign_extract_duration = @as(f64, @floatFromInt(sign_extract_end - sign_extract_start));
        const sign_extract_ops = (@as(f64, @floatFromInt(iterations)) / sign_extract_duration) * 1_000_000_000.0;

        const sign_extract_result = BenchmarkResult{
            .algorithm = "SM9",
            .operation = "key_extract_sign",
            .data_size_kb = 0,
            .performance_value = sign_extract_ops,
            .performance_unit = "ops/s",
            .timestamp = timestamp,
            .build_mode = getBuildMode(),
            .platform = getPlatform(),
        };

        try suite.addResult(sign_extract_result);

        // Encryption key extraction
        const encrypt_extract_start = std.time.nanoTimestamp();
        for (0..iterations) |_| {
            _ = key_context.extractEncryptKey(test_user_id) catch continue;
        }
        const encrypt_extract_end = std.time.nanoTimestamp();

        const encrypt_extract_duration = @as(f64, @floatFromInt(encrypt_extract_end - encrypt_extract_start));
        const encrypt_extract_ops = (@as(f64, @floatFromInt(iterations)) / encrypt_extract_duration) * 1_000_000_000.0;

        const encrypt_extract_result = BenchmarkResult{
            .algorithm = "SM9",
            .operation = "key_extract_encrypt",
            .data_size_kb = 0,
            .performance_value = encrypt_extract_ops,
            .performance_unit = "ops/s",
            .timestamp = timestamp,
            .build_mode = getBuildMode(),
            .platform = getPlatform(),
        };

        try suite.addResult(encrypt_extract_result);
    }

    // Extract keys for subsequent operations
    const sign_key = key_context.extractSignKey(test_user_id) catch return;
    const encrypt_key = key_context.extractEncryptKey(test_user_id) catch return;

    // 2. Benchmark digital signature operations
    for (test_messages, 0..) |message, i| {
        const data_size_kb = @as(f64, @floatFromInt(message.len)) / 1024.0;
        const iterations: u32 = if (i == 2) 5 else 15;

        // Signature creation
        {
            const start_time = std.time.nanoTimestamp();

            for (0..iterations) |_| {
                _ = sign_context.sign(message, sign_key, .{}) catch continue;
            }

            const end_time = std.time.nanoTimestamp();
            const duration_ns = @as(f64, @floatFromInt(end_time - start_time));
            const ops_per_second = (@as(f64, @floatFromInt(iterations)) / duration_ns) * 1_000_000_000.0;

            const result = BenchmarkResult{
                .algorithm = "SM9",
                .operation = "sign",
                .data_size_kb = data_size_kb,
                .performance_value = ops_per_second,
                .performance_unit = "ops/s",
                .timestamp = timestamp,
                .build_mode = getBuildMode(),
                .platform = getPlatform(),
            };

            try suite.addResult(result);
        }

        // Signature verification
        {
            const signature = sign_context.sign(message, sign_key, .{}) catch continue;

            const start_time = std.time.nanoTimestamp();

            for (0..iterations) |_| {
                _ = sign_context.verify(message, signature, test_user_id, .{}) catch continue;
            }

            const end_time = std.time.nanoTimestamp();
            const duration_ns = @as(f64, @floatFromInt(end_time - start_time));
            const ops_per_second = (@as(f64, @floatFromInt(iterations)) / duration_ns) * 1_000_000_000.0;

            const result = BenchmarkResult{
                .algorithm = "SM9",
                .operation = "verify",
                .data_size_kb = data_size_kb,
                .performance_value = ops_per_second,
                .performance_unit = "ops/s",
                .timestamp = timestamp,
                .build_mode = getBuildMode(),
                .platform = getPlatform(),
            };

            try suite.addResult(result);
        }

        // Encryption/Decryption operations
        {
            const enc_iterations: u32 = if (i == 2) 3 else 10;

            // Encryption
            const encrypt_start = std.time.nanoTimestamp();
            for (0..enc_iterations) |_| {
                const ciphertext = encrypt_context.encrypt(message, test_user_id, .{}) catch continue;
                ciphertext.deinit();
            }
            const encrypt_end = std.time.nanoTimestamp();

            const encrypt_duration = @as(f64, @floatFromInt(encrypt_end - encrypt_start));
            const encrypt_ops_per_second = (@as(f64, @floatFromInt(enc_iterations)) / encrypt_duration) * 1_000_000_000.0;

            const encrypt_result = BenchmarkResult{
                .algorithm = "SM9",
                .operation = "encrypt",
                .data_size_kb = data_size_kb,
                .performance_value = encrypt_ops_per_second,
                .performance_unit = "ops/s",
                .timestamp = timestamp,
                .build_mode = getBuildMode(),
                .platform = getPlatform(),
            };

            try suite.addResult(encrypt_result);

            // Decryption
            const ciphertext = encrypt_context.encrypt(message, test_user_id, .{}) catch return;
            defer ciphertext.deinit();

            const decrypt_start = std.time.nanoTimestamp();
            for (0..enc_iterations) |_| {
                const plaintext = encrypt_context.decrypt(ciphertext, encrypt_key, .{}) catch continue;
                allocator.free(plaintext);
            }
            const decrypt_end = std.time.nanoTimestamp();

            const decrypt_duration = @as(f64, @floatFromInt(decrypt_end - decrypt_start));
            const decrypt_ops_per_second = (@as(f64, @floatFromInt(enc_iterations)) / decrypt_duration) * 1_000_000_000.0;

            const decrypt_result = BenchmarkResult{
                .algorithm = "SM9",
                .operation = "decrypt",
                .data_size_kb = data_size_kb,
                .performance_value = decrypt_ops_per_second,
                .performance_unit = "ops/s",
                .timestamp = timestamp,
                .build_mode = getBuildMode(),
                .platform = getPlatform(),
            };

            try suite.addResult(decrypt_result);
        }
    }
}

// Run all benchmarks and output JSON
pub fn runBenchmarks(allocator: std.mem.Allocator, output_json: bool) !void {
    var suite = BenchmarkSuite.init(allocator);
    defer suite.deinit();

    try benchmarkSM3(allocator, &suite);
    try benchmarkSM4(allocator, &suite);
    try benchmarkSM2(allocator, &suite);
    try benchmarkSM9(allocator, &suite);

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
