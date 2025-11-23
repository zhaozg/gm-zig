// Standalone SIMD benchmark - comparing scalar vs SIMD in same build
const std = @import("std");
const sm3 = @import("./sm3.zig");
const sm4 = @import("./sm4.zig");
const simd = @import("./simd.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const stdout = std.io.getStdOut().writer();
    
    try stdout.print("\n=== SIMD Performance Benchmark (Scalar vs SIMD) ===\n", .{});
    try stdout.print("Build Mode: {s}\n", .{@tagName(@import("builtin").mode)});
    
    const caps = simd.SimdCapabilities.detect();
    try stdout.print("SIMD Hardware Support: {}\n", .{caps.canUseSIMD()});
    try stdout.print("Optimal Vector Size: {} blocks\n\n", .{simd.getOptimalVectorSize()});

    // SM4 ECB Benchmark
    try stdout.print("=== SM4 ECB Mode ===\n", .{});
    try benchmarkSM4ECB(allocator, stdout);
    
    // SM4 CBC Benchmark
    try stdout.print("\n=== SM4 CBC Decrypt Mode ===\n", .{});
    try benchmarkSM4CBC(allocator, stdout);
    
    // SM3 Benchmark
    try stdout.print("\n=== SM3 Hash ===\n", .{});
    try benchmarkSM3(allocator, stdout);
}

fn benchmarkSM4ECB(allocator: std.mem.Allocator, writer: anytype) !void {
    const key = [_]u8{0x01} ** 16;
    const sizes = [_]usize{ 1024, 16 * 1024, 1024 * 1024 };
    
    for (sizes) |size| {
        const plaintext = try allocator.alloc(u8, size);
        defer allocator.free(plaintext);
        const ciphertext_scalar = try allocator.alloc(u8, size);
        defer allocator.free(ciphertext_scalar);
        const ciphertext_simd = try allocator.alloc(u8, size);
        defer allocator.free(ciphertext_simd);
        
        // Fill with test data
        for (plaintext, 0..) |*b, i| {
            b.* = @as(u8, @truncate(i));
        }
        
        // Warmup
        var sm4_warmup = sm4.SM4_ECB.init(&key);
        sm4_warmup.encrypt(plaintext, ciphertext_scalar);
        
        // Benchmark scalar
        var sm4_scalar = sm4.SM4_ECB.init(&key);
        sm4_scalar.use_simd = false;
        const start_scalar = std.time.nanoTimestamp();
        sm4_scalar.encrypt(plaintext, ciphertext_scalar);
        const elapsed_scalar = std.time.nanoTimestamp() - start_scalar;
        
        // Benchmark SIMD
        var sm4_simd = sm4.SM4_ECB.init(&key);
        const start_simd = std.time.nanoTimestamp();
        sm4_simd.encrypt(plaintext, ciphertext_simd);
        const elapsed_simd = std.time.nanoTimestamp() - start_simd;
        
        const mb = @as(f64, @floatFromInt(size)) / (1024.0 * 1024.0);
        const throughput_scalar = mb / (@as(f64, @floatFromInt(elapsed_scalar)) / 1_000_000_000.0);
        const throughput_simd = mb / (@as(f64, @floatFromInt(elapsed_simd)) / 1_000_000_000.0);
        const speedup = throughput_simd / throughput_scalar;
        
        try writer.print("Size: {d:6} KB | Scalar: {d:6.2} MB/s | SIMD: {d:6.2} MB/s | Speedup: {d:4.2}x\n", .{
            size / 1024,
            throughput_scalar,
            throughput_simd,
            speedup,
        });
    }
}

fn benchmarkSM4CBC(allocator: std.mem.Allocator, writer: anytype) !void {
    const key = [_]u8{0x01} ** 16;
    const iv = [_]u8{0x00} ** 16;
    const sizes = [_]usize{ 1024, 16 * 1024, 1024 * 1024 };
    
    for (sizes) |size| {
        const ciphertext = try allocator.alloc(u8, size);
        defer allocator.free(ciphertext);
        const plaintext_scalar = try allocator.alloc(u8, size);
        defer allocator.free(plaintext_scalar);
        const plaintext_simd = try allocator.alloc(u8, size);
        defer allocator.free(plaintext_simd);
        
        // Fill with test data
        for (ciphertext, 0..) |*b, i| {
            b.* = @as(u8, @truncate(i));
        }
        
        // Warmup
        var sm4_warmup = sm4.SM4_CBC.init(&key, &iv);
        sm4_warmup.decrypt(ciphertext, plaintext_scalar);
        
        // Benchmark scalar
        var sm4_scalar = sm4.SM4_CBC.init(&key, &iv);
        sm4_scalar.use_simd = false;
        const start_scalar = std.time.nanoTimestamp();
        sm4_scalar.decrypt(ciphertext, plaintext_scalar);
        const elapsed_scalar = std.time.nanoTimestamp() - start_scalar;
        
        // Benchmark SIMD
        var sm4_simd = sm4.SM4_CBC.init(&key, &iv);
        const start_simd = std.time.nanoTimestamp();
        sm4_simd.decrypt(ciphertext, plaintext_simd);
        const elapsed_simd = std.time.nanoTimestamp() - start_simd;
        
        const mb = @as(f64, @floatFromInt(size)) / (1024.0 * 1024.0);
        const throughput_scalar = mb / (@as(f64, @floatFromInt(elapsed_scalar)) / 1_000_000_000.0);
        const throughput_simd = mb / (@as(f64, @floatFromInt(elapsed_simd)) / 1_000_000_000.0);
        const speedup = throughput_simd / throughput_scalar;
        
        try writer.print("Size: {d:6} KB | Scalar: {d:6.2} MB/s | SIMD: {d:6.2} MB/s | Speedup: {d:4.2}x\n", .{
            size / 1024,
            throughput_scalar,
            throughput_simd,
            speedup,
        });
    }
}

fn benchmarkSM3(allocator: std.mem.Allocator, writer: anytype) !void {
    const sizes = [_]usize{ 64 * 1024, 1024 * 1024, 10 * 1024 * 1024 };
    
    for (sizes) |size| {
        const data = try allocator.alloc(u8, size);
        defer allocator.free(data);
        
        // Fill with test data
        for (data, 0..) |*b, i| {
            b.* = @as(u8, @truncate(i));
        }
        
        var hash_scalar: [32]u8 = undefined;
        var hash_simd: [32]u8 = undefined;
        
        // Warmup
        var warmup = sm3.SM3.init(.{});
        warmup.update(data);
        warmup.final(&hash_scalar);
        
        // Benchmark scalar
        var hasher_scalar = sm3.SM3.init(.{});
        hasher_scalar.use_simd = false;
        const start_scalar = std.time.nanoTimestamp();
        hasher_scalar.update(data);
        hasher_scalar.final(&hash_scalar);
        const elapsed_scalar = std.time.nanoTimestamp() - start_scalar;
        
        // Benchmark SIMD
        var hasher_simd = sm3.SM3.init(.{});
        const start_simd = std.time.nanoTimestamp();
        hasher_simd.update(data);
        hasher_simd.final(&hash_simd);
        const elapsed_simd = std.time.nanoTimestamp() - start_simd;
        
        const mb = @as(f64, @floatFromInt(size)) / (1024.0 * 1024.0);
        const throughput_scalar = mb / (@as(f64, @floatFromInt(elapsed_scalar)) / 1_000_000_000.0);
        const throughput_simd = mb / (@as(f64, @floatFromInt(elapsed_simd)) / 1_000_000_000.0);
        const speedup = throughput_simd / throughput_scalar;
        
        try writer.print("Size: {d:6} KB | Scalar: {d:6.2} MB/s | SIMD: {d:6.2} MB/s | Speedup: {d:4.2}x\n", .{
            size / 1024,
            throughput_scalar,
            throughput_simd,
            speedup,
        });
    }
}
