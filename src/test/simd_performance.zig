// SIMD performance tests - comparing SIMD-optimized vs scalar implementations
const std = @import("std");
const testing = std.testing;
const sm3 = @import("../sm3.zig");
const sm4 = @import("../sm4.zig");
const simd = @import("../simd.zig");

test "SM4 ECB SIMD performance comparison" {
    const key = [_]u8{0x01} ** 16;
    const data_sizes = [_]usize{ 1024, 16 * 1024, 1024 * 1024 };
    
    const caps = simd.SimdCapabilities.detect();
    std.debug.print("\n=== SM4 ECB SIMD Performance Test ===\n", .{});
    std.debug.print("SIMD Support: {}\n", .{caps.canUseSIMD()});
    std.debug.print("Vector Size: {} blocks\n\n", .{simd.getOptimalVectorSize()});
    
    for (data_sizes) |size| {
        const plaintext = try testing.allocator.alloc(u8, size);
        defer testing.allocator.free(plaintext);
        const ciphertext = try testing.allocator.alloc(u8, size);
        defer testing.allocator.free(ciphertext);
        
        // Fill with test data
        for (plaintext, 0..) |*b, i| {
            b.* = @as(u8, @truncate(i));
        }
        
        // Test with SIMD
        var sm4_ecb = sm4.SM4_ECB.init(&key);
        const start = std.time.nanoTimestamp();
        sm4_ecb.encrypt(plaintext, ciphertext);
        const elapsed = std.time.nanoTimestamp() - start;
        
        const mb = @as(f64, @floatFromInt(size)) / (1024.0 * 1024.0);
        const seconds = @as(f64, @floatFromInt(elapsed)) / 1_000_000_000.0;
        const throughput = mb / seconds;
        
        std.debug.print("Size: {d:6} KB | Throughput: {d:6.2} MB/s | SIMD: {}\n", .{
            size / 1024,
            throughput,
            sm4_ecb.use_simd,
        });
    }
}

test "SM4 CBC SIMD decrypt performance" {
    const key = [_]u8{0x01} ** 16;
    const iv = [_]u8{0x00} ** 16;
    const data_sizes = [_]usize{ 1024, 16 * 1024, 1024 * 1024 };
    
    const caps = simd.SimdCapabilities.detect();
    std.debug.print("\n=== SM4 CBC Decrypt SIMD Performance Test ===\n", .{});
    std.debug.print("SIMD Support: {}\n", .{caps.canUseSIMD()});
    std.debug.print("Vector Size: {} blocks\n\n", .{simd.getOptimalVectorSize()});
    
    for (data_sizes) |size| {
        const ciphertext = try testing.allocator.alloc(u8, size);
        defer testing.allocator.free(ciphertext);
        const plaintext = try testing.allocator.alloc(u8, size);
        defer testing.allocator.free(plaintext);
        
        // Fill with test data
        for (ciphertext, 0..) |*b, i| {
            b.* = @as(u8, @truncate(i));
        }
        
        // Test with SIMD
        var sm4_cbc = sm4.SM4_CBC.init(&key, &iv);
        const start = std.time.nanoTimestamp();
        sm4_cbc.decrypt(ciphertext, plaintext);
        const elapsed = std.time.nanoTimestamp() - start;
        
        const mb = @as(f64, @floatFromInt(size)) / (1024.0 * 1024.0);
        const seconds = @as(f64, @floatFromInt(elapsed)) / 1_000_000_000.0;
        const throughput = mb / seconds;
        
        std.debug.print("Size: {d:6} KB | Throughput: {d:6.2} MB/s | SIMD: {}\n", .{
            size / 1024,
            throughput,
            sm4_cbc.use_simd,
        });
    }
}

test "SM3 SIMD performance comparison" {
    const data_sizes = [_]usize{ 64 * 1024, 1024 * 1024, 10 * 1024 * 1024 };
    
    const caps = simd.SimdCapabilities.detect();
    std.debug.print("\n=== SM3 Hash SIMD Performance Test ===\n", .{});
    std.debug.print("SIMD Support: {}\n", .{caps.canUseSIMD()});
    std.debug.print("Vector Size: {} blocks\n\n", .{simd.getOptimalVectorSize()});
    
    for (data_sizes) |size| {
        const data = try testing.allocator.alloc(u8, size);
        defer testing.allocator.free(data);
        
        // Fill with test data
        for (data, 0..) |*b, i| {
            b.* = @as(u8, @truncate(i));
        }
        
        var hash: [32]u8 = undefined;
        var hasher = sm3.SM3.init(.{});
        
        const start = std.time.nanoTimestamp();
        hasher.update(data);
        hasher.final(&hash);
        const elapsed = std.time.nanoTimestamp() - start;
        
        const mb = @as(f64, @floatFromInt(size)) / (1024.0 * 1024.0);
        const seconds = @as(f64, @floatFromInt(elapsed)) / 1_000_000_000.0;
        const throughput = mb / seconds;
        
        std.debug.print("Size: {d:6} KB | Throughput: {d:6.2} MB/s | SIMD: {}\n", .{
            size / 1024,
            throughput,
            hasher.use_simd,
        });
    }
}

test "SIMD capability details" {
    const caps = simd.SimdCapabilities.detect();
    
    std.debug.print("\n=== Detailed SIMD Capabilities ===\n", .{});
    std.debug.print("SSE2:   {} (x86 128-bit SIMD)\n", .{caps.has_sse2});
    std.debug.print("SSSE3:  {} (x86 supplemental SIMD)\n", .{caps.has_ssse3});
    std.debug.print("AES-NI: {} (hardware AES acceleration)\n", .{caps.has_aes_ni});
    std.debug.print("AVX2:   {} (x86 256-bit SIMD)\n", .{caps.has_avx2});
    std.debug.print("NEON:   {} (ARM SIMD)\n", .{caps.has_neon});
    std.debug.print("\nOptimal vector size: {} blocks ({} bytes)\n", .{
        simd.getOptimalVectorSize(),
        simd.getOptimalVectorSize() * 16,
    });
    std.debug.print("Can use SIMD: {}\n", .{caps.canUseSIMD()});
    
    try testing.expect(simd.getOptimalVectorSize() >= 1);
}
