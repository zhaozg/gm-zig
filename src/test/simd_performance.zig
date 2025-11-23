// SIMD performance tests - comparing SIMD-optimized vs scalar implementations
// Tests both with and without SIMD in the same build configuration for fair comparison
const std = @import("std");
const testing = std.testing;
const sm3 = @import("../sm3.zig");
const sm4 = @import("../sm4.zig");
const simd = @import("../simd.zig");

test "SM4 ECB SIMD performance comparison" {
    const key = [_]u8{0x01} ** 16;
    const data_sizes = [_]usize{ 1024, 16 * 1024, 1024 * 1024 };
    
    const caps = simd.SimdCapabilities.detect();
    std.debug.print("\n=== SM4 ECB SIMD Performance Comparison ===\n", .{});
    std.debug.print("SIMD Hardware Support: {}\n", .{caps.canUseSIMD()});
    std.debug.print("Optimal Vector Size: {} blocks\n", .{simd.getOptimalVectorSize()});
    std.debug.print("Testing scalar vs SIMD in same build configuration\n\n", .{});
    
    for (data_sizes) |size| {
        const plaintext = try testing.allocator.alloc(u8, size);
        defer testing.allocator.free(plaintext);
        const ciphertext_scalar = try testing.allocator.alloc(u8, size);
        defer testing.allocator.free(ciphertext_scalar);
        const ciphertext_simd = try testing.allocator.alloc(u8, size);
        defer testing.allocator.free(ciphertext_simd);
        
        // Fill with test data
        for (plaintext, 0..) |*b, i| {
            b.* = @as(u8, @truncate(i));
        }
        
        // Test WITHOUT SIMD (scalar baseline)
        var sm4_ecb_scalar = sm4.SM4_ECB.init(&key);
        sm4_ecb_scalar.use_simd = false; // Force scalar path
        const start_scalar = std.time.nanoTimestamp();
        sm4_ecb_scalar.encrypt(plaintext, ciphertext_scalar);
        const elapsed_scalar = std.time.nanoTimestamp() - start_scalar;
        
        const mb = @as(f64, @floatFromInt(size)) / (1024.0 * 1024.0);
        const seconds_scalar = @as(f64, @floatFromInt(elapsed_scalar)) / 1_000_000_000.0;
        const throughput_scalar = mb / seconds_scalar;
        
        // Test WITH SIMD (if available)
        var sm4_ecb_simd = sm4.SM4_ECB.init(&key);
        const start_simd = std.time.nanoTimestamp();
        sm4_ecb_simd.encrypt(plaintext, ciphertext_simd);
        const elapsed_simd = std.time.nanoTimestamp() - start_simd;
        
        const seconds_simd = @as(f64, @floatFromInt(elapsed_simd)) / 1_000_000_000.0;
        const throughput_simd = mb / seconds_simd;
        
        const speedup = throughput_simd / throughput_scalar;
        
        std.debug.print("Size: {d:6} KB | Scalar: {d:6.2} MB/s | SIMD: {d:6.2} MB/s | Speedup: {d:4.2}x\n", .{
            size / 1024,
            throughput_scalar,
            throughput_simd,
            speedup,
        });
        
        // Verify results are identical
        try testing.expectEqualSlices(u8, ciphertext_scalar, ciphertext_simd);
    }
}

test "SM4 CBC SIMD decrypt performance comparison" {
    const key = [_]u8{0x01} ** 16;
    const iv = [_]u8{0x00} ** 16;
    const data_sizes = [_]usize{ 1024, 16 * 1024, 1024 * 1024 };
    
    const caps = simd.SimdCapabilities.detect();
    std.debug.print("\n=== SM4 CBC Decrypt SIMD Performance Comparison ===\n", .{});
    std.debug.print("SIMD Hardware Support: {}\n", .{caps.canUseSIMD()});
    std.debug.print("Optimal Vector Size: {} blocks\n", .{simd.getOptimalVectorSize()});
    std.debug.print("Testing scalar vs SIMD in same build configuration\n\n", .{});
    
    for (data_sizes) |size| {
        const ciphertext = try testing.allocator.alloc(u8, size);
        defer testing.allocator.free(ciphertext);
        const plaintext_scalar = try testing.allocator.alloc(u8, size);
        defer testing.allocator.free(plaintext_scalar);
        const plaintext_simd = try testing.allocator.alloc(u8, size);
        defer testing.allocator.free(plaintext_simd);
        
        // Fill with test data
        for (ciphertext, 0..) |*b, i| {
            b.* = @as(u8, @truncate(i));
        }
        
        // Test WITHOUT SIMD (scalar baseline)
        var sm4_cbc_scalar = sm4.SM4_CBC.init(&key, &iv);
        sm4_cbc_scalar.use_simd = false; // Force scalar path
        const start_scalar = std.time.nanoTimestamp();
        sm4_cbc_scalar.decrypt(ciphertext, plaintext_scalar);
        const elapsed_scalar = std.time.nanoTimestamp() - start_scalar;
        
        const mb = @as(f64, @floatFromInt(size)) / (1024.0 * 1024.0);
        const seconds_scalar = @as(f64, @floatFromInt(elapsed_scalar)) / 1_000_000_000.0;
        const throughput_scalar = mb / seconds_scalar;
        
        // Test WITH SIMD (if available)
        var sm4_cbc_simd = sm4.SM4_CBC.init(&key, &iv);
        const start_simd = std.time.nanoTimestamp();
        sm4_cbc_simd.decrypt(ciphertext, plaintext_simd);
        const elapsed_simd = std.time.nanoTimestamp() - start_simd;
        
        const seconds_simd = @as(f64, @floatFromInt(elapsed_simd)) / 1_000_000_000.0;
        const throughput_simd = mb / seconds_simd;
        
        const speedup = throughput_simd / throughput_scalar;
        
        std.debug.print("Size: {d:6} KB | Scalar: {d:6.2} MB/s | SIMD: {d:6.2} MB/s | Speedup: {d:4.2}x\n", .{
            size / 1024,
            throughput_scalar,
            throughput_simd,
            speedup,
        });
        
        // Verify results are identical
        try testing.expectEqualSlices(u8, plaintext_scalar, plaintext_simd);
    }
}

test "SM3 SIMD performance comparison" {
    const data_sizes = [_]usize{ 64 * 1024, 1024 * 1024, 10 * 1024 * 1024 };
    
    const caps = simd.SimdCapabilities.detect();
    std.debug.print("\n=== SM3 Hash SIMD Performance Comparison ===\n", .{});
    std.debug.print("SIMD Hardware Support: {}\n", .{caps.canUseSIMD()});
    std.debug.print("Optimal Vector Size: {} blocks\n", .{simd.getOptimalVectorSize()});
    std.debug.print("Testing scalar vs SIMD in same build configuration\n\n", .{});
    
    for (data_sizes) |size| {
        const data = try testing.allocator.alloc(u8, size);
        defer testing.allocator.free(data);
        
        // Fill with test data
        for (data, 0..) |*b, i| {
            b.* = @as(u8, @truncate(i));
        }
        
        var hash_scalar: [32]u8 = undefined;
        var hash_simd: [32]u8 = undefined;
        
        // Test WITHOUT SIMD (scalar baseline)
        var hasher_scalar = sm3.SM3.init(.{});
        hasher_scalar.use_simd = false; // Force scalar path
        const start_scalar = std.time.nanoTimestamp();
        hasher_scalar.update(data);
        hasher_scalar.final(&hash_scalar);
        const elapsed_scalar = std.time.nanoTimestamp() - start_scalar;
        
        const mb = @as(f64, @floatFromInt(size)) / (1024.0 * 1024.0);
        const seconds_scalar = @as(f64, @floatFromInt(elapsed_scalar)) / 1_000_000_000.0;
        const throughput_scalar = mb / seconds_scalar;
        
        // Test WITH SIMD (if available)
        var hasher_simd = sm3.SM3.init(.{});
        const start_simd = std.time.nanoTimestamp();
        hasher_simd.update(data);
        hasher_simd.final(&hash_simd);
        const elapsed_simd = std.time.nanoTimestamp() - start_simd;
        
        const seconds_simd = @as(f64, @floatFromInt(elapsed_simd)) / 1_000_000_000.0;
        const throughput_simd = mb / seconds_simd;
        
        const speedup = throughput_simd / throughput_scalar;
        
        std.debug.print("Size: {d:6} KB | Scalar: {d:6.2} MB/s | SIMD: {d:6.2} MB/s | Speedup: {d:4.2}x\n", .{
            size / 1024,
            throughput_scalar,
            throughput_simd,
            speedup,
        });
        
        // Verify results are identical
        try testing.expectEqualSlices(u8, &hash_scalar, &hash_simd);
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
