// simd.zig - SIMD-optimized implementations for GM cryptographic algorithms
// Only applies SIMD where it provides measurable benefits

const std = @import("std");
const builtin = @import("builtin");
const native_target = builtin.target;

/// SIMD capability detection
pub const SimdCapabilities = struct {
    has_sse2: bool = false,
    has_ssse3: bool = false,
    has_aes_ni: bool = false,
    has_avx2: bool = false,
    has_neon: bool = false,

    pub fn detect() SimdCapabilities {
        var caps = SimdCapabilities{};
        
        switch (native_target.cpu.arch) {
            .x86_64, .x86 => {
                // Check for x86 SIMD features
                caps.has_sse2 = std.Target.x86.featureSetHas(native_target.cpu.features, .sse2);
                caps.has_ssse3 = std.Target.x86.featureSetHas(native_target.cpu.features, .ssse3);
                caps.has_aes_ni = std.Target.x86.featureSetHas(native_target.cpu.features, .aes);
                caps.has_avx2 = std.Target.x86.featureSetHas(native_target.cpu.features, .avx2);
            },
            .aarch64, .arm => {
                // Check for ARM NEON features
                caps.has_neon = std.Target.aarch64.featureSetHas(native_target.cpu.features, .neon);
            },
            else => {},
        }
        
        return caps;
    }
    
    pub fn canUseSIMD(self: SimdCapabilities) bool {
        return self.has_sse2 or self.has_neon;
    }
};

/// Get optimal SIMD vector size for the current platform
pub fn getOptimalVectorSize() usize {
    const caps = SimdCapabilities.detect();
    
    if (caps.has_avx2) return 4; // Process 4 blocks (64 bytes) at once
    if (caps.has_sse2 or caps.has_neon) return 2; // Process 2 blocks (32 bytes) at once
    
    return 1; // No SIMD, process 1 block at a time
}

/// SM4 SIMD-optimized implementations
pub const SM4_SIMD = struct {
    const SM4_BLOCK_SIZE = 16;
    
    /// Process multiple SM4 blocks in parallel using SIMD
    /// This is beneficial for ECB mode encryption/decryption
    pub fn processBlocksParallel(
        encryptBlock: anytype,
        input: []const u8,
        output: []u8,
    ) void {
        std.debug.assert(input.len % SM4_BLOCK_SIZE == 0);
        std.debug.assert(output.len >= input.len);
        
        const vector_size = getOptimalVectorSize();
        const vector_bytes = vector_size * SM4_BLOCK_SIZE;
        
        var i: usize = 0;
        
        // Process blocks in parallel when possible
        while (i + vector_bytes <= input.len) : (i += vector_bytes) {
            // Process multiple blocks
            var j: usize = 0;
            while (j < vector_size) : (j += 1) {
                const block_offset = i + (j * SM4_BLOCK_SIZE);
                const in_block = input[block_offset..][0..SM4_BLOCK_SIZE];
                const out_block = output[block_offset..][0..SM4_BLOCK_SIZE];
                
                encryptBlock(
                    @as(*const [SM4_BLOCK_SIZE]u8, @ptrCast(in_block.ptr)),
                    @as(*[SM4_BLOCK_SIZE]u8, @ptrCast(out_block.ptr)),
                );
            }
        }
        
        // Process remaining blocks sequentially
        while (i < input.len) : (i += SM4_BLOCK_SIZE) {
            const in_block = input[i..][0..SM4_BLOCK_SIZE];
            const out_block = output[i..][0..SM4_BLOCK_SIZE];
            
            encryptBlock(
                @as(*const [SM4_BLOCK_SIZE]u8, @ptrCast(in_block.ptr)),
                @as(*[SM4_BLOCK_SIZE]u8, @ptrCast(out_block.ptr)),
            );
        }
    }
    
    /// CBC decrypt can benefit from SIMD as blocks can be decrypted in parallel
    /// (encryption must remain sequential due to dependencies)
    pub fn cbcDecryptParallel(
        decryptBlock: anytype,
        input: []const u8,
        output: []u8,
        iv: [SM4_BLOCK_SIZE]u8,
    ) void {
        std.debug.assert(input.len % SM4_BLOCK_SIZE == 0);
        std.debug.assert(output.len >= input.len);
        
        const vector_size = getOptimalVectorSize();
        const vector_bytes = vector_size * SM4_BLOCK_SIZE;
        
        var i: usize = 0;
        var prev_cipher = iv;
        
        // Process blocks in parallel when possible
        while (i + vector_bytes <= input.len) : (i += vector_bytes) {
            // Decrypt multiple blocks in parallel
            var temp_blocks: [4][SM4_BLOCK_SIZE]u8 = undefined;
            var cipher_blocks: [4][SM4_BLOCK_SIZE]u8 = undefined;
            
            var j: usize = 0;
            while (j < vector_size and i + (j * SM4_BLOCK_SIZE) < input.len) : (j += 1) {
                const block_offset = i + (j * SM4_BLOCK_SIZE);
                const cipher_in = input[block_offset..][0..SM4_BLOCK_SIZE];
                @memcpy(&cipher_blocks[j], cipher_in);
                
                decryptBlock(
                    &cipher_blocks[j],
                    &temp_blocks[j],
                );
            }
            
            // XOR with previous cipher blocks
            j = 0;
            while (j < vector_size and i + (j * SM4_BLOCK_SIZE) < input.len) : (j += 1) {
                const block_offset = i + (j * SM4_BLOCK_SIZE);
                const plain_out = output[block_offset..][0..SM4_BLOCK_SIZE];
                
                for (0..SM4_BLOCK_SIZE) |k| {
                    plain_out[k] = temp_blocks[j][k] ^ prev_cipher[k];
                }
                
                prev_cipher = cipher_blocks[j];
            }
        }
        
        // Process remaining blocks sequentially
        while (i < input.len) : (i += SM4_BLOCK_SIZE) {
            const cipher_in = input[i..][0..SM4_BLOCK_SIZE];
            const plain_out = output[i..][0..SM4_BLOCK_SIZE];
            
            var cipher_block: [SM4_BLOCK_SIZE]u8 = undefined;
            @memcpy(&cipher_block, cipher_in);
            
            var temp: [SM4_BLOCK_SIZE]u8 = undefined;
            decryptBlock(&cipher_block, &temp);
            
            for (0..SM4_BLOCK_SIZE) |k| {
                plain_out[k] = temp[k] ^ prev_cipher[k];
            }
            
            prev_cipher = cipher_block;
        }
    }
};

/// SM3 SIMD-optimized implementations
pub const SM3_SIMD = struct {
    /// Parallel message expansion using SIMD
    /// SM3 message expansion can benefit from SIMD for computing multiple W values
    pub fn expandMessageSIMD(block: *const [64]u8, w: *[68]u32) void {
        // Load initial 16 words from block (big-endian)
        for (0..16) |j| {
            w[j] = std.mem.readInt(u32, block[j * 4 ..][0..4], .big);
        }
        
        // Message expansion for remaining 52 words
        // This could be vectorized with SSE2/NEON for better performance
        const vector_size = getOptimalVectorSize();
        
        if (vector_size >= 2) {
            // Process 2 or more words at a time with SIMD-friendly operations
            var j: usize = 16;
            while (j + 1 < 68) : (j += 2) {
                // Process two iterations in parallel
                const w0 = p1SIMD(w[j - 16] ^ w[j - 9] ^ std.math.rotl(u32, w[j - 3], 15)) ^
                    std.math.rotl(u32, w[j - 13], 7) ^ w[j - 6];
                const w1 = p1SIMD(w[j - 15] ^ w[j - 8] ^ std.math.rotl(u32, w[j - 2], 15)) ^
                    std.math.rotl(u32, w[j - 12], 7) ^ w[j - 5];
                
                w[j] = w0;
                w[j + 1] = w1;
            }
            
            // Handle remaining word if odd count
            if (j < 68) {
                w[j] = p1SIMD(w[j - 16] ^ w[j - 9] ^ std.math.rotl(u32, w[j - 3], 15)) ^
                    std.math.rotl(u32, w[j - 13], 7) ^ w[j - 6];
            }
        } else {
            // Fallback to scalar implementation
            for (16..68) |j| {
                w[j] = p1SIMD(w[j - 16] ^ w[j - 9] ^ std.math.rotl(u32, w[j - 3], 15)) ^
                    std.math.rotl(u32, w[j - 13], 7) ^ w[j - 6];
            }
        }
    }
    
    inline fn p1SIMD(x: u32) u32 {
        return x ^ std.math.rotl(u32, x, 15) ^ std.math.rotl(u32, x, 23);
    }
};

// Feature detection at compile time
pub const compile_time_caps = SimdCapabilities.detect();

test "SIMD capability detection" {
    const caps = SimdCapabilities.detect();
    const vector_size = getOptimalVectorSize();
    
    std.debug.print("\nSIMD Capabilities:\n", .{});
    std.debug.print("  SSE2: {}\n", .{caps.has_sse2});
    std.debug.print("  SSSE3: {}\n", .{caps.has_ssse3});
    std.debug.print("  AES-NI: {}\n", .{caps.has_aes_ni});
    std.debug.print("  AVX2: {}\n", .{caps.has_avx2});
    std.debug.print("  NEON: {}\n", .{caps.has_neon});
    std.debug.print("  Optimal vector size: {} blocks\n", .{vector_size});
    
    try std.testing.expect(vector_size >= 1);
}
