const std = @import("std");
const assert = std.debug.assert;
const print = std.debug.print;

// SM4 算法常量定义
const SM4_BLOCK_SIZE = 16; // 128-bit blocks
const SM4_KEY_SIZE = 16; // 128-bit keys
const ROUNDS = 32; // 32 rounds

// SM4 S-Box (256-byte substitution table)
const SBOX = [256]u8{
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
    0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
    0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
    0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
    0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
    0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
    0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48,
};

// Fixed parameters (FK)
const FK = [4]u32{
    0xA3B1_BAC6,
    0x56AA_3350,
    0x677D_9197,
    0xB270_22DC,
};

// Round constants (CK)
const CK = [32]u32{
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
    0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
    0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
    0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
    0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279,
};

// SM4 context structure
pub const SM4 = struct {
    rk: [ROUNDS]u32, // Round keys

    // Initialize SM4 context with key
    pub fn init(key: *const [SM4_KEY_SIZE]u8) SM4 {
        var ctx: SM4 = undefined;
        var k: [4]u32 = undefined;

        // Load key as big-endian words
        k[0] = std.mem.readInt(u32, key[0..4], .big) ^ FK[0];
        k[1] = std.mem.readInt(u32, key[4..8], .big) ^ FK[1];
        k[2] = std.mem.readInt(u32, key[8..12], .big) ^ FK[2];
        k[3] = std.mem.readInt(u32, key[12..16], .big) ^ FK[3];

        // Generate round keys
        for (0..ROUNDS) |i| {
            const x = k[(i + 1) % 4] ^ k[(i + 2) % 4] ^ k[(i + 3) % 4] ^ CK[i];
            const t = l_prime(tau(x));
            ctx.rk[i] = k[i % 4] ^ t;
            k[i % 4] = ctx.rk[i];
        }

        return ctx;
    }

    // Encrypt single 128-bit block
    pub fn encryptBlock(ctx: *const SM4, input: *const [SM4_BLOCK_SIZE]u8, output: *[SM4_BLOCK_SIZE]u8) void {
        var x0 = std.mem.readInt(u32, input[0..4], .big);
        var x1 = std.mem.readInt(u32, input[4..8], .big);
        var x2 = std.mem.readInt(u32, input[8..12], .big);
        var x3 = std.mem.readInt(u32, input[12..16], .big);

        for (0..ROUNDS) |i| {
            const tmp = round(x0, x1, x2, x3, ctx.rk[i]);
            x0 = x1;
            x1 = x2;
            x2 = x3;
            x3 = tmp;
        }

        std.mem.writeInt(u32, output[0..4], x3, .big);
        std.mem.writeInt(u32, output[4..8], x2, .big);
        std.mem.writeInt(u32, output[8..12], x1, .big);
        std.mem.writeInt(u32, output[12..16], x0, .big);
    }

    // Decrypt single 128-bit block
    pub fn decryptBlock(ctx: *const SM4, input: *const [SM4_BLOCK_SIZE]u8, output: *[SM4_BLOCK_SIZE]u8) void {
        var x0 = std.mem.readInt(u32, input[0..4], .big);
        var x1 = std.mem.readInt(u32, input[4..8], .big);
        var x2 = std.mem.readInt(u32, input[8..12], .big);
        var x3 = std.mem.readInt(u32, input[12..16], .big);

        for (0..ROUNDS) |i| {
            const tmp = round(x0, x1, x2, x3, ctx.rk[ROUNDS - 1 - i]);
            x0 = x1;
            x1 = x2;
            x2 = x3;
            x3 = tmp;
        }

        std.mem.writeInt(u32, output[0..4], x3, .big);
        std.mem.writeInt(u32, output[4..8], x2, .big);
        std.mem.writeInt(u32, output[8..12], x1, .big);
        std.mem.writeInt(u32, output[12..16], x0, .big);
    }

    fn l_prime(b: u32) u32 {
        return b ^ rotl(b, 13) ^ rotl(b, 23);
    }

    fn round(x0: u32, x1: u32, x2: u32, x3: u32, rk: u32) u32 {
        // tau + l_transform 合并
        const t = x1 ^ x2 ^ x3 ^ rk;
        const sbox_out = tau(t);
        const l = sbox_out ^
            rotl(sbox_out, 2) ^
            rotl(sbox_out, 10) ^
            rotl(sbox_out, 18) ^
            rotl(sbox_out, 24);
        return x0 ^ l;
    }

    // Nonlinear transformation τ (S-box substitution)
    fn tau(a: u32) u32 {
        return (@as(u32, SBOX[@as(u8, @truncate(a >> 24))]) << 24) |
            (@as(u32, SBOX[@as(u8, @truncate(a >> 16))]) << 16) |
            (@as(u32, SBOX[@as(u8, @truncate(a >> 8))]) << 8) |
            (@as(u32, SBOX[@as(u8, @truncate(a))]));
    }

    // Linear transformation L
    fn l_transform(b: u32) u32 {
        return b ^
            rotl(b, 2) ^
            rotl(b, 10) ^
            rotl(b, 18) ^
            rotl(b, 24);
    }

    // Rotate left helper
    fn rotl(x: u32, n: u5) u32 {
        return (x << n) | (x >> @as(u5, @intCast(@as(u6, 32) - n)));
    }
};

// CBC模式加密
pub const SM4_CBC = struct {
    sm4: SM4,
    iv: [SM4_BLOCK_SIZE]u8,

    pub fn init(key: *const [SM4_KEY_SIZE]u8, iv: *const [SM4_BLOCK_SIZE]u8) SM4_CBC {
        return .{
            .sm4 = SM4.init(key),
            .iv = iv.*,
        };
    }

    pub fn encrypt(self: *SM4_CBC, input: []const u8, output: []u8) void {
        assert(input.len % SM4_BLOCK_SIZE == 0);
        assert(output.len >= input.len);

        var iv = self.iv;
        var i: usize = 0;
        while (i < input.len) : (i += SM4_BLOCK_SIZE) {
            const block = input[i .. i + SM4_BLOCK_SIZE];
            var xored: [SM4_BLOCK_SIZE]u8 = undefined;

            // XOR with IV or previous ciphertext
            for (0..SM4_BLOCK_SIZE) |j| {
                xored[j] = block[j] ^ iv[j];
            }

            self.sm4.encryptBlock(&xored, @as(*[16]u8, @ptrCast(output[i..].ptr)));
            iv = @as(*[16]u8, @ptrCast(output[i..].ptr)).*;
        }

        // 更新IV为最后一个密文块
        @memcpy(&self.iv, output[output.len - SM4_BLOCK_SIZE ..][0..SM4_BLOCK_SIZE]);
    }

    pub fn decrypt(self: *SM4_CBC, input: []const u8, output: []u8) void {
        assert(input.len % SM4_BLOCK_SIZE == 0);
        assert(output.len >= input.len);

        var next_iv: [SM4_BLOCK_SIZE]u8 = undefined;
        var iv = self.iv;
        var i: usize = 0;
        while (i < input.len) : (i += SM4_BLOCK_SIZE) {
            const ciphertext = input[i .. i + SM4_BLOCK_SIZE];
            var decrypted: [SM4_BLOCK_SIZE]u8 = undefined;

            // 保存下一个IV
            @memcpy(&next_iv, ciphertext[0..SM4_BLOCK_SIZE]);

            self.sm4.decryptBlock(@as(*const [16]u8, @ptrCast(ciphertext.ptr)), &decrypted);

            // XOR with IV or previous ciphertext
            for (0..SM4_BLOCK_SIZE) |j| {
                output[i + j] = decrypted[j] ^ iv[j];
            }

            // 更新IV
            iv = next_iv;
        }

        // 更新IV为最后一个密文块
        @memcpy(&self.iv, &next_iv);
    }
};

// Test vector from GM/T 0002-2012
test "SM4 Known Answer Test" {
    // Test key and plaintext
    const key = [16]u8{
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
    };
    const plaintext = [16]u8{
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
    };
    const expected_ciphertext = [16]u8{
        0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e,
        0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46,
    };

    // Initialize context
    const ctx = SM4.init(&key);

    // Test encryption
    var ciphertext: [16]u8 = undefined;
    ctx.encryptBlock(&plaintext, &ciphertext);
    try std.testing.expectEqualSlices(u8, &expected_ciphertext, &ciphertext);

    // Test decryption
    var decrypted: [16]u8 = undefined;
    ctx.decryptBlock(&ciphertext, &decrypted);
    try std.testing.expectEqualSlices(u8, &plaintext, &decrypted);
}

// 性能测试函数
pub fn testPerformance(allocator: std.mem.Allocator) !void {
    const key = [16]u8{
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
    };
    const ctx = SM4.init(&key);

    const test_sizes = [_]usize{
        1024, // 64 blocks
        1024 * 16, // 1KB
        1024 * 1024, // 1MB
        10 * 1024 * 1024, // 10MB
    };

    print("\nSM4 Performance Test (ReleaseSafe build recommended)\n", .{});
    print("------------------------------------------------\n", .{});

    for (test_sizes) |size| {
        // 分配对齐的内存以提高性能
        const alignment = 16;
        const buffer = try allocator.alignedAlloc(u8, alignment, size);
        defer allocator.free(buffer);

        // 填充随机数据
        var prng = std.Random.DefaultPrng.init(0);
        prng.random().bytes(buffer);

        // 准备输出缓冲区
        const out = try allocator.alignedAlloc(u8, alignment, size);
        defer allocator.free(out);

        // 预热缓存
        ctx.encryptBlock(buffer[0..16], out[0..16]);

        // 加密性能测试
        const encrypt_start = std.time.nanoTimestamp();
        const blocks = size / SM4_BLOCK_SIZE;
        for (0..blocks) |i| {
            const start = i * SM4_BLOCK_SIZE;
            const end = start + SM4_BLOCK_SIZE;
            ctx.encryptBlock(
                std.mem.bytesAsValue([SM4_BLOCK_SIZE]u8, buffer[start..end]),
                std.mem.bytesAsValue([SM4_BLOCK_SIZE]u8, out[start..end]),
            );
        }
        const encrypt_time = @as(f64, @floatFromInt(std.time.nanoTimestamp() - encrypt_start));

        // 解密性能测试
        const decrypt_start = std.time.nanoTimestamp();
        for (0..blocks) |i| {
            const start = i * SM4_BLOCK_SIZE;
            const end = start + SM4_BLOCK_SIZE;
            ctx.decryptBlock(
                std.mem.bytesAsValue([SM4_BLOCK_SIZE]u8, out[start..end]),
                std.mem.bytesAsValue([SM4_BLOCK_SIZE]u8, buffer[start..end]),
            );
        }
        const decrypt_time = @as(f64, @floatFromInt(std.time.nanoTimestamp() - decrypt_start));

        // 计算速度 (MB/s)
        const bytes_per_mb = 1024.0 * 1024.0;
        const ns_per_s = 1_000_000_000.0;
        const encrypt_speed = (@as(f64, @floatFromInt(size)) / encrypt_time) * ns_per_s / bytes_per_mb;
        const decrypt_speed = (@as(f64, @floatFromInt(size)) / decrypt_time) * ns_per_s / bytes_per_mb;

        print("Data: {d:>6.2} KB | Encrypt: {d:>6.2} MB/s | Decrypt: {d:>6.2} MB/s\n", .{
            size / 1024,
            encrypt_speed,
            decrypt_speed,
        });
    }
}

pub fn testPerformance_cbc(allocator: std.mem.Allocator) !void {
    const key = [16]u8{
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
    };
    var ctx = SM4_CBC.init(&key, &key);

    const test_sizes = [_]usize{
        16 * 64, // 1KB
        1024 * 16, // 16KB
        1024 * 1024, // 1MB
        10 * 1024 * 1024, // 10MB
        100 * 1024 * 1024, // 100MB
    };

    std.debug.print("\nSM4_CBC 性能测试 (推荐使用ReleaseSafe构建)\n", .{});
    std.debug.print("------------------------------------------------\n", .{});

    for (test_sizes) |size| {
        const buffer = try allocator.alloc(u8, size);
        defer allocator.free(buffer);

        // 填充随机数据
        var prng = std.Random.DefaultPrng.init(0);
        prng.random().bytes(buffer);

        const out = try allocator.alloc(u8, size);
        defer allocator.free(out);

        // 预热
        ctx.encrypt(buffer[0..16], out[0..16]);

        // 加密性能测试
        const encrypt_start = std.time.nanoTimestamp();
        const blocks = size / SM4_BLOCK_SIZE;
        for (0..blocks) |i| {
            const start = i * SM4_BLOCK_SIZE;
            ctx.encrypt(
                buffer[start..][0..SM4_BLOCK_SIZE],
                out[start..][0..SM4_BLOCK_SIZE],
            );
        }
        const encrypt_time = @as(f64, @floatFromInt(std.time.nanoTimestamp() - encrypt_start));

        // 解密性能测试
        const decrypt_start = std.time.nanoTimestamp();
        for (0..blocks) |i| {
            const start = i * SM4_BLOCK_SIZE;
            ctx.decrypt(
                out[start..][0..SM4_BLOCK_SIZE],
                buffer[start..][0..SM4_BLOCK_SIZE],
            );
        }
        const decrypt_time = @as(f64, @floatFromInt(std.time.nanoTimestamp() - decrypt_start));

        // 计算速度 (MB/s)
        const bytes_per_mb = 1024.0 * 1024.0;
        const ns_per_s = 1_000_000_000.0;
        const encrypt_speed = (@as(f64, @floatFromInt(size)) / encrypt_time) * ns_per_s / bytes_per_mb;
        const decrypt_speed = (@as(f64, @floatFromInt(size)) / decrypt_time) * ns_per_s / bytes_per_mb;

        std.debug.print("数据: {d:>6} KB | 加密: {d:>6.2} MB/s | 解密: {d:>6.2} MB/s\n", .{
            size / 1024,
            encrypt_speed,
            decrypt_speed,
        });
    }
}
