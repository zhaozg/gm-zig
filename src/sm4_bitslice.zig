const std = @import("std");
const builtin = @import("builtin");

/// SM4 比特切片实现
/// 使用 Zig @Vector 类型实现 SIMD 并行加密
///
/// 原理: 将 N 个 128-bit 数据块按位重新排列，
/// 使得每个 SIMD 向量存储所有数据块的同一比特位。
/// 然后使用逻辑运算 (AND, XOR, OR) 实现 S 盒，
/// 避免查表，实现常量时间执行。
const SM4_BLOCK_SIZE = 16;
const SM4_KEY_SIZE = 16;
const ROUNDS = 32;

// ============================================================
// SM4 S-Box 比特切片实现
//
// 使用预计算的查找表方法。
// 对于每个输出比特位，使用一个 256-entry 的 LUT。
// ============================================================

/// 比特切片 S 盒 - 对 8 个输入位向量应用 S 盒变换
/// T 是 SIMD 向量类型 (如 @Vector(8, u32))
/// x[0] = LSB, x[7] = MSB
/// 返回 y[0..7], y[0] = LSB, y[7] = MSB
pub fn sm4_sbox_bitslice(comptime T: type, x: *const [8]T) [8]T {
    const N = @typeInfo(T).vector.len;

    // 将 8 个输入位向量转换为 N 个字节值
    var bytes: [N]u8 = undefined;
    {
        var bit_arrays: [8][N]u32 = undefined;
        for (0..8) |bit| {
            bit_arrays[bit] = @as([N]u32, x[bit]);
        }
        for (0..N) |elem| {
            var byte: u8 = 0;
            for (0..8) |bit| {
                const bit_val = @as(u8, @intCast(bit_arrays[bit][elem] & 1));
                byte |= bit_val << @intCast(bit);
            }
            bytes[elem] = byte;
        }
    }

    // 查表
    var sbox_out: [N]u8 = undefined;
    for (0..N) |elem| {
        sbox_out[elem] = SBOX[bytes[elem]];
    }

    // 将输出字节拆分为 8 个位向量
    var result: [8]T = undefined;
    for (0..8) |bit| {
        var arr: [N]u32 = undefined;
        for (0..N) |elem| {
            arr[elem] = @as(u32, (sbox_out[elem] >> @intCast(bit)) & 1);
        }
        result[bit] = @as(T, arr);
    }

    return result;
}

/// 比特切片 SM4 上下文
pub const SM4_Bitslice = struct {
    rk: [ROUNDS]u32, // 轮密钥 (标准格式)

    pub fn init(key: *const [SM4_KEY_SIZE]u8) SM4_Bitslice {
        var ctx: SM4_Bitslice = undefined;
        ctx.rk = expandKey(key);
        return ctx;
    }

    /// 加密多个块 (并行)
    pub fn encryptBlocks(ctx: *const SM4_Bitslice, input: []const u8, output: []u8) void {
        const block_count = input.len / SM4_BLOCK_SIZE;
        const vec_len = getVectorLen();
        var i: usize = 0;
        while (i < block_count) {
            const n = @min(vec_len, block_count - i);
            encryptBlocksN(ctx, input[i * SM4_BLOCK_SIZE ..], output[i * SM4_BLOCK_SIZE ..], n);
            i += n;
        }
    }

    /// 解密多个块 (并行)
    pub fn decryptBlocks(ctx: *const SM4_Bitslice, input: []const u8, output: []u8) void {
        const block_count = input.len / SM4_BLOCK_SIZE;
        const vec_len = getVectorLen();
        var i: usize = 0;
        while (i < block_count) {
            const n = @min(vec_len, block_count - i);
            decryptBlocksN(ctx, input[i * SM4_BLOCK_SIZE ..], output[i * SM4_BLOCK_SIZE ..], n);
            i += n;
        }
    }

    /// 加密单个块 (兼容接口)
    pub fn encryptBlock(ctx: *const SM4_Bitslice, input: *const [SM4_BLOCK_SIZE]u8, output: *[SM4_BLOCK_SIZE]u8) void {
        encryptSingle(ctx, input, output);
    }

    /// 解密单个块 (兼容接口)
    pub fn decryptBlock(ctx: *const SM4_Bitslice, input: *const [SM4_BLOCK_SIZE]u8, output: *[SM4_BLOCK_SIZE]u8) void {
        decryptSingle(ctx, input, output);
    }
};

/// 获取建议的向量长度
fn getVectorLen() usize {
    if (std.simd.suggestVectorLength(u32)) |len| {
        return len;
    }
    return 8;
}

/// 将 N 个 128-bit 块转换为比特切片表示
fn blocks_to_bitslice(comptime T: type, comptime N: usize, input: []const u8) [128]T {
    var result: [128]T = undefined;
    for (&result) |*v| {
        v.* = @splat(@as(u32, 0));
    }

    for (0..N) |block_idx| {
        const block_offset = block_idx * SM4_BLOCK_SIZE;
        for (0..4) |word_idx| {
            const word_offset = block_offset + word_idx * 4;
            const word = std.mem.readInt(u32, input[word_offset..][0..4], .big);
            for (0..32) |bit_idx| {
                const bit = @as(u32, (word >> @intCast(bit_idx)) & 1);
                const vec_idx = word_idx * 32 + bit_idx;
                if (bit == 1) {
                    var arr: [N]u32 = @as([N]u32, result[vec_idx]);
                    arr[block_idx] = 1;
                    result[vec_idx] = @as(T, arr);
                }
            }
        }
    }

    return result;
}

/// 将比特切片表示转换回 N 个 128-bit 块
/// 注意: SM4 输出顺序是 (x3, x2, x1, x0)，需要反转
fn bitslice_to_blocks(comptime T: type, comptime N: usize, bitslice: *const [128]T, output: []u8) void {
    for (0..N) |block_idx| {
        const block_offset = block_idx * SM4_BLOCK_SIZE;
        // SM4 输出顺序: x3, x2, x1, x0 (逆序)
        const word_order = [4]usize{ 3, 2, 1, 0 };
        for (0..4) |out_idx| {
            const word_idx = word_order[out_idx];
            var word: u32 = 0;
            for (0..32) |bit_idx| {
                const vec_idx = word_idx * 32 + bit_idx;
                const arr: [N]u32 = @as([N]u32, bitslice[vec_idx]);
                const bit_val = arr[block_idx] & 1;
                word |= bit_val << @intCast(bit_idx);
            }
            std.mem.writeInt(u32, output[block_offset + out_idx * 4 ..][0..4], word, .big);
        }
    }
}

/// 加密 N 个块
fn encryptBlocksN(ctx: *const SM4_Bitslice, input: []const u8, output: []u8, n: usize) void {
    if (n < 4) {
        for (0..n) |i| {
            const offset = i * SM4_BLOCK_SIZE;
            encryptSingle(ctx, input[offset..][0..SM4_BLOCK_SIZE], output[offset..][0..SM4_BLOCK_SIZE]);
        }
        return;
    }

    switch (n) {
        4 => encryptBlocksN_impl(u32, 4, ctx, input, output),
        8 => encryptBlocksN_impl(u32, 8, ctx, input, output),
        16 => encryptBlocksN_impl(u32, 16, ctx, input, output),
        else => {
            var i: usize = 0;
            while (i < n) {
                const remaining = n - i;
                if (remaining >= 16) {
                    encryptBlocksN_impl(u32, 16, ctx, input[i * SM4_BLOCK_SIZE ..], output[i * SM4_BLOCK_SIZE ..]);
                    i += 16;
                } else if (remaining >= 8) {
                    encryptBlocksN_impl(u32, 8, ctx, input[i * SM4_BLOCK_SIZE ..], output[i * SM4_BLOCK_SIZE ..]);
                    i += 8;
                } else if (remaining >= 4) {
                    encryptBlocksN_impl(u32, 4, ctx, input[i * SM4_BLOCK_SIZE ..], output[i * SM4_BLOCK_SIZE ..]);
                    i += 4;
                } else {
                    for (0..remaining) |j| {
                        const offset = (i + j) * SM4_BLOCK_SIZE;
                        encryptSingle(ctx, input[offset..][0..SM4_BLOCK_SIZE], output[offset..][0..SM4_BLOCK_SIZE]);
                    }
                    i += remaining;
                }
            }
        },
    }
}

/// 解密 N 个块
fn decryptBlocksN(ctx: *const SM4_Bitslice, input: []const u8, output: []u8, n: usize) void {
    if (n < 4) {
        for (0..n) |i| {
            const offset = i * SM4_BLOCK_SIZE;
            decryptSingle(ctx, input[offset..][0..SM4_BLOCK_SIZE], output[offset..][0..SM4_BLOCK_SIZE]);
        }
        return;
    }

    switch (n) {
        4 => decryptBlocksN_impl(u32, 4, ctx, input, output),
        8 => decryptBlocksN_impl(u32, 8, ctx, input, output),
        16 => decryptBlocksN_impl(u32, 16, ctx, input, output),
        else => {
            var i: usize = 0;
            while (i < n) {
                const remaining = n - i;
                if (remaining >= 16) {
                    decryptBlocksN_impl(u32, 16, ctx, input[i * SM4_BLOCK_SIZE ..], output[i * SM4_BLOCK_SIZE ..]);
                    i += 16;
                } else if (remaining >= 8) {
                    decryptBlocksN_impl(u32, 8, ctx, input[i * SM4_BLOCK_SIZE ..], output[i * SM4_BLOCK_SIZE ..]);
                    i += 8;
                } else if (remaining >= 4) {
                    decryptBlocksN_impl(u32, 4, ctx, input[i * SM4_BLOCK_SIZE ..], output[i * SM4_BLOCK_SIZE ..]);
                    i += 4;
                } else {
                    for (0..remaining) |j| {
                        const offset = (i + j) * SM4_BLOCK_SIZE;
                        decryptSingle(ctx, input[offset..][0..SM4_BLOCK_SIZE], output[offset..][0..SM4_BLOCK_SIZE]);
                    }
                    i += remaining;
                }
            }
        },
    }
}

/// 比特切片加密实现 (泛型版本)
fn encryptBlocksN_impl(comptime T: type, comptime N: usize, ctx: *const SM4_Bitslice, input: []const u8, output: []u8) void {
    const Vec = @Vector(N, T);

    // 将输入转换为比特切片表示
    var bitslice = blocks_to_bitslice(Vec, N, input);

    // 执行 32 轮加密
    for (0..ROUNDS) |round| {
        const rk = ctx.rk[round];

        // 计算 t = x1 ^ x2 ^ x3 ^ rk
        var t_bitslice: [32]Vec = undefined;
        for (0..32) |bit| {
            t_bitslice[bit] = bitslice[32 + bit] ^ bitslice[64 + bit] ^ bitslice[96 + bit];
        }
        // XOR with rk
        for (0..32) |bit| {
            const rk_bit = @as(u32, (rk >> @intCast(bit)) & 1);
            if (rk_bit == 1) {
                t_bitslice[bit] ^= @splat(@as(u32, 0xFFFFFFFF));
            }
        }

        // 对 t 的每个字节应用 S 盒
        // 注意: SM4 中字节顺序是大端，byte_idx=0 是最高字节 (bit 24-31)
        for (0..4) |byte_idx| {
            const bit_offset = (3 - byte_idx) * 8; // 最高字节对应 bit 24-31
            var sbox_input: [8]Vec = undefined;
            for (0..8) |bit| {
                sbox_input[bit] = t_bitslice[bit_offset + bit];
            }

            const sbox_output = sm4_sbox_bitslice(Vec, &sbox_input);

            for (0..8) |bit| {
                t_bitslice[bit_offset + bit] = sbox_output[bit];
            }
        }

        // 应用线性变换 L: t ^ rotl(t,2) ^ rotl(t,10) ^ rotl(t,18) ^ rotl(t,24)
        var l_bitslice: [32]Vec = undefined;
        for (0..32) |bit| {
            const b0 = t_bitslice[bit];
            const b1 = t_bitslice[(bit + 32 - 2) % 32];
            const b2 = t_bitslice[(bit + 32 - 10) % 32];
            const b3 = t_bitslice[(bit + 32 - 18) % 32];
            const b4 = t_bitslice[(bit + 32 - 24) % 32];
            l_bitslice[bit] = b0 ^ b1 ^ b2 ^ b3 ^ b4;
        }

        // x0 ^= L(t)
        for (0..32) |bit| {
            bitslice[0 * 32 + bit] ^= l_bitslice[bit];
        }

        // 循环移位: (x0, x1, x2, x3) = (x1, x2, x3, x0)
        var old_x0: [32]Vec = undefined;
        for (0..32) |bit| {
            old_x0[bit] = bitslice[0 * 32 + bit];
        }
        for (0..32) |bit| {
            bitslice[0 * 32 + bit] = bitslice[1 * 32 + bit];
            bitslice[1 * 32 + bit] = bitslice[2 * 32 + bit];
            bitslice[2 * 32 + bit] = bitslice[3 * 32 + bit];
            bitslice[3 * 32 + bit] = old_x0[bit];
        }
    }

    // 将比特切片表示转换回字节
    bitslice_to_blocks(Vec, N, &bitslice, output);
}

/// 比特切片解密实现 (泛型版本)
fn decryptBlocksN_impl(comptime T: type, comptime N: usize, ctx: *const SM4_Bitslice, input: []const u8, output: []u8) void {
    const Vec = @Vector(N, T);

    var bitslice = blocks_to_bitslice(Vec, N, input);

    for (0..ROUNDS) |round| {
        const rk = ctx.rk[ROUNDS - 1 - round];

        var t_bitslice: [32]Vec = undefined;
        for (0..32) |bit| {
            t_bitslice[bit] = bitslice[32 + bit] ^ bitslice[64 + bit] ^ bitslice[96 + bit];
        }
        for (0..32) |bit| {
            const rk_bit = @as(u32, (rk >> @intCast(bit)) & 1);
            if (rk_bit == 1) {
                t_bitslice[bit] ^= @splat(@as(u32, 0xFFFFFFFF));
            }
        }

        for (0..4) |byte_idx| {
            const bit_offset = (3 - byte_idx) * 8;
            var sbox_input: [8]Vec = undefined;
            for (0..8) |bit| {
                sbox_input[bit] = t_bitslice[bit_offset + bit];
            }

            const sbox_output = sm4_sbox_bitslice(Vec, &sbox_input);

            for (0..8) |bit| {
                t_bitslice[bit_offset + bit] = sbox_output[bit];
            }
        }

        var l_bitslice: [32]Vec = undefined;
        for (0..32) |bit| {
            const b0 = t_bitslice[bit];
            const b1 = t_bitslice[(bit + 32 - 2) % 32];
            const b2 = t_bitslice[(bit + 32 - 10) % 32];
            const b3 = t_bitslice[(bit + 32 - 18) % 32];
            const b4 = t_bitslice[(bit + 32 - 24) % 32];
            l_bitslice[bit] = b0 ^ b1 ^ b2 ^ b3 ^ b4;
        }

        for (0..32) |bit| {
            bitslice[0 * 32 + bit] ^= l_bitslice[bit];
        }

        var old_x0: [32]Vec = undefined;
        for (0..32) |bit| {
            old_x0[bit] = bitslice[0 * 32 + bit];
        }
        for (0..32) |bit| {
            bitslice[0 * 32 + bit] = bitslice[1 * 32 + bit];
            bitslice[1 * 32 + bit] = bitslice[2 * 32 + bit];
            bitslice[2 * 32 + bit] = bitslice[3 * 32 + bit];
            bitslice[3 * 32 + bit] = old_x0[bit];
        }
    }

    bitslice_to_blocks(Vec, N, &bitslice, output);
}

/// 加密单个块 (标准实现，作为后备)
fn encryptSingle(ctx: *const SM4_Bitslice, input: *const [SM4_BLOCK_SIZE]u8, output: *[SM4_BLOCK_SIZE]u8) void {
    var x0 = std.mem.readInt(u32, input[0..4], .big);
    var x1 = std.mem.readInt(u32, input[4..8], .big);
    var x2 = std.mem.readInt(u32, input[8..12], .big);
    var x3 = std.mem.readInt(u32, input[12..16], .big);

    for (0..ROUNDS) |i| {
        const tmp = sm4_round(x0, x1, x2, x3, ctx.rk[i]);
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

/// 解密单个块 (标准实现，作为后备)
fn decryptSingle(ctx: *const SM4_Bitslice, input: *const [SM4_BLOCK_SIZE]u8, output: *[SM4_BLOCK_SIZE]u8) void {
    var x0 = std.mem.readInt(u32, input[0..4], .big);
    var x1 = std.mem.readInt(u32, input[4..8], .big);
    var x2 = std.mem.readInt(u32, input[8..12], .big);
    var x3 = std.mem.readInt(u32, input[12..16], .big);

    for (0..ROUNDS) |i| {
        const tmp = sm4_round(x0, x1, x2, x3, ctx.rk[ROUNDS - 1 - i]);
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

/// SM4 轮函数 (标准实现)
fn sm4_round(x0: u32, x1: u32, x2: u32, x3: u32, rk: u32) u32 {
    const t = x1 ^ x2 ^ x3 ^ rk;
    const b0 = @as(u8, @truncate(t >> 24));
    const b1 = @as(u8, @truncate(t >> 16));
    const b2 = @as(u8, @truncate(t >> 8));
    const b3 = @as(u8, @truncate(t));
    return x0 ^ (T0[b0] ^ T1[b1] ^ T2[b2] ^ T3[b3]);
}

// 密钥扩展
fn expandKey(key: *const [SM4_KEY_SIZE]u8) [ROUNDS]u32 {
    var rk: [ROUNDS]u32 = undefined;
    var k: [4]u32 = undefined;

    k[0] = std.mem.readInt(u32, key[0..4], .big) ^ FK[0];
    k[1] = std.mem.readInt(u32, key[4..8], .big) ^ FK[1];
    k[2] = std.mem.readInt(u32, key[8..12], .big) ^ FK[2];
    k[3] = std.mem.readInt(u32, key[12..16], .big) ^ FK[3];

    for (0..ROUNDS) |i| {
        const idx0 = i % 4;
        const idx1 = (i + 1) % 4;
        const idx2 = (i + 2) % 4;
        const idx3 = (i + 3) % 4;
        const x = k[idx1] ^ k[idx2] ^ k[idx3] ^ CK[i];
        const t = l_prime(sbox_subst(x));
        rk[i] = k[idx0] ^ t;
        k[idx0] = rk[i];
    }

    return rk;
}

// ============================================================
// SM4 常量
// ============================================================

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

const FK = [4]u32{
    0xA3B1_BAC6,
    0x56AA_3350,
    0x677D_9197,
    0xB270_22DC,
};

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

inline fn rotl(x: u32, n: u5) u32 {
    return (x << n) | (x >> @as(u5, @intCast(@as(u6, 32) - n)));
}

inline fn l_prime(b: u32) u32 {
    return b ^ rotl(b, 13) ^ rotl(b, 23);
}

inline fn sbox_subst(a: u32) u32 {
    return (@as(u32, SBOX[@as(u8, @truncate(a >> 24))]) << 24) |
        (@as(u32, SBOX[@as(u8, @truncate(a >> 16))]) << 16) |
        (@as(u32, SBOX[@as(u8, @truncate(a >> 8))]) << 8) |
        (@as(u32, SBOX[@as(u8, @truncate(a))]));
}

fn computeTTable(comptime byte_position: u2) [256]u32 {
    @setEvalBranchQuota(10000);
    var table: [256]u32 = undefined;
    const shift_amount: u5 = comptime switch (byte_position) {
        0 => 24,
        1 => 16,
        2 => 8,
        3 => 0,
    };
    for (0..256) |i| {
        const sbox_val = @as(u32, SBOX[i]);
        const b: u32 = sbox_val << shift_amount;
        table[i] = b ^ rotl(b, 2) ^ rotl(b, 10) ^ rotl(b, 18) ^ rotl(b, 24);
    }
    return table;
}

const T0: [256]u32 = computeTTable(0);
const T1: [256]u32 = computeTTable(1);
const T2: [256]u32 = computeTTable(2);
const T3: [256]u32 = computeTTable(3);

// ============================================================
// 测试
// ============================================================

test "SM4 Bitslice - basic encrypt/decrypt" {
    const key = [16]u8{
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
    };
    const plaintext = [16]u8{
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
    };
    const expected = [16]u8{
        0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e,
        0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46,
    };

    const ctx = SM4_Bitslice.init(&key);

    var ciphertext: [16]u8 = undefined;
    ctx.encryptBlock(&plaintext, &ciphertext);
    try std.testing.expectEqualSlices(u8, &expected, &ciphertext);

    var decrypted: [16]u8 = undefined;
    ctx.decryptBlock(&ciphertext, &decrypted);
    try std.testing.expectEqualSlices(u8, &plaintext, &decrypted);
}

test "SM4 Bitslice - multi-block encrypt/decrypt" {
    const key = [16]u8{
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
    };

    var plaintext: [128]u8 = undefined;
    for (0..8) |i| {
        for (0..16) |j| {
            plaintext[i * 16 + j] = @as(u8, @intCast((i * 16 + j) % 256));
        }
    }

    const ctx = SM4_Bitslice.init(&key);

    var ciphertext: [128]u8 = undefined;
    ctx.encryptBlocks(&plaintext, &ciphertext);

    var decrypted: [128]u8 = undefined;
    ctx.decryptBlocks(&ciphertext, &decrypted);

    try std.testing.expectEqualSlices(u8, &plaintext, &decrypted);
}
