// zuc.zig
const std = @import("std");
const mem = std.mem;
const math = std.math;

const S0 = [256]u8{
    0x3e, 0x72, 0x5b, 0x47, 0xca, 0xe0, 0x00, 0x33, 0x04, 0xd1, 0x54, 0x98, 0x09, 0xb9, 0x6d, 0xcb,
    0x7b, 0x1b, 0xf9, 0x32, 0xaf, 0x9d, 0x6a, 0xa5, 0xb8, 0x2d, 0xfc, 0x1d, 0x08, 0x53, 0x03, 0x90,
    0x4d, 0x4e, 0x84, 0x99, 0xe4, 0xce, 0xd9, 0x91, 0xdd, 0xb6, 0x85, 0x48, 0x8b, 0x29, 0x6e, 0xac,
    0xcd, 0xc1, 0xf8, 0x1e, 0x73, 0x43, 0x69, 0xc6, 0xb5, 0xbd, 0xfd, 0x39, 0x63, 0x20, 0xd4, 0x38,
    0x76, 0x7d, 0xb2, 0xa7, 0xcf, 0xed, 0x57, 0xc5, 0xf3, 0x2c, 0xbb, 0x14, 0x21, 0x06, 0x55, 0x9b,
    0xe3, 0xef, 0x5e, 0x31, 0x4f, 0x7f, 0x5a, 0xa4, 0x0d, 0x82, 0x51, 0x49, 0x5f, 0xba, 0x58, 0x1c,
    0x4a, 0x16, 0xd5, 0x17, 0xa8, 0x92, 0x24, 0x1f, 0x8c, 0xff, 0xd8, 0xae, 0x2e, 0x01, 0xd3, 0xad,
    0x3b, 0x4b, 0xda, 0x46, 0xeb, 0xc9, 0xde, 0x9a, 0x8f, 0x87, 0xd7, 0x3a, 0x80, 0x6f, 0x2f, 0xc8,
    0xb1, 0xb4, 0x37, 0xf7, 0x0a, 0x22, 0x13, 0x28, 0x7c, 0xcc, 0x3c, 0x89, 0xc7, 0xc3, 0x96, 0x56,
    0x07, 0xbf, 0x7e, 0xf0, 0x0b, 0x2b, 0x97, 0x52, 0x35, 0x41, 0x79, 0x61, 0xa6, 0x4c, 0x10, 0xfe,
    0xbc, 0x26, 0x95, 0x88, 0x8a, 0xb0, 0xa3, 0xfb, 0xc0, 0x18, 0x94, 0xf2, 0xe1, 0xe5, 0xe9, 0x5d,
    0xd0, 0xdc, 0x11, 0x66, 0x64, 0x5c, 0xec, 0x59, 0x42, 0x75, 0x12, 0xf5, 0x74, 0x9c, 0xaa, 0x23,
    0x0e, 0x86, 0xab, 0xbe, 0x2a, 0x02, 0xe7, 0x67, 0xe6, 0x44, 0xa2, 0x6c, 0xc2, 0x93, 0x9f, 0xf1,
    0xf6, 0xfa, 0x36, 0xd2, 0x50, 0x68, 0x9e, 0x62, 0x71, 0x15, 0x3d, 0xd6, 0x40, 0xc4, 0xe2, 0x0f,
    0x8e, 0x83, 0x77, 0x6b, 0x25, 0x05, 0x3f, 0x0c, 0x30, 0xea, 0x70, 0xb7, 0xa1, 0xe8, 0xa9, 0x65,
    0x8d, 0x27, 0x1a, 0xdb, 0x81, 0xb3, 0xa0, 0xf4, 0x45, 0x7a, 0x19, 0xdf, 0xee, 0x78, 0x34, 0x60,
};

const S1 = [256]u8{
    0x55, 0xc2, 0x63, 0x71, 0x3b, 0xc8, 0x47, 0x86, 0x9f, 0x3c, 0xda, 0x5b, 0x29, 0xaa, 0xfd, 0x77,
    0x8c, 0xc5, 0x94, 0x0c, 0xa6, 0x1a, 0x13, 0x00, 0xe3, 0xa8, 0x16, 0x72, 0x40, 0xf9, 0xf8, 0x42,
    0x44, 0x26, 0x68, 0x96, 0x81, 0xd9, 0x45, 0x3e, 0x10, 0x76, 0xc6, 0xa7, 0x8b, 0x39, 0x43, 0xe1,
    0x3a, 0xb5, 0x56, 0x2a, 0xc0, 0x6d, 0xb3, 0x05, 0x22, 0x66, 0xbf, 0xdc, 0x0b, 0xfa, 0x62, 0x48,
    0xdd, 0x20, 0x11, 0x06, 0x36, 0xc9, 0xc1, 0xcf, 0xf6, 0x27, 0x52, 0xbb, 0x69, 0xf5, 0xd4, 0x87,
    0x7f, 0x84, 0x4c, 0xd2, 0x9c, 0x57, 0xa4, 0xbc, 0x4f, 0x9a, 0xdf, 0xfe, 0xd6, 0x8d, 0x7a, 0xeb,
    0x2b, 0x53, 0xd8, 0x5c, 0xa1, 0x14, 0x17, 0xfb, 0x23, 0xd5, 0x7d, 0x30, 0x67, 0x73, 0x08, 0x09,
    0xee, 0xb7, 0x70, 0x3f, 0x61, 0xb2, 0x19, 0x8e, 0x4e, 0xe5, 0x4b, 0x93, 0x8f, 0x5d, 0xdb, 0xa9,
    0xad, 0xf1, 0xae, 0x2e, 0xcb, 0x0d, 0xfc, 0xf4, 0x2d, 0x46, 0x6e, 0x1d, 0x97, 0xe8, 0xd1, 0xe9,
    0x4d, 0x37, 0xa5, 0x75, 0x5e, 0x83, 0x9e, 0xab, 0x82, 0x9d, 0xb9, 0x1c, 0xe0, 0xcd, 0x49, 0x89,
    0x01, 0xb6, 0xbd, 0x58, 0x24, 0xa2, 0x5f, 0x38, 0x78, 0x99, 0x15, 0x90, 0x50, 0xb8, 0x95, 0xe4,
    0xd0, 0x91, 0xc7, 0xce, 0xed, 0x0f, 0xb4, 0x6f, 0xa0, 0xcc, 0xf0, 0x02, 0x4a, 0x79, 0xc3, 0xde,
    0xa3, 0xef, 0xea, 0x51, 0xe6, 0x6b, 0x18, 0xec, 0x1b, 0x2c, 0x80, 0xf7, 0x74, 0xe7, 0xff, 0x21,
    0x5a, 0x6a, 0x54, 0x1e, 0x41, 0x31, 0x92, 0x35, 0xc4, 0x33, 0x07, 0x0a, 0xba, 0x7e, 0x0e, 0x34,
    0x88, 0xb1, 0x98, 0x7c, 0xf3, 0x3d, 0x60, 0x6c, 0x7b, 0xca, 0xd3, 0x1f, 0x32, 0x65, 0x04, 0x28,
    0x64, 0xbe, 0x85, 0x9b, 0x2f, 0x59, 0x8a, 0xd7, 0xb0, 0x25, 0xac, 0xaf, 0x12, 0x03, 0xe2, 0xf2,
};

pub const ZUC = struct {
    // State registers
    lfsr: [16]u32,  // 31-bit LFSR registers
    r1: u32,        // F register R1
    r2: u32,        // F register R2

    // Constants from C implementation
    const KD = [16]u16{
        0x44D7, 0x26BC, 0x626B, 0x135E, 0x5789, 0x35E2, 0x7135, 0x09AF,
        0x4D78, 0x2F13, 0x6BC4, 0x1AF1, 0x5E26, 0x3C4D, 0x789A, 0x47AC,
    };

    /// Initialize ZUC with key and IV (ZUC-128)
    pub fn init(key: *const [16]u8, iv: *const [16]u8) ZUC {
        var self = ZUC{
            .lfsr = undefined,
            .r1 = 0,
            .r2 = 0,
        };

        // Initialize LFSR
        for (0..16) |i| {
            self.lfsr[i] = (@as(u32, key[i]) << 23) | (@as(u32, KD[i]) << 8) | @as(u32, iv[i]);
        }

        var r1: u32 = 0;
        var r2: u32 = 0;
        var x0: u32 = undefined;
        var x1: u32 = undefined;
        var x2: u32 = undefined;

        // 32 initialization rounds
        for (0..32) |_| {
            bitReconstruction3(&self.lfsr, &x0, &x1, &x2);
            const w = f(x0, x1, x2, &r1, &r2);
            lfsrWithInitialisationMode(&self.lfsr, w >> 1);
        }

        bitReconstruction2(&self.lfsr, &x1, &x2);
        f_(x1, x2, &r1, &r2);
        lfsrWithWorkMode(&self.lfsr);

        self.r1 = r1;
        self.r2 = r2;

        return self;
    }

    /// Generate a single keystream word
    pub fn generateKeyword(self: *ZUC) u32 {
        var x0: u32 = undefined;
        var x1: u32 = undefined;
        var x2: u32 = undefined;
        var x3: u32 = undefined;

        bitReconstruction4(&self.lfsr, &x0, &x1, &x2, &x3);
        const z = x3 ^ f(x0, x1, x2, &self.r1, &self.r2);
        lfsrWithWorkMode(&self.lfsr);

        return z;
    }

    /// Generate keystream
    pub fn generateKeystream(self: *ZUC, keystream: []u32) void {
        for (0..keystream.len) |i| {
            keystream[i] = self.generateKeyword();
        }
    }

    /// Encrypt/decrypt data
    pub fn crypt(self: *ZUC, input: []const u8, output: []u8) void {
        std.debug.assert(input.len == output.len);

        const num_words = (input.len + 3) / 4;
        const keystream = std.heap.page_allocator.alloc(u32, num_words) catch unreachable;
        defer std.heap.page_allocator.free(keystream);

        self.generateKeystream(keystream);

        for (input, 0..) |byte, i| {
            const word_idx = i / 4;
            const byte_pos = 3 - (i % 4);
            const shift_amt = @as(u5, @intCast(byte_pos)) * 8;
            const key_byte = @as(u8, @truncate(keystream[word_idx] >> shift_amt));
            output[i] = byte ^ key_byte;
        }
    }
};

// Helper functions

fn makeU32(a: u8, b: u8, c: u8, d: u8) u32 {
    return (@as(u32, a) << 24) | (@as(u32, b) << 16) | (@as(u32, c) << 8) | @as(u32, d);
}

fn rot31(a: u32, k: u5) u32 {
    return ((a << k) | (a >> (31 - k))) & 0x7FFFFFFF;
}

fn l1(x: u32) u32 {
    return x ^ math.rotl(u32, x, 2) ^ math.rotl(u32, x, 10) ^
           math.rotl(u32, x, 18) ^ math.rotl(u32, x, 24);
}

fn l2(x: u32) u32 {
    return x ^ math.rotl(u32, x, 8) ^ math.rotl(u32, x, 14) ^
           math.rotl(u32, x, 22) ^ math.rotl(u32, x, 30);
}

// 确保比特重组完全匹配C代码
fn bitReconstruction2(lfsr: *const [16]u32, x1: *u32, x2: *u32) void {
    x1.* = ((lfsr[11] & 0xFFFF) << 16) | (lfsr[9] >> 15);
    x2.* = ((lfsr[7] & 0xFFFF) << 16) | (lfsr[5] >> 15);
}

fn bitReconstruction3(lfsr: *const [16]u32, x0: *u32, x1: *u32, x2: *u32) void {
    x0.* = ((lfsr[15] & 0x7FFF8000) << 1) | (lfsr[14] & 0xFFFF);
    bitReconstruction2(lfsr, x1, x2);
}

fn bitReconstruction4(lfsr: *const [16]u32, x0: *u32, x1: *u32, x2: *u32, x3: *u32) void {
    bitReconstruction3(lfsr, x0, x1, x2);
    x3.* = ((lfsr[2] & 0xFFFF) << 16) | (lfsr[0] >> 15);
}

fn f_(x1: u32, x2: u32, r1: *u32, r2: *u32) void {
    const w1 = r1.* +% x1;
    const w2 = r2.* ^ x2;
    const u = l1((w1 << 16) | (w2 >> 16));
    const v = l2((w2 << 16) | (w1 >> 16));

    r1.* = makeU32(
        S0[u >> 24],
        S1[(u >> 16) & 0xFF],
        S0[(u >> 8) & 0xFF],
        S1[u & 0xFF],
    );

    r2.* = makeU32(
        S0[v >> 24],
        S1[(v >> 16) & 0xFF],
        S0[(v >> 8) & 0xFF],
        S1[v & 0xFF],
    );
}

fn f(x0: u32, x1: u32, x2: u32, r1: *u32, r2: *u32) u32 {
    const w = (x0 ^ r1.*) +% r2.*;
    f_(x1, x2, r1, r2);
    return w;
}

// 修正的LFSR初始化模式
fn lfsrWithInitialisationMode(lfsr: *[16]u32, u: u32) void {
    var v = lfsr[0];

    // 使用与C代码相同的顺序和操作
    v = add31(v, rot31(lfsr[0], 8));
    v = add31(v, rot31(lfsr[4], 20));
    v = add31(v, rot31(lfsr[10], 21));
    v = add31(v, rot31(lfsr[13], 17));
    v = add31(v, rot31(lfsr[15], 15));
    v = add31(v, u);

    // 移位寄存器
    for (0..15) |j| {
        lfsr[j] = lfsr[j + 1];
    }
    lfsr[15] = v;
}

fn lfsrWithWorkMode(lfsr: *[16]u32) void {
    var a: u64 = lfsr[0];

    a += (@as(u64, lfsr[0]) << 8);
    a += (@as(u64, lfsr[4]) << 20);
    a += (@as(u64, lfsr[10]) << 21);
    a += (@as(u64, lfsr[13]) << 17);
    a += (@as(u64, lfsr[15]) << 15);

    // 第一次模约简
    a = (a & 0x7FFFFFFF) + (a >> 31);
    // 第二次模约简，直接赋值给32位变量
    const v = @as(u32, @intCast((a & 0x7FFFFFFF) + (a >> 31)));

    for (0..15) |j| {
        lfsr[j] = lfsr[j + 1];
    }
    lfsr[15] = v;
}

// 修正的模2^31-1加法
fn add31(a: u32, b: u32) u32 {
    const sum = a +% b;
    var result = (sum & 0x7FFFFFFF) +% (sum >> 31);
    // 如果结果 >= 2^31-1，需要减去 2^31-1
    if (result >= 0x7FFFFFFF) {
        result -= 0x7FFFFFFF;
    }
    return result;
}

const testing = std.testing;

// 标准测试向量
test "ZUC-128 standard test vector 1" {
    const key = [_]u8{0x00} ** 16;
    const iv = [_]u8{0x00} ** 16;

    var zuc = ZUC.init(&key, &iv);
    var keystream: [10]u32 = undefined;
    zuc.generateKeystream(&keystream);

    const expected = [_]u32{
        0x27BEDE74, 0x018082DA, 0x87D4E5B6, 0x9F18BF66,
        0x32070E0F, 0x39B7B692, 0xB4673EDC, 0x3184A48E,
        0x27636F44, 0x14510D62
    };

    for (keystream, expected) |got, exp| {
        try testing.expectEqual(exp, got);
    }
}

test "ZUC-128 standard test vector 2" {
    const key = [_]u8{0xff} ** 16;
    const iv = [_]u8{0xff} ** 16;

    var zuc = ZUC.init(&key, &iv);
    var keystream: [10]u32 = undefined;
    zuc.generateKeystream(&keystream);

    const expected = [_]u32{
        0x0657CFA0, 0x7096398B, 0x734B6CB4, 0x883EEDF4,
        0x257A76EB, 0x97595208, 0xD884ADCD, 0xB1CBFFB8,
        0xE0F9D158, 0x46A0EED0
    };

    for (keystream, expected) |got, exp| {
        try testing.expectEqual(exp, got);
    }
}

test "ZUC-128 standard test vector 3" {
    const key = [_]u8{
        0x3d, 0x4c, 0x4b, 0xe9, 0x6a, 0x82, 0xfd, 0xae,
        0xb5, 0x8f, 0x64, 0x1d, 0xb1, 0x7b, 0x45, 0x5b,
    };
    const iv = [_]u8{
        0x84, 0x31, 0x9a, 0xa8, 0xde, 0x69, 0x15, 0xca,
        0x1f, 0x6b, 0xda, 0x6b, 0xfb, 0xd8, 0xc7, 0x66,
    };

    var zuc = ZUC.init(&key, &iv);
    var keystream: [10]u32 = undefined;
    zuc.generateKeystream(&keystream);

    const expected = [_]u32{
        0x14f1c272,0x3279c419,0x4b8ea41d,0x0cc80863,
        0xd28062e1,0xe71d3dda,0xe3c4d158,0xa7f067ac,
        0x94935056,0x8ee5c63d
    };

    for (keystream, expected) |got, exp| {
        try testing.expectEqual(exp, got);
    }
}

// 加解密一致性测试
test "ZUC encryption/decryption" {
    const key = [_]u8{0x11} ** 16;
    const iv = [_]u8{0x22} ** 16;

    const plaintext = "Hello, ZUC!";
    var ciphertext: [plaintext.len]u8 = undefined;
    var decrypted: [plaintext.len]u8 = undefined;

    var zuc1 = ZUC.init(&key, &iv);
    zuc1.crypt(plaintext, &ciphertext);

    var zuc2 = ZUC.init(&key, &iv);
    zuc2.crypt(&ciphertext, &decrypted);

    try testing.expectEqualSlices(u8, plaintext, &decrypted);
}

// 空输入测试
test "ZUC empty input" {
    const key = [_]u8{0x77} ** 16;
    const iv = [_]u8{0x88} ** 16;

    var zuc = ZUC.init(&key, &iv);
    var output: [0]u8 = undefined;

    zuc.crypt(&[_]u8{}, &output);
    try testing.expect(true);
}

// 不同密钥/IV输出不同
test "ZUC different keys produce different keystreams" {
    const key1 = [_]u8{0x01} ** 16;
    const key2 = [_]u8{0x02} ** 16;
    const iv = [_]u8{0x00} ** 16;

    var zuc1 = ZUC.init(&key1, &iv);
    var zuc2 = ZUC.init(&key2, &iv);

    var ks1: [4]u32 = undefined;
    var ks2: [4]u32 = undefined;

    zuc1.generateKeystream(&ks1);
    zuc2.generateKeystream(&ks2);

    var different = false;
    for (ks1, ks2) |a, b| {
        if (a != b) {
            different = true;
            break;
        }
    }
    try testing.expect(different);
}

test "ZUC different IVs produce different keystreams" {
    const key = [_]u8{0x00} ** 16;
    const iv1 = [_]u8{0x01} ** 16;
    const iv2 = [_]u8{0x02} ** 16;

    var zuc1 = ZUC.init(&key, &iv1);
    var zuc2 = ZUC.init(&key, &iv2);

    var ks1: [4]u32 = undefined;
    var ks2: [4]u32 = undefined;

    zuc1.generateKeystream(&ks1);
    zuc2.generateKeystream(&ks2);

    var different = false;
    for (ks1, ks2) |a, b| {
        if (a != b) {
            different = true;
            break;
        }
    }
    try testing.expect(different);
}

test "ZUC same key and IV produce same keystream" {
    const key = [_]u8{0x12} ** 16;
    const iv = [_]u8{0x34} ** 16;

    var zuc1 = ZUC.init(&key, &iv);
    var zuc2 = ZUC.init(&key, &iv);

    var ks1: [8]u32 = undefined;
    var ks2: [8]u32 = undefined;

    zuc1.generateKeystream(&ks1);
    zuc2.generateKeystream(&ks2);

    for (ks1, ks2) |a, b| {
        try testing.expectEqual(a, b);
    }
}

test "ZUC encryption/decryption with 1 byte" {
    const key = [_]u8{0x11} ** 16;
    const iv = [_]u8{0x22} ** 16;

    const plaintext = [_]u8{0xAA};
    var ciphertext: [1]u8 = undefined;
    var decrypted: [1]u8 = undefined;

    var zuc1 = ZUC.init(&key, &iv);
    zuc1.crypt(&plaintext, &ciphertext);

    var zuc2 = ZUC.init(&key, &iv);
    zuc2.crypt(&ciphertext, &decrypted);

    try testing.expectEqualSlices(u8, &plaintext, &decrypted);
}

test "ZUC encryption/decryption with 3 bytes" {
    const key = [_]u8{0x33} ** 16;
    const iv = [_]u8{0x44} ** 16;

    const plaintext = [_]u8{0x01, 0x02, 0x03};
    var ciphertext: [3]u8 = undefined;
    var decrypted: [3]u8 = undefined;

    var zuc1 = ZUC.init(&key, &iv);
    zuc1.crypt(&plaintext, &ciphertext);

    var zuc2 = ZUC.init(&key, &iv);
    zuc2.crypt(&ciphertext, &decrypted);

    try testing.expectEqualSlices(u8, &plaintext, &decrypted);
}

test "ZUC encryption/decryption with 15 bytes" {
    const key = [_]u8{0x55} ** 16;
    const iv = [_]u8{0x66} ** 16;

    const plaintext = "1234567890ABCDE";
    var ciphertext: [15]u8 = undefined;
    var decrypted: [15]u8 = undefined;

    var zuc1 = ZUC.init(&key, &iv);
    zuc1.crypt(plaintext, &ciphertext);

    var zuc2 = ZUC.init(&key, &iv);
    zuc2.crypt(&ciphertext, &decrypted);

    try testing.expectEqualSlices(u8, plaintext, &decrypted);
}

test "ZUC encryption/decryption with 71 bytes" {
    const key = [_]u8{0x77} ** 16;
    const iv = [_]u8{0x88} ** 16;

    const plaintext = "This is a longer test message for ZUC encryption with 71 bytes of data!";
    var ciphertext: [71]u8 = undefined;
    var decrypted: [71]u8 = undefined;

    var zuc1 = ZUC.init(&key, &iv);
    zuc1.crypt(plaintext, &ciphertext);

    var zuc2 = ZUC.init(&key, &iv);
    zuc2.crypt(&ciphertext, &decrypted);

    try testing.expectEqualSlices(u8, plaintext, &decrypted);
}

test "ZUC keystream periodicity check" {
    const key = [_]u8{0xAA} ** 16;
    const iv = [_]u8{0xBB} ** 16;

    var zuc = ZUC.init(&key, &iv);

    // 生成大量密钥流并检查是否有明显的重复模式
    var keystream: [1000]u32 = undefined;
    zuc.generateKeystream(&keystream);

    // 简单检查：确保不是全0或全相同
    var all_zero = true;
    var all_same = true;
    const first = keystream[0];

    for (keystream) |word| {
        if (word != 0) all_zero = false;
        if (word != first) all_same = false;
        if (!all_zero and !all_same) break;
    }

    try testing.expect(!all_zero);
    try testing.expect(!all_same);
}

test "ZUC generateKeyword consistency" {
    const key = [_]u8{0x11} ** 16;
    const iv = [_]u8{0x22} ** 16;

    var zuc1 = ZUC.init(&key, &iv);
    var zuc2 = ZUC.init(&key, &iv);

    // generateKeyword 应该与 generateKeystream 产生相同的结果
    const word1 = zuc1.generateKeyword();
    const word2 = zuc1.generateKeyword();

    var keystream: [2]u32 = undefined;
    zuc2.generateKeystream(&keystream);

    try testing.expectEqual(word1, keystream[0]);
    try testing.expectEqual(word2, keystream[1]);
}

test "ZUC state persistence" {
    const key = [_]u8{0x99} ** 16;
    const iv = [_]u8{0x88} ** 16;

    var zuc = ZUC.init(&key, &iv);

    // 多次生成密钥流，状态应该持续更新
    var ks1: [2]u32 = undefined;
    var ks2: [2]u32 = undefined;
    var ks3: [2]u32 = undefined;

    zuc.generateKeystream(&ks1);
    zuc.generateKeystream(&ks2);
    zuc.generateKeystream(&ks3);

    // 检查是否产生了不同的密钥流（状态在更新）
    var different = false;
    for (ks1, ks2) |a, b| {
        if (a != b) {
            different = true;
            break;
        }
    }
    try testing.expect(different);
}

test "ZUC bit patterns" {
    // 测试特殊位模式
    const key = [_]u8{
        0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF,
        0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF,
    };
    const iv = [_]u8{
        0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00,
        0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00,
    };

    var zuc = ZUC.init(&key, &iv);
    var keystream: [4]u32 = undefined;
    zuc.generateKeystream(&keystream);

    // 确保产生了非零输出
    var has_non_zero = false;
    for (keystream) |word| {
        if (word != 0) {
            has_non_zero = true;
            break;
        }
    }
    try testing.expect(has_non_zero);
}

test "ZUC multiple init calls" {
    const key1 = [_]u8{0x11} ** 16;
    const iv1 = [_]u8{0x22} ** 16;
    const key2 = [_]u8{0x33} ** 16;
    const iv2 = [_]u8{0x44} ** 16;

    var zuc = ZUC.init(&key1, &iv1);
    var ks1: [2]u32 = undefined;
    zuc.generateKeystream(&ks1);

    // 重新初始化应该重置状态
    zuc = ZUC.init(&key2, &iv2);
    var ks2: [2]u32 = undefined;
    zuc.generateKeystream(&ks2);

    // 不同密钥应该产生不同密钥流
    var different = false;
    for (ks1, ks2) |a, b| {
        if (a != b) {
            different = true;
            break;
        }
    }
    try testing.expect(different);
}

test "ZUC large keystream generation" {
    const key = [_]u8{0x55} ** 16;
    const iv = [_]u8{0x66} ** 16;

    var zuc = ZUC.init(&key, &iv);

    // 生成大量密钥流（不应该崩溃）
    var keystream: [10000]u32 = undefined;
    zuc.generateKeystream(&keystream);

    // 简单检查：确保产生了非零输出
    var has_non_zero = false;
    for (keystream[0..100]) |word| { // 只检查前100个
        if (word != 0) {
            has_non_zero = true;
            break;
        }
    }
    try testing.expect(has_non_zero);
}

// 性能测试（可选）
test "ZUC performance" {
    const key = [_]u8{0x77} ** 16;
    const iv = [_]u8{0x88} ** 16;

    var zuc = ZUC.init(&key, &iv);

    const iterations = 1000;
    var total_bytes: u64 = 0;

    const start_time = std.time.milliTimestamp();

    for (0..iterations) |_| {
        var keystream: [64]u32 = undefined; // 256 bytes per iteration
        zuc.generateKeystream(&keystream);
        total_bytes += keystream.len * 4;
    }

    const end_time = std.time.milliTimestamp();
    const elapsed_ms = @as(f64, @floatFromInt(end_time - start_time));

    const mbps = (@as(f64, @floatFromInt(total_bytes)) / (1024 * 1024)) / (elapsed_ms / 1000);

    std.debug.print("\nZUC Performance: {d:.2} MB/s ({d} bytes in {d} ms)\n", .{
        mbps, total_bytes, elapsed_ms
    });

    // 性能测试不失败，只是输出信息
    try testing.expect(true);
}

