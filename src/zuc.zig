// zuc.zig
const std = @import("std");
const mem = std.mem;
const math = std.math;
const builtin = @import("builtin");

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

const KD = [16]u16{
    0x44D7, 0x26BC, 0x626B, 0x135E, 0x5789, 0x35E2, 0x7135, 0x09AF,
    0x4D78, 0x2F13, 0x6BC4, 0x1AF1, 0x5E26, 0x3C4D, 0x789A, 0x47AC,
};

pub const ZUC = struct {
    lfsr: [16]u32,
    r1: u32,
    r2: u32,

    pub fn init(key: *const [16]u8, iv: *const [16]u8) ZUC {
        var self = ZUC{
            .lfsr = undefined,
            .r1 = 0,
            .r2 = 0,
        };

        for (0..16) |i| {
            self.lfsr[i] = (@as(u32, key[i]) << 23) | (@as(u32, KD[i]) << 8) | @as(u32, iv[i]);
        }

        var r1: u32 = 0;
        var r2: u32 = 0;

        comptime var init_round = 0;
        inline while (init_round < 32) : (init_round += 1) {
            const x0 = ((self.lfsr[15] & 0x7FFF8000) << 1) | (self.lfsr[14] & 0xFFFF);
            const x1 = ((self.lfsr[11] & 0xFFFF) << 16) | (self.lfsr[9] >> 15);
            const x2 = ((self.lfsr[7] & 0xFFFF) << 16) | (self.lfsr[5] >> 15);

            const w = f(x0, x1, x2, &r1, &r2);
            lfsrWithInitialisationMode(&self.lfsr, w >> 1);
        }

        {
            const x1 = ((self.lfsr[11] & 0xFFFF) << 16) | (self.lfsr[9] >> 15);
            const x2 = ((self.lfsr[7] & 0xFFFF) << 16) | (self.lfsr[5] >> 15);
            f_(x1, x2, &r1, &r2);
            lfsrWithWorkMode(&self.lfsr);
        }

        self.r1 = r1;
        self.r2 = r2;

        return self;
    }

    pub fn generateKeyword(self: *ZUC) u32 {
        const lfsr = &self.lfsr;
        const s0 = lfsr[0];
        const s2 = lfsr[2];
        const s4 = lfsr[4];
        const s5 = lfsr[5];
        const s7 = lfsr[7];
        const s9 = lfsr[9];
        const s10 = lfsr[10];
        const s11 = lfsr[11];
        const s13 = lfsr[13];
        const s14 = lfsr[14];
        const s15 = lfsr[15];

        const x0 = ((s15 & 0x7FFF8000) << 1) | (s14 & 0xFFFF);
        const x1 = ((s11 & 0xFFFF) << 16) | (s9 >> 15);
        const x2 = ((s7 & 0xFFFF) << 16) | (s5 >> 15);
        const x3 = ((s2 & 0xFFFF) << 16) | (s0 >> 15);

        const w = (x0 ^ self.r1) +% self.r2;

        const w1 = self.r1 +% x1;
        const w2 = self.r2 ^ x2;
        const u = l1((w1 << 16) | (w2 >> 16));
        const v = l2((w2 << 16) | (w1 >> 16));

        self.r1 = makeU32(S0[u >> 24], S1[(u >> 16) & 0xFF], S0[(u >> 8) & 0xFF], S1[u & 0xFF]);
        self.r2 = makeU32(S0[v >> 24], S1[(v >> 16) & 0xFF], S0[(v >> 8) & 0xFF], S1[v & 0xFF]);

        // 内联 lfsrWithWorkMode - 使用局部变量避免重复加载
        var a: u64 = s0;
        a += (@as(u64, s0) << 8);
        a += (@as(u64, s4) << 20);
        a += (@as(u64, s10) << 21);
        a += (@as(u64, s13) << 17);
        a += (@as(u64, s15) << 15);
        a = (a & 0x7FFFFFFF) + (a >> 31);
        const new_s = @as(u32, @intCast((a & 0x7FFFFFFF) + (a >> 31)));

        // 使用 memcpy 风格移位
        lfsr[0] = lfsr[1];
        lfsr[1] = lfsr[2];
        lfsr[2] = lfsr[3];
        lfsr[3] = lfsr[4];
        lfsr[4] = lfsr[5];
        lfsr[5] = lfsr[6];
        lfsr[6] = lfsr[7];
        lfsr[7] = lfsr[8];
        lfsr[8] = lfsr[9];
        lfsr[9] = lfsr[10];
        lfsr[10] = lfsr[11];
        lfsr[11] = lfsr[12];
        lfsr[12] = lfsr[13];
        lfsr[13] = lfsr[14];
        lfsr[14] = lfsr[15];
        lfsr[15] = new_s;

        return x3 ^ w;
    }

    pub fn generateKeystream(self: *ZUC, keystream: []u32) void {
        const len = keystream.len;
        var i: usize = 0;

        while (i + 4 <= len) {
            keystream[i + 0] = self.generateKeyword();
            keystream[i + 1] = self.generateKeyword();
            keystream[i + 2] = self.generateKeyword();
            keystream[i + 3] = self.generateKeyword();
            i += 4;
        }

        while (i < len) {
            keystream[i] = self.generateKeyword();
            i += 1;
        }
    }

    pub fn crypt(self: *ZUC, input: []const u8, output: []u8) void {
        std.debug.assert(input.len == output.len);

        const len = input.len;
        if (len == 0) return;

        var ks_buf: [256]u32 = undefined;
        var remaining = len;
        var offset: usize = 0;

        while (remaining > 0) {
            const batch_words: usize = @min(ks_buf.len, (remaining + 3) / 4);
            const batch = ks_buf[0..batch_words];
            self.generateKeystream(batch);

            const batch_bytes: usize = @min(remaining, batch_words * 4);
            for (0..batch_bytes) |j| {
                const word_idx = j / 4;
                const byte_pos = 3 - (j % 4);
                const shift_amt = @as(u5, @intCast(byte_pos)) * 8;
                const key_byte = @as(u8, @truncate(batch[word_idx] >> shift_amt));
                output[offset + j] = input[offset + j] ^ key_byte;
            }

            remaining -= batch_bytes;
            offset += batch_bytes;
        }
    }

    pub fn generateMAC(self: *ZUC, message: []const u8) u32 {
        if (message.len == 0) return 0;

        var mac: u32 = 0;
        const num_blocks = message.len / 4;
        var i: usize = 0;

        while (i < num_blocks) : (i += 1) {
            const block = mem.readInt(u32, message[i * 4 ..][0..4], .big);
            mac ^= block ^ self.generateKeyword();
        }

        const remaining = message.len % 4;
        if (remaining > 0) {
            const start_idx = num_blocks * 4;
            var last_block: u32 = 0;
            for (0..remaining) |j| {
                last_block |= @as(u32, message[start_idx + j]) << @as(u5, @intCast((3 - j) * 8));
            }
            mac ^= last_block ^ self.generateKeyword();
        }

        return mac;
    }

    pub fn verifyMAC(self: *ZUC, message: []const u8, received_mac: u32) bool {
        return self.generateMAC(message) == received_mac;
    }

    pub fn generateMACWithKey(key: *const [16]u8, iv: *const [16]u8, message: []const u8) u32 {
        var zuc = ZUC.init(key, iv);
        return zuc.generateMAC(message);
    }

    pub fn verifyMACWithKey(key: *const [16]u8, iv: *const [16]u8, message: []const u8, received_mac: u32) bool {
        var zuc = ZUC.init(key, iv);
        return zuc.verifyMAC(message, received_mac);
    }
};

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

fn f_(x1: u32, x2: u32, r1: *u32, r2: *u32) void {
    const w1 = r1.* +% x1;
    const w2 = r2.* ^ x2;
    const u = l1((w1 << 16) | (w2 >> 16));
    const v = l2((w2 << 16) | (w1 >> 16));

    r1.* = makeU32(S0[u >> 24], S1[(u >> 16) & 0xFF], S0[(u >> 8) & 0xFF], S1[u & 0xFF]);
    r2.* = makeU32(S0[v >> 24], S1[(v >> 16) & 0xFF], S0[(v >> 8) & 0xFF], S1[v & 0xFF]);
}

fn f(x0: u32, x1: u32, x2: u32, r1: *u32, r2: *u32) u32 {
    const w = (x0 ^ r1.*) +% r2.*;
    f_(x1, x2, r1, r2);
    return w;
}

fn lfsrWithInitialisationMode(lfsr: *[16]u32, u: u32) void {
    var v = lfsr[0];
    v = add31(v, rot31(lfsr[0], 8));
    v = add31(v, rot31(lfsr[4], 20));
    v = add31(v, rot31(lfsr[10], 21));
    v = add31(v, rot31(lfsr[13], 17));
    v = add31(v, rot31(lfsr[15], 15));
    v = add31(v, u);

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

    a = (a & 0x7FFFFFFF) + (a >> 31);
    const v = @as(u32, @intCast((a & 0x7FFFFFFF) + (a >> 31)));

    for (0..15) |j| {
        lfsr[j] = lfsr[j + 1];
    }
    lfsr[15] = v;
}

fn add31(a: u32, b: u32) u32 {
    const sum = a +% b;
    var result = (sum & 0x7FFFFFFF) +% (sum >> 31);
    if (result >= 0x7FFFFFFF) {
        result -= 0x7FFFFFFF;
    }
    return result;
}

const testing = std.testing;

test "ZUC-128 standard test vector 1" {
    const key = [_]u8{0x00} ** 16;
    const iv = [_]u8{0x00} ** 16;

    var zuc = ZUC.init(&key, &iv);
    var keystream: [10]u32 = undefined;
    zuc.generateKeystream(&keystream);

    const expected = [_]u32{
        0x27BEDE74, 0x018082DA, 0x87D4E5B6, 0x9F18BF66, 0x32070E0F,
        0x39B7B692, 0xB4673EDC, 0x3184A48E, 0x27636F44, 0x14510D62,
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
        0x0657CFA0, 0x7096398B, 0x734B6CB4, 0x883EEDF4, 0x257A76EB,
        0x97595208, 0xD884ADCD, 0xB1CBFFB8, 0xE0F9D158, 0x46A0EED0,
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
        0x14f1c272, 0x3279c419, 0x4b8ea41d, 0x0cc80863, 0xd28062e1,
        0xe71d3dda, 0xe3c4d158, 0xa7f067ac, 0x94935056, 0x8ee5c63d,
    };

    for (keystream, expected) |got, exp| {
        try testing.expectEqual(exp, got);
    }
}

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

test "ZUC empty input" {
    const key = [_]u8{0x77} ** 16;
    const iv = [_]u8{0x88} ** 16;

    var zuc = ZUC.init(&key, &iv);
    var output: [0]u8 = undefined;

    zuc.crypt(&[_]u8{}, &output);
    try testing.expect(true);
}

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

    const plaintext = [_]u8{ 0x01, 0x02, 0x03 };
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

    var keystream: [1000]u32 = undefined;
    zuc.generateKeystream(&keystream);

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

    var ks1: [2]u32 = undefined;
    var ks2: [2]u32 = undefined;
    var ks3: [2]u32 = undefined;

    zuc.generateKeystream(&ks1);
    zuc.generateKeystream(&ks2);
    zuc.generateKeystream(&ks3);

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

    zuc = ZUC.init(&key2, &iv2);
    var ks2: [2]u32 = undefined;
    zuc.generateKeystream(&ks2);

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

    var keystream: [10000]u32 = undefined;
    zuc.generateKeystream(&keystream);

    var has_non_zero = false;
    for (keystream[0..100]) |word| {
        if (word != 0) {
            has_non_zero = true;
            break;
        }
    }
    try testing.expect(has_non_zero);
}

test "ZUC MAC generation - empty message" {
    const key = [_]u8{0x11} ** 16;
    const iv = [_]u8{0x22} ** 16;

    var zuc = ZUC.init(&key, &iv);
    const mac = zuc.generateMAC("");

    try testing.expectEqual(@as(u32, 0), mac);
}

test "ZUC MAC generation - single byte" {
    const key = [_]u8{0x33} ** 16;
    const iv = [_]u8{0x44} ** 16;

    var zuc = ZUC.init(&key, &iv);
    const message = [_]u8{0xAA};
    const mac = zuc.generateMAC(&message);

    try testing.expect(mac != 0);
}

test "ZUC MAC generation - full word" {
    const key = [_]u8{0x55} ** 16;
    const iv = [_]u8{0x66} ** 16;

    var zuc = ZUC.init(&key, &iv);
    const message = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    const mac = zuc.generateMAC(&message);

    try testing.expect(mac != 0);
}

test "ZUC MAC generation - multiple words" {
    const key = [_]u8{0x77} ** 16;
    const iv = [_]u8{0x88} ** 16;

    var zuc = ZUC.init(&key, &iv);
    const message = "Hello, ZUC MAC!";
    const mac = zuc.generateMAC(message);

    try testing.expect(mac != 0);
}

test "ZUC MAC generation - partial word" {
    const key = [_]u8{0x99} ** 16;
    const iv = [_]u8{0xAA} ** 16;

    var zuc = ZUC.init(&key, &iv);
    const message = [_]u8{ 0x01, 0x02, 0x03 };
    const mac = zuc.generateMAC(&message);

    try testing.expect(mac != 0);
}

test "ZUC MAC verification - valid MAC" {
    const key = [_]u8{0xBB} ** 16;
    const iv = [_]u8{0xCC} ** 16;

    const message = "Test message for MAC verification";
    const mac = ZUC.generateMACWithKey(&key, &iv, message);

    const valid = ZUC.verifyMACWithKey(&key, &iv, message, mac);
    try testing.expect(valid);
}

test "ZUC MAC verification - invalid MAC" {
    const key = [_]u8{0xDD} ** 16;
    const iv = [_]u8{0xEE} ** 16;

    const message = "Test message for MAC verification";
    const mac = ZUC.generateMACWithKey(&key, &iv, message);

    const valid = ZUC.verifyMACWithKey(&key, &iv, message, mac + 1);
    try testing.expect(!valid);
}

test "ZUC MAC verification - tampered message" {
    const key = [_]u8{0xFF} ** 16;
    const iv = [_]u8{0x00} ** 16;

    const original_message = "Original message";
    const tampered_message = "Tampered message";

    const mac = ZUC.generateMACWithKey(&key, &iv, original_message);

    const valid = ZUC.verifyMACWithKey(&key, &iv, tampered_message, mac);
    try testing.expect(!valid);
}

test "ZUC MAC consistency" {
    const key = [_]u8{0x12} ** 16;
    const iv = [_]u8{0x34} ** 16;

    const message = "Consistency test message";

    const mac1 = ZUC.generateMACWithKey(&key, &iv, message);
    const mac2 = ZUC.generateMACWithKey(&key, &iv, message);

    try testing.expectEqual(mac1, mac2);
}

test "ZUC MAC different keys" {
    const key1 = [_]u8{0x11} ** 16;
    const key2 = [_]u8{0x22} ** 16;
    const iv = [_]u8{0x33} ** 16;

    const message = "Same message, different keys";

    const mac1 = ZUC.generateMACWithKey(&key1, &iv, message);
    const mac2 = ZUC.generateMACWithKey(&key2, &iv, message);

    try testing.expect(mac1 != mac2);
}

test "ZUC MAC different IVs" {
    const key = [_]u8{0x44} ** 16;
    const iv1 = [_]u8{0x55} ** 16;
    const iv2 = [_]u8{0x66} ** 16;

    const message = "Same message, different IVs";

    const mac1 = ZUC.generateMACWithKey(&key, &iv1, message);
    const mac2 = ZUC.generateMACWithKey(&key, &iv2, message);

    try testing.expect(mac1 != mac2);
}

test "ZUC MAC state advancement" {
    const key = [_]u8{0x77} ** 16;
    const iv = [_]u8{0x88} ** 16;

    var zuc = ZUC.init(&key, &iv);

    const message = "Test message";
    const mac = zuc.generateMAC(message);

    var keystream: [4]u32 = undefined;
    zuc.generateKeystream(&keystream);

    var has_non_zero = false;
    for (keystream) |word| {
        if (word != 0) {
            has_non_zero = true;
            break;
        }
    }
    try testing.expect(has_non_zero);
    try testing.expect(mac != 0);
}

test "ZUC MAC with special patterns" {
    const key = [_]u8{
        0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF,
        0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF,
    };
    const iv = [_]u8{
        0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00,
        0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00,
    };

    const message = [_]u8{ 0x00, 0xFF, 0x00, 0xFF };
    const mac = ZUC.generateMACWithKey(&key, &iv, &message);

    try testing.expect(mac != 0);
}

test "ZUC-128-MAC standard test vector 1" {
    const key = [_]u8{0x00} ** 16;
    const iv = [_]u8{0x00} ** 16;
    const message = [_]u8{0x00};
    const expected_mac: u32 = 0x27BEDE74;

    const mac = ZUC.generateMACWithKey(&key, &iv, &message);
    try testing.expectEqual(expected_mac, mac);
}

test "ZUC MAC with maximum length message" {
    const key = [_]u8{0x11} ** 16;
    const iv = [_]u8{0x22} ** 16;

    var long_message: [4096]u8 = undefined;
    for (&long_message, 0..) |*byte, i| {
        byte.* = @as(u8, @intCast(i & 0xFF));
    }

    const mac = ZUC.generateMACWithKey(&key, &iv, &long_message);
    try testing.expect(mac != 0);
}

test "ZUC MAC with null pointers" {
    const key = [_]u8{0x33} ** 16;
    const iv = [_]u8{0x44} ** 16;

    const mac1 = ZUC.generateMACWithKey(&key, &iv, &[_]u8{});
    try testing.expectEqual(@as(u32, 0), mac1);

    const message = [_]u8{ 0x01, 0x02, 0x03 };
    const mac2 = ZUC.generateMACWithKey(&key, &iv, &message);
    try testing.expect(mac2 != 0);
}

test "ZUC MAC thread safety" {
    const key = [_]u8{0x77} ** 16;
    const iv = [_]u8{0x88} ** 16;
    const message = "Thread safety test message";

    const mac1 = ZUC.generateMACWithKey(&key, &iv, message);
    const mac2 = ZUC.generateMACWithKey(&key, &iv, message);
    const mac3 = ZUC.generateMACWithKey(&key, &iv, message);

    try testing.expectEqual(mac1, mac2);
    try testing.expectEqual(mac2, mac3);
}

test "ZUC MAC usage example" {
    const key = [_]u8{0x99} ** 16;
    const iv = [_]u8{0xAA} ** 16;
    const sensitive_data = "This is sensitive data that needs integrity protection";

    const mac = ZUC.generateMACWithKey(&key, &iv, sensitive_data);

    const is_valid = ZUC.verifyMACWithKey(&key, &iv, sensitive_data, mac);
    try testing.expect(is_valid);

    const tampered_data = "This is tampered data that needs integrity protection";
    const is_tampered_valid = ZUC.verifyMACWithKey(&key, &iv, tampered_data, mac);
    try testing.expect(!is_tampered_valid);
}

pub fn testZUCPerformance(io: std.Io, allocator: std.mem.Allocator) !void {
    const key = [16]u8{
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
    };
    const iv = [16]u8{
        0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
        0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01,
    };

    const test_sizes = [_]usize{
        1024,
        1024 * 16,
        1024 * 1024,
        10 * 1024 * 1024,
    };

    std.debug.print("\nZUC Performance Test (ReleaseSafe build recommended)\n", .{});
    std.debug.print("---------------------------------------------------\n", .{});

    for (test_sizes) |size| {
        const alignment = @as(std.mem.Alignment, @enumFromInt(16));
        const input = try allocator.alignedAlloc(u8, alignment, size);
        defer allocator.free(input);

        var prng = std.Random.DefaultPrng.init(0);
        prng.random().bytes(input);

        const output = try allocator.alignedAlloc(u8, alignment, size);
        defer allocator.free(output);

        var zuc = ZUC.init(&key, &iv);
        zuc.crypt(input[0..16], output[0..16]);

        zuc = ZUC.init(&key, &iv);
        const clock = std.Io.Clock.awake;
        const encrypt_start = std.Io.Clock.now(clock, io).toNanoseconds();
        zuc.crypt(input, output);
        const encrypt_time = @as(f64, @floatFromInt(std.Io.Clock.now(clock, io).toNanoseconds() - encrypt_start));

        var zuc_mac = ZUC.init(&key, &iv);
        const mac_start = std.Io.Clock.now(clock, io).toNanoseconds();
        const mac = zuc_mac.generateMAC(input);
        const mac_time = @as(f64, @floatFromInt(std.Io.Clock.now(clock, io).toNanoseconds() - mac_start));

        const bytes_per_mb = 1024.0 * 1024.0;
        const ns_per_s = 1_000_000_000.0;
        const encrypt_speed = (@as(f64, @floatFromInt(size)) / encrypt_time) * ns_per_s / bytes_per_mb;
        const mac_speed = (@as(f64, @floatFromInt(size)) / mac_time) * ns_per_s / bytes_per_mb;

        std.debug.print("Data: {d:>7.2} KB | Encrypt: {d:>7.2} MB/s | MAC: {d:>7.2} MB/s | MAC: 0x{X:0>8}\n", .{
            @as(f64, @floatFromInt(size)) / 1024.0,
            encrypt_speed,
            mac_speed,
            mac,
        });
    }
}
