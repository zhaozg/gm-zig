const std = @import("std");
const testing = std.testing;
const mem = std.mem;
const math = std.math;
const fmt = std.fmt;

/// The SM3 function is now considered cryptographically broken.
/// Namely, it is trivial to find multiple inputs producing the same hash.
pub const SM3 = struct {
    const Self = @This();

    pub const block_length = 64;
    pub const digest_length = 32;
    pub const Options = struct {};

    const sbox = [_]u32{
        0x79cc4519, 0xf3988a32, 0xe7311465, 0xce6228cb, 0x9cc45197, 0x3988a32f, 0x7311465e, 0xe6228cbc,
        0xcc451979, 0x988a32f3, 0x311465e7, 0x6228cbce, 0xc451979c, 0x88a32f39, 0x11465e73, 0x228cbce6,
        0x9d8a7a87, 0x3b14f50f, 0x7629ea1e, 0xec53d43c, 0xd8a7a879, 0xb14f50f3, 0x629ea1e7, 0xc53d43ce,
        0x8a7a879d, 0x14f50f3b, 0x29ea1e76, 0x53d43cec, 0xa7a879d8, 0x4f50f3b1, 0x9ea1e762, 0x3d43cec5,
        0x7a879d8a, 0xf50f3b14, 0xea1e7629, 0xd43cec53, 0xa879d8a7, 0x50f3b14f, 0xa1e7629e, 0x43cec53d,
        0x879d8a7a, 0x0f3b14f5, 0x1e7629ea, 0x3cec53d4, 0x79d8a7a8, 0xf3b14f50, 0xe7629ea1, 0xcec53d43,
        0x9d8a7a87, 0x3b14f50f, 0x7629ea1e, 0xec53d43c, 0xd8a7a879, 0xb14f50f3, 0x629ea1e7, 0xc53d43ce,
        0x8a7a879d, 0x14f50f3b, 0x29ea1e76, 0x53d43cec, 0xa7a879d8, 0x4f50f3b1, 0x9ea1e762, 0x3d43cec5,
    };

    s: [8]u32,
    // Streaming Cache
    buf: [64]u8,
    buf_len: u8,
    total_len: u64,

    pub fn init(options: Options) Self {
        _ = options;
        return Self{
            .s = [_]u32{
                0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
                0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e,
            },
            .buf = undefined,
            .buf_len = 0,
            .total_len = 0,
        };
    }

    pub fn hash(b: []const u8, out: *[digest_length]u8, options: Options) void {
        var d = SM3.init(options);
        d.update(b);
        d.final(out);
    }

    pub fn update(d: *Self, b: []const u8) void {
        var off: usize = 0;

        // Partial buffer exists from previous update. Copy into buffer then hash.
        if (d.buf_len != 0 and d.buf_len + b.len >= 64) {
            off += 64 - d.buf_len;
            @memcpy(d.buf[d.buf_len..][0..off], b[0..off]);

            d.round(&d.buf);
            d.buf_len = 0;
        }

        // Full middle blocks.
        while (off + 64 <= b.len) : (off += 64) {
            d.round(b[off..][0..64]);
        }

        // Copy any remainder for next pass.
        const b_slice = b[off..];
        @memcpy(d.buf[d.buf_len..][0..b_slice.len], b_slice);
        d.buf_len += @as(u8, @intCast(b_slice.len));

        // SM3 uses the bottom 16-bits for length padding
        d.total_len +%= b.len;
    }

    pub fn final(d: *Self, out: *[digest_length]u8) void {
        // The buffer here will never be completely full.
        @memset(d.buf[d.buf_len..], 0);

        // Append padding bits.
        d.buf[d.buf_len] = 0x80;

        // > 448 mod 512 so need to add an extra round to wrap around.
        if (block_length - d.buf_len < 9) {
            d.round(d.buf[0..]);
            @memset(d.buf[0..], 0);
        }

        const bcount: u64 = d.total_len / block_length;

        const len = @as(u32, @intCast(bcount >> 23));
        mem.writeInt(u32, d.buf[56..][0..4], len, .big);

        const nx = @as(u64, @intCast(d.buf_len)) << 3;
        const len2 = @as(u32, @intCast((bcount << 9) + nx));
        mem.writeInt(u32, d.buf[60..][0..4], len2, .big);

        d.round(d.buf[0..]);

        for (d.s, 0..) |s, j| {
            mem.writeInt(u32, out[4 * j ..][0..4], s, .big);
        }
    }

    pub fn finalResult(d: *Self) [digest_length]u8 {
        var result: [digest_length]u8 = undefined;
        d.final(&result);
        return result;
    }

    fn round(d: *Self, b: *const [64]u8) void {
        var a: [8]u32 = undefined;
        var w: [68]u32 = undefined;

        var ss1: u32 = undefined;
        var ss2: u32 = undefined;
        var tt1: u32 = undefined;
        var tt2: u32 = undefined;

        var i: usize = 0;
        while (i < 4) : (i += 1) {
            w[i] = mem.readInt(u32, b[i * 4 ..][0..4], .big);
        }

        i = 0;
        while (i < 8) : (i += 1) {
            a[i] = d.s[i];
        }

        i = 0;
        while (i < 12) : (i += 1) {
            w[i + 4] = mem.readInt(u32, b[(i + 4) * 4 ..][0..4], .big);

            tt2 = rotateLeft32(a[0], 12);
            ss1 = rotateLeft32(tt2 +% a[4] +% sbox[i], 7);
            ss2 = ss1 ^ tt2;
            tt1 = (a[0] ^ a[1] ^ a[2]) +% a[3] +% ss2 +% (w[i] ^ w[i + 4]);
            tt2 = (a[4] ^ a[5] ^ a[6]) +% a[7] +% ss1 +% w[i];

            a[3] = a[2];
            a[2] = rotateLeft32(a[1], 9);
            a[1] = a[0];
            a[0] = tt1;
            a[7] = a[6];
            a[6] = rotateLeft32(a[5], 19);
            a[5] = a[4];
            a[4] = p0(tt2);
        }

        i = 12;
        while (i < 16) : (i += 1) {
            w[i + 4] = p1(w[i - 12] ^ w[i - 5] ^ rotateLeft32(w[i + 1], 15)) ^ rotateLeft32(w[i - 9], 7) ^ w[i - 2];
            tt2 = rotateLeft32(a[0], 12);
            ss1 = rotateLeft32(tt2 +% a[4] +% sbox[i], 7);
            ss2 = ss1 ^ tt2;
            tt1 = (a[0] ^ a[1] ^ a[2]) +% a[3] +% ss2 +% (w[i] ^ w[i + 4]);
            tt2 = (a[4] ^ a[5] ^ a[6]) +% a[7] +% ss1 +% w[i];

            a[3] = a[2];
            a[2] = rotateLeft32(a[1], 9);
            a[1] = a[0];
            a[0] = tt1;
            a[7] = a[6];
            a[6] = rotateLeft32(a[5], 19);
            a[5] = a[4];
            a[4] = p0(tt2);
        }

        i = 16;
        while (i < 64) : (i += 1) {
            w[i + 4] = p1(w[i - 12] ^ w[i - 5] ^ rotateLeft32(w[i + 1], 15)) ^ rotateLeft32(w[i - 9], 7) ^ w[i - 2];
            tt2 = rotateLeft32(a[0], 12);
            ss1 = rotateLeft32(tt2 +% a[4] +% sbox[i], 7);
            ss2 = ss1 ^ tt2;
            tt1 = ff(a[0], a[1], a[2]) +% a[3] +% ss2 +% (w[i] ^ w[i + 4]);
            tt2 = gg(a[4], a[5], a[6]) +% a[7] +% ss1 +% w[i];

            a[3] = a[2];
            a[2] = rotateLeft32(a[1], 9);
            a[1] = a[0];
            a[0] = tt1;
            a[7] = a[6];
            a[6] = rotateLeft32(a[5], 19);
            a[5] = a[4];
            a[4] = p0(tt2);
        }

        i = 0;
        while (i < 8) : (i += 1) {
            d.s[i] ^= a[i];
        }
    }

    fn rotateLeft32(x: u32, k: usize) u32 {
        return math.rotl(u32, x, k);
    }

    fn p0(x: u32) u32 {
        return x ^ rotateLeft32(x, 9) ^ rotateLeft32(x, 17);
    }

    fn p1(x: u32) u32 {
        return x ^ rotateLeft32(x, 15) ^ rotateLeft32(x, 23);
    }

    fn ff(x: u32, y: u32, z: u32) u32 {
        return (x & y) | (x & z) | (y & z);
    }

    fn gg(x: u32, y: u32, z: u32) u32 {
        return ((y ^ z) & x) ^ z;
    }

    pub const Error = error{};
    pub const Writer = std.io.Writer(*Self, Error, write);

    fn write(self: *Self, bytes: []const u8) Error!usize {
        self.update(bytes);
        return bytes.len;
    }

    pub fn writer(self: *Self) Writer {
        return .{ .context = self };
    }

};

// Hash using the specified hasher `H` asserting `expected == H(input)`.
pub fn assertEqualHash(comptime Hasher: anytype, comptime expected_hex: *const [Hasher.digest_length * 2:0]u8, input: []const u8) !void {
    var h: [Hasher.digest_length]u8 = undefined;
    Hasher.hash(input, &h, .{});

    try assertEqual(expected_hex, &h);
}

// Assert `expected` == hex(`input`) where `input` is a bytestring
pub fn assertEqual(comptime expected_hex: [:0]const u8, input: []const u8) !void {
    var expected_bytes: [expected_hex.len / 2]u8 = undefined;
    for (&expected_bytes, 0..) |*r, i| {
        r.* = fmt.parseInt(u8, expected_hex[2 * i .. 2 * i + 2], 16) catch unreachable;
    }

    try testing.expectEqualSlices(u8, &expected_bytes, input);
}

test "single" {
    try assertEqualHash(SM3, "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b", "");
    try assertEqualHash(SM3, "623476ac18f65a2909e43c7fec61b49c7e764a91a18ccb82f1917a29c86c5e88", "a");
    try assertEqualHash(SM3, "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0", "abc");
    try assertEqualHash(SM3, "c522a942e89bd80d97dd666e7a5531b36188c9817149e9b258dfe51ece98ed77", "message digest");
    try assertEqualHash(SM3, "b80fe97a4da24afc277564f66a359ef440462ad28dcc6d63adb24d5c20a61595", "abcdefghijklmnopqrstuvwxyz");
    try assertEqualHash(SM3, "2971d10c8842b70c979e55063480c50bacffd90e98e2e60d2512ab8abfdfcec5", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
    try assertEqualHash(SM3, "ad81805321f3e69d251235bf886a564844873b56dd7dde400f055b7dde39307a", "12345678901234567890123456789012345678901234567890123456789012345678901234567890");
}

test "streaming" {
    var out: [32]u8 = undefined;

    var h = SM3.init(.{});
    h.final(out[0..]);
    try assertEqual("1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b", out[0..]);

    h = SM3.init(.{});
    h.update("abc");
    h.final(out[0..]);
    try assertEqual("66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0", out[0..]);

    h = SM3.init(.{});
    h.update("a");
    h.update("b");
    h.update("c");
    h.final(out[0..]);

    try assertEqual("66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0", out[0..]);
}

test "finalResult" {
    var h = SM3.init(.{});
    var out = h.finalResult();
    try assertEqual("1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b", out[0..]);

    h = SM3.init(.{});
    h.update("abc");
    out = h.finalResult();
    try assertEqual("66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0", out[0..]);
}

test "writer" {
    var h = SM3.init(.{});
    try h.writer().print("{s}", .{"abc"});
    const out = h.finalResult();
    try assertEqual("66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0", out[0..]);
}

test "aligned final" {
    var block = [_]u8{0} ** SM3.block_length;
    var out: [SM3.digest_length]u8 = undefined;

    var h = SM3.init(.{});
    h.update(&block);
    h.final(out[0..]);
}

// 性能测试函数
pub fn testPerformance(allocator: std.mem.Allocator) !void {
    const test_sizes = [_]usize{
        1024,      // 64 blocks
        1024 * 16, // 1KB
        1024 * 1024, // 1MB
        10 * 1024 * 1024, // 10MB
    };

    const print = std.debug.print;

    print("\nSM3 Performance Test (ReleaseSafe build recommended)\n", .{});
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
        var out: [32]u8 = undefined;

        // 加密性能测试
        const hash_start = std.time.nanoTimestamp();
        SM3.hash(buffer, &out, .{});
        const hash_time = @as(f64, @floatFromInt(std.time.nanoTimestamp() - hash_start));

        // 计算速度 (MB/s)
        const bytes_per_mb = 1024.0 * 1024.0;
        const ns_per_s = 1_000_000_000.0;
        const hash_speed = (@as(f64, @floatFromInt(size)) / hash_time) * ns_per_s / bytes_per_mb;

        print("Data: {d:>6.2} KB | Digest: {d:>6.2} MB/s\n", .{
            size / 1024,
            hash_speed,
        });
    }
}

// 主测试函数
test "SM3 Performance" {
    const allocator = std.testing.allocator;
    try testPerformance(allocator);
}
