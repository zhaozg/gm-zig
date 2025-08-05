const std = @import("std");
const testing = std.testing;
const mem = std.mem;
const math = std.math;
const fmt = std.fmt;
const builtin = @import("builtin");
const simd = std.simd;

/// 优化的SM3哈希算法实现
pub const SM3 = struct {
    const Self = @This();

    pub const block_length = 64;
    pub const digest_length = 32;
    pub const Options = struct {};

    // 使用编译期计算的常量表
    const T = initT();
    fn initT() [64]u32 {
        var table: [64]u32 = undefined;
        inline for (0..16) |i| {
            table[i] = 0x79CC4519;
        }
        inline for (16..64) |i| {
            table[i] = 0x7A879D8A;
        }
        return table;
    }

    s: [8]u32,
    buf: [block_length]u8 align(16), // 16字节对齐内存访问
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
        d.total_len +%= b.len;
        var off: usize = 0;
        const buf = &d.buf;
        var buf_len = d.buf_len;

        // 处理缓冲区中已有的部分数据
        if (buf_len != 0 and buf_len + b.len >= block_length) {
            off = block_length - buf_len;
            @memcpy(buf[buf_len..][0..off], b[0..off]);
            d.compress(buf);
            buf_len = 0;
        }

        // 处理完整块
        const main_blocks = (b.len - off) / block_length;
        const main_end = off + main_blocks * block_length;
        while (off < main_end) : (off += block_length) {
            d.compress(b[off..][0..block_length]);
        }

        // 保存剩余数据
        const remain = b[off..];
        if (remain.len > 0) {
            @memcpy(buf[buf_len..][0..remain.len], remain);
            buf_len += @as(u8, @intCast(remain.len));
        }

        d.buf_len = buf_len;
    }

    pub fn final(d: *Self, out: *[digest_length]u8) void {
        var buf = d.buf;
        var buf_len = d.buf_len;
        const total_bits = d.total_len * 8;

        // 添加填充
        @memset(buf[buf_len..], 0);
        buf[buf_len] = 0x80;
        buf_len += 1;

        // 处理需要额外块的情况
        if (block_length - buf_len < 8) {
            d.compress(&buf);
            @memset(buf[0..], 0);
            buf_len = 0;
        }

        // 写入长度信息
        mem.writeInt(u64, buf[block_length - 8 ..][0..8], total_bits, .big);
        d.compress(&buf);

        // 输出结果
        for (d.s, 0..) |s, i| {
            mem.writeInt(u32, out[4 * i ..][0..4], s, .big);
        }
    }

    pub fn finalResult(d: *Self) [digest_length]u8 {
        var result: [digest_length]u8 = undefined;
        d.final(&result);
        return result;
    }

    // 优化后的压缩函数
    inline fn compress(d: *Self, block: *const [block_length]u8) void {
        var w: [68]u32 align(16) = undefined; // 对齐内存
        var a: [8]u32 = d.s; // 局部变量优化

        // 加载初始消息字
        simdLoadMessageWords(block, w[0..16]);

        // 展开的消息扩展循环
        comptime var i = 16;
        inline while (i < 68) : (i += 4) {
            w[i] = p1(w[i-16] ^ w[i-9] ^ math.rotl(u32, w[i-3], 15)) ^
                   math.rotl(u32, w[i-13], 7) ^ w[i-6];
            w[i+1] = p1(w[i-15] ^ w[i-8] ^ math.rotl(u32, w[i-2], 15)) ^
                     math.rotl(u32, w[i-12], 7) ^ w[i-5];
            w[i+2] = p1(w[i-14] ^ w[i-7] ^ math.rotl(u32, w[i-1], 15)) ^
                     math.rotl(u32, w[i-11], 7) ^ w[i-4];
            w[i+3] = p1(w[i-13] ^ w[i-6] ^ math.rotl(u32, w[i], 15)) ^
                     math.rotl(u32, w[i-10], 7) ^ w[i-3];
        }

        // 展开的主循环 (4轮一组)
        comptime var j = 0;
        inline while (j < 64) : (j += 4) {
            // 第1轮
            var ss1 = math.rotl(u32, a[0], 12);
            ss1 +%= a[4];
            ss1 +%= T[j];
            ss1 = math.rotl(u32, ss1, 7);
            const ss2 = ss1 ^ math.rotl(u32, a[0], 12);

            var tt1 = if (j < 16) a[0] ^ a[1] ^ a[2] else (a[0] & a[1]) | (a[0] & a[2]) | (a[1] & a[2]);
            tt1 +%= a[3];
            tt1 +%= ss2;
            tt1 +%= (w[j] ^ w[j+4]);

            var tt2 = if (j < 16) a[4] ^ a[5] ^ a[6] else (a[4] & a[5]) | (~a[4] & a[6]);
            tt2 +%= a[7];
            tt2 +%= ss1;
            tt2 +%= w[j];

            // 更新状态
            a[3] = a[2];
            a[2] = math.rotl(u32, a[1], 9);
            a[1] = a[0];
            a[0] = tt1;
            a[7] = a[6];
            a[6] = math.rotl(u32, a[5], 19);
            a[5] = a[4];
            a[4] = p0(tt2);

            // 第2轮 (j+1)
            ss1 = math.rotl(u32, a[0], 12);
            ss1 +%= a[4];
            ss1 +%= T[j+1];
            ss1 = math.rotl(u32, ss1, 7);
            const ss2_1 = ss1 ^ math.rotl(u32, a[0], 12);

            tt1 = if (j+1 < 16) a[0] ^ a[1] ^ a[2] else (a[0] & a[1]) | (a[0] & a[2]) | (a[1] & a[2]);
            tt1 +%= a[3];
            tt1 +%= ss2_1;
            tt1 +%= (w[j+1] ^ w[j+5]);

            tt2 = if (j+1 < 16) a[4] ^ a[5] ^ a[6] else (a[4] & a[5]) | (~a[4] & a[6]);
            tt2 +%= a[7];
            tt2 +%= ss1;
            tt2 +%= w[j+1];

            a[3] = a[2];
            a[2] = math.rotl(u32, a[1], 9);
            a[1] = a[0];
            a[0] = tt1;
            a[7] = a[6];
            a[6] = math.rotl(u32, a[5], 19);
            a[5] = a[4];
            a[4] = p0(tt2);

            // 第3轮 (j+2)
            ss1 = math.rotl(u32, a[0], 12);
            ss1 +%= a[4];
            ss1 +%= T[j+2];
            ss1 = math.rotl(u32, ss1, 7);
            const ss2_2 = ss1 ^ math.rotl(u32, a[0], 12);

            tt1 = if (j+2 < 16) a[0] ^ a[1] ^ a[2] else (a[0] & a[1]) | (a[0] & a[2]) | (a[1] & a[2]);
            tt1 +%= a[3];
            tt1 +%= ss2_2;
            tt1 +%= (w[j+2] ^ w[j+6]);

            tt2 = if (j+2 < 16) a[4] ^ a[5] ^ a[6] else (a[4] & a[5]) | (~a[4] & a[6]);
            tt2 +%= a[7];
            tt2 +%= ss1;
            tt2 +%= w[j+2];

            a[3] = a[2];
            a[2] = math.rotl(u32, a[1], 9);
            a[1] = a[0];
            a[0] = tt1;
            a[7] = a[6];
            a[6] = math.rotl(u32, a[5], 19);
            a[5] = a[4];
            a[4] = p0(tt2);

            // 第4轮 (j+3)
            ss1 = math.rotl(u32, a[0], 12);
            ss1 +%= a[4];
            ss1 +%= T[j+3];
            ss1 = math.rotl(u32, ss1, 7);
            const ss2_3 = ss1 ^ math.rotl(u32, a[0], 12);

            tt1 = if (j+3 < 16) a[0] ^ a[1] ^ a[2] else (a[0] & a[1]) | (a[0] & a[2]) | (a[1] & a[2]);
            tt1 +%= a[3];
            tt1 +%= ss2_3;
            tt1 +%= (w[j+3] ^ w[j+7]);

            tt2 = if (j+3 < 16) a[4] ^ a[5] ^ a[6] else (a[4] & a[5]) | (~a[4] & a[6]);
            tt2 +%= a[7];
            tt2 +%= ss1;
            tt2 +%= w[j+3];

            a[3] = a[2];
            a[2] = math.rotl(u32, a[1], 9);
            a[1] = a[0];
            a[0] = tt1;
            a[7] = a[6];
            a[6] = math.rotl(u32, a[5], 19);
            a[5] = a[4];
            a[4] = p0(tt2);
        }

        // 更新状态
        for (0..8) |k| {
            d.s[k] ^= a[k];
        }
    }

    // 优化内存加载函数
    inline fn simdLoadMessageWords(block: *const [block_length]u8, words: []u32) void {
        // 回退到普通加载
        for (0..16) |i| {
            words[i] = mem.readInt(u32, block[i * 4 ..][0..4], .big);
        }
    }

    // 优化P0函数
    inline fn p0(x: u32) u32 {
        return x ^ math.rotl(u32, x, 9) ^ math.rotl(u32, x, 17);
    }

    // 优化P1函数
    inline fn p1(x: u32) u32 {
        return x ^ math.rotl(u32, x, 15) ^ math.rotl(u32, x, 23);
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

pub fn hash(b: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    var d = SM3.init(.{});
    d.update(b);
    d.final(&out);
    return out;
}

// 测试辅助函数
fn assertEqualHash(comptime Hasher: anytype, comptime expected_hex: *const [Hasher.digest_length * 2:0]u8, input: []const u8) !void {
    var h: [Hasher.digest_length]u8 = undefined;
    Hasher.hash(input, &h, .{});
    try assertEqual(expected_hex, &h);
}

fn assertEqual(comptime expected_hex: [:0]const u8, input: []const u8) !void {
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
    h.final(&out);
    try assertEqual("1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b", &out);

    h = SM3.init(.{});
    h.update("abc");
    h.final(&out);
    try assertEqual("66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0", &out);

    h = SM3.init(.{});
    h.update("a");
    h.update("b");
    h.update("c");
    h.final(&out);
    try assertEqual("66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0", &out);
}

test "finalResult" {
    var h = SM3.init(.{});
    var out = h.finalResult();
    try assertEqual("1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b", &out);

    h = SM3.init(.{});
    h.update("abc");
    out = h.finalResult();
    try assertEqual("66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0", &out);
}

test "writer" {
    var h = SM3.init(.{});
    try h.writer().print("{s}", .{"abc"});
    const out = h.finalResult();
    try assertEqual("66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0", &out);
}

test "aligned final" {
    var block = [_]u8{0} ** SM3.block_length;
    var out: [SM3.digest_length]u8 = undefined;

    var h = SM3.init(.{});
    h.update(&block);
    h.final(&out);
}

fn hashChunk(chunk: []const u8, out: *[32]u8) void {
    SM3.hash(chunk, out, .{});
}

// 优化的性能测试函数
pub fn testPerformance(allocator: std.mem.Allocator) !void {
    const print = std.debug.print;
    const test_sizes = [_]usize{
        64 * 1024,       // 64KB
        1024 * 1024,     // 1MB
        10 * 1024 * 1024, // 10MB
        100 * 1024 * 1024, // 100MB
    };

    print("\nSM3 性能测试 (推荐使用 ReleaseFast 模式编译)\n", .{});
    print("------------------------------------------------\n", .{});

    for (test_sizes) |size| {
        // 分配对齐的内存
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
