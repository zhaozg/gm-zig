const std = @import("std");
const testing = std.testing;
const mem = std.mem;
const math = std.math;
const fmt = std.fmt;

const builtin = @import("builtin");

/// 编译时检测是否为 Zig 0.15 或更新版本
pub const isZig015OrNewer = blk: {
    // Zig 版本号结构: major.minor.patch
    const version = builtin.zig_version;

    // 0.15.0 或更新版本
    break :blk (version.major == 0 and version.minor >= 15);
};

/// SM3哈希算法实现 - 严格按照GM/T 0004-2012标准
pub const SM3 = struct {
    const Self = @This();

    pub const block_length = 64;
    pub const digest_length = 32;
    pub const Options = struct {};

    s: [8]u32,
    buf: [block_length]u8,
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

        // 如果缓冲区有数据且加上新数据能组成完整块
        if (d.buf_len != 0 and d.buf_len + b.len >= block_length) {
            off = block_length - d.buf_len;
            @memcpy(d.buf[d.buf_len..][0..off], b[0..off]);
            d.compress(&d.buf);
            d.buf_len = 0;
        }

        // 处理完整的64字节块
        while (off + block_length <= b.len) {
            d.compress(b[off..][0..block_length]);
            off += block_length;
        }

        // 保存剩余数据到缓冲区
        const remainder = b[off..];
        if (remainder.len > 0) {
            @memcpy(d.buf[d.buf_len..][0..remainder.len], remainder);
            d.buf_len += @as(u8, @intCast(remainder.len));
        }
    }

    pub fn final(d: *Self, out: *[digest_length]u8) void {
        const total_bits = d.total_len * 8;

        // 添加填充位 10000000
        d.buf[d.buf_len] = 0x80;
        d.buf_len += 1;

        // 如果剩余空间不足8字节存放长度，需要新的块
        if (d.buf_len > 56) {
            @memset(d.buf[d.buf_len..], 0);
            d.compress(&d.buf);
            @memset(d.buf[0..56], 0);
        } else {
            @memset(d.buf[d.buf_len..56], 0);
        }

        // 在最后8字节写入消息长度(大端序)
        mem.writeInt(u64, d.buf[56..64], total_bits, .big);
        d.compress(&d.buf);

        // 输出哈希值(大端序)
        for (d.s, 0..) |state, i| {
            mem.writeInt(u32, out[4 * i ..][0..4], state, .big);
        }
    }

    pub fn finalResult(d: *Self) [digest_length]u8 {
        var result: [digest_length]u8 = undefined;
        d.final(&result);
        return result;
    }

    fn compress(d: *Self, block: *const [block_length]u8) void {
        var w: [68]u32 = undefined;
        var w1: [64]u32 = undefined;

        // 消息字加载 - 大端序
        for (0..16) |j| {
            w[j] = mem.readInt(u32, block[j * 4..][0..4], .big);
        }

        // 消息扩展
        for (16..68) |j| {
            w[j] = p1(w[j - 16] ^ w[j - 9] ^ math.rotl(u32, w[j - 3], 15)) ^
                math.rotl(u32, w[j - 13], 7) ^ w[j - 6];
        }

        // 计算W'
        for (0..64) |j| {
            w1[j] = w[j] ^ w[j + 4];
        }

        // 初始化工作变量 (A,B,C,D,E,F,G,H)
        var a = d.s[0];
        var b = d.s[1];
        var c = d.s[2];
        var dd = d.s[3]; // 重命名为dd避免与d冲突
        var e = d.s[4];
        var f = d.s[5];
        var g = d.s[6];
        var h = d.s[7];

        // 64轮迭代 - 修复工作变量更新逻辑
        for (0..64) |j| {
            const t_j = if (j < 16) @as(u32, 0x79CC4519) else @as(u32, 0x7A879D8A);
            const shift = @as(u5, @intCast(j % 32));
            const ss1 = math.rotl(u32, math.rotl(u32, a, 12) +% e +% math.rotl(u32, t_j, shift), 7);
            const ss2 = ss1 ^ math.rotl(u32, a, 12);

            const ff_j = if (j < 16) a ^ b ^ c else (a & b) | (a & c) | (b & c);
            const gg_j = if (j < 16) e ^ f ^ g else (e & f) | (~e & g);

            const tt1 = ff_j +% dd +% ss2 +% w1[j];
            const tt2 = gg_j +% h +% ss1 +% w[j];

            // 正确的工作变量更新顺序
            dd = c;                  // D = C
            c = math.rotl(u32, b, 9); // C = B <<< 9
            b = a;                   // B = A
            a = tt1;                 // A = TT1
            h = g;                   // H = G
            g = math.rotl(u32, f, 19); // G = F <<< 19
            f = e;                   // F = E
            e = p0(tt2);             // E = P0(TT2)
        }

        // 更新哈希值
        d.s[0] ^= a;
        d.s[1] ^= b;
        d.s[2] ^= c;
        d.s[3] ^= dd;
        d.s[4] ^= e;
        d.s[5] ^= f;
        d.s[6] ^= g;
        d.s[7] ^= h;
    }

    // 置换函数P0
    inline fn p0(x: u32) u32 {
        return x ^ math.rotl(u32, x, 9) ^ math.rotl(u32, x, 17);
    }

    // 置换函数P1
    inline fn p1(x: u32) u32 {
        return x ^ math.rotl(u32, x, 15) ^ math.rotl(u32, x, 23);
    }

    pub const Error = error{};
    pub const Writer = std.io.GenericWriter(*Self, Error, write);

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
    SM3.hash(b, &out, .{});
    return out;
}

pub fn hmac(key: []const u8, message: []const u8) [SM3.digest_length]u8 {
    var k: [SM3.block_length]u8 = undefined;
    if (key.len > SM3.block_length) {
        SM3.hash(key, k[0..SM3.digest_length], .{});
        @memset(k[SM3.digest_length..], 0);
    } else {
        @memcpy(k[0..key.len], key);
        @memset(k[key.len..], 0);
    }

    var o_key_pad: [SM3.block_length]u8 = undefined;
    var i_key_pad: [SM3.block_length]u8 = undefined;
    for (k, 0..) |b, i| {
        o_key_pad[i] = b ^ 0x5c;
        i_key_pad[i] = b ^ 0x36;
    }

    // inner = SM3(i_key_pad || message)
    var inner = SM3.init(.{});
    inner.update(i_key_pad[0..]);
    inner.update(message);
    var inner_hash: [SM3.digest_length]u8 = undefined;
    inner.final(&inner_hash);

    // outer = SM3(o_key_pad || inner_hash)
    var outer = SM3.init(.{});
    outer.update(o_key_pad[0..]);
    outer.update(inner_hash[0..]);
    var out: [SM3.digest_length]u8 = undefined;
    outer.final(&out);

    return out;
}

// 优化的性能测试函数
pub fn testPerformance(allocator: std.mem.Allocator) !void {
    const print = std.debug.print;
    const test_sizes = [_]usize{
        64 * 1024, // 64KB
        1024 * 1024, // 1MB
        10 * 1024 * 1024, // 10MB
        100 * 1024 * 1024, // 100MB
    };

    print("\nSM3 性能测试 (推荐使用 ReleaseFast 模式编译)\n", .{});
    print("------------------------------------------------\n", .{});

    for (test_sizes) |size| {
        // 分配对齐的内存
        var buffer: []u8 = undefined;
        if (isZig015OrNewer) {
            const alignment = mem.Alignment.@"64";
            buffer = try allocator.alignedAlloc(u8, alignment, size);
        } else {
            const alignment = 16;
            buffer = try allocator.alignedAlloc(u8, alignment, size);
        }
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
