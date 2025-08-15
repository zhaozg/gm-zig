const std = @import("std");

var global: ByteArrayRandom = undefined;

/// 基于固定字节序列的随机数生成器
pub const ByteArrayRandom = struct {
    data: []const u8,
    index: usize,
    exhausted: bool,  // 添加耗尽标记

    /// 初始化随机数生成器
    /// seed: 随机源字节序列（非空）
    pub fn init(seed: []const u8) ByteArrayRandom {
        // 若传入空切片，使用默认单字节种子
        const effective_seed = std.heap.wasm_allocator.alloc(u8, seed.len) catch @panic("allocation failed");
        for(0..seed.len) |i| {
            effective_seed[i]=seed[i];
        }
        return .{
            .data = effective_seed,
            .index = 0,
            .exhausted = false,
        };
    }

    /// 实现 Random 接口的填充方法
    fn fillBytes(ctx: *anyopaque, buf: []u8) void {
        // 从上下文指针恢复生成器实例
        const self: *ByteArrayRandom = @ptrCast(@alignCast(ctx));

        // 如果已经耗尽，直接返回0
        if (self.exhausted) {
            @memset(buf, 0);
            return;
        }

        // 检查剩余数据
        const remaining = self.data.len - self.index;

        // 如果请求超过剩余数据，返回全0并标记耗尽
        if (buf.len > remaining) {
            @memset(buf, 0);
            self.exhausted = true;
            return;
        }

        // 正常复制数据
        @memcpy(buf, self.data[self.index..][0..buf.len]);
        self.index += buf.len;

        // 检查是否耗尽
        if (self.index >= self.data.len) {
            self.exhausted = true;
        }
    }

    /// 获取标准库 Random 接口实例
    pub fn random(self: *ByteArrayRandom) std.Random {
        return .{
            .ptr = self,
            .fillFn = fillBytes,
        };
    }
};

pub fn init(seed: []const u8)  void {
    global = ByteArrayRandom.init(seed);
}
pub fn random(buf: []u8) void {
    global.random().bytes(buf);
}

pub fn getDefault() *const std.Random {
    return &global.random();
}

// 测试用例
test "ByteArrayRandom interface compatibility" {
    const seed = "ZIG_RAND"; // 8字节
    var rng = ByteArrayRandom.init(seed);
    const rand = rng.random();

    // 验证接口类型：将anyopaque指针转换回原始类型
    const rng_ptr = @as(*ByteArrayRandom, @ptrCast(@alignCast(rand.ptr)));
    try std.testing.expect(rng_ptr == &rng);
    try std.testing.expect(rand.fillFn == ByteArrayRandom.fillBytes);

    // 验证填充功能：请求8字节（正好等于种子长度）
    var buf: [8]u8 = undefined;
    rand.fillFn(rand.ptr, &buf);
    try std.testing.expectEqualSlices(u8, "ZIG_RAND", &buf);
}

test "ByteArrayRandom basic usage" {
    const seed = "0123456789ABCDEF"; // 16字节
    var rng = ByteArrayRandom.init(seed);
    const rand = rng.random();

    // 验证填充字节：请求16字节（正好等于种子长度）
    var buf: [16]u8 = undefined;
    rand.fillFn(rand.ptr, &buf);
    try std.testing.expectEqualSlices(u8, "0123456789ABCDEF", &buf);

    // 验证耗尽后返回0
    var zero_buf: [4]u8 = undefined;
    rand.fillFn(rand.ptr, &zero_buf);
    try std.testing.expectEqualSlices(u8, &[_]u8{0, 0, 0, 0}, &zero_buf);

    // 验证整数生成
    const num = std.Random.int(rand, u32);
    try std.testing.expect(num == 0); // 耗尽后应返回0
}

test "ByteArrayRandom empty seed handling" {
    var rng = ByteArrayRandom.init(&[_]u8{}); // 使用默认种子 [0]
    const rand = rng.random();

    // 请求1字节应返回0（因为请求1字节 > 剩余0字节）
    var buf: [1]u8 = undefined;
    rand.fillFn(rand.ptr, &buf);
    try std.testing.expectEqualSlices(u8, &[_]u8{0}, &buf);

    // 再次请求应返回0
    var zero_buf: [1]u8 = undefined;
    rand.fillFn(rand.ptr, &zero_buf);
    try std.testing.expectEqualSlices(u8, &[_]u8{0}, &zero_buf);
}

test "ByteArrayRandom partial request" {
    const seed = "12345678"; // 8字节
    var rng = ByteArrayRandom.init(seed);
    const rand = rng.random();

    // 请求3字节
    var buf1: [3]u8 = undefined;
    rand.fillFn(rand.ptr, &buf1);
    try std.testing.expectEqualSlices(u8, "123", &buf1);

    // 再请求3字节
    var buf2: [3]u8 = undefined;
    rand.fillFn(rand.ptr, &buf2);
    try std.testing.expectEqualSlices(u8, "456", &buf2);

    // 请求3字节（超过剩余2字节）应返回全0
    var buf3: [3]u8 = undefined;
    rand.fillFn(rand.ptr, &buf3);
    try std.testing.expectEqualSlices(u8, &[_]u8{0, 0, 0}, &buf3);

    // 再次请求应返回0
    var zero_buf: [3]u8 = undefined;
    rand.fillFn(rand.ptr, &zero_buf);
    try std.testing.expectEqualSlices(u8, &[_]u8{0, 0, 0}, &zero_buf);
}

test "ByteArrayRandom over request" {
    const seed = "abcd"; // 4字节
    var rng = ByteArrayRandom.init(seed);
    const rand = rng.random();

    // 尝试请求超过剩余长度的数据（5字节）应返回全0
    var buf: [5]u8 = undefined;
    rand.fillFn(rand.ptr, &buf);
    try std.testing.expectEqualSlices(u8, &[_]u8{0, 0, 0, 0, 0}, &buf);

    // 后续请求也应返回0
    var zero_buf: [2]u8 = undefined;
    rand.fillFn(rand.ptr, &zero_buf);
    try std.testing.expectEqualSlices(u8, &[_]u8{0, 0}, &zero_buf);
}

test "ByteArrayRandom exact request" {
    const seed = "exact";
    var rng = ByteArrayRandom.init(seed);
    const rand = rng.random();

    // 请求等于剩余长度的数据
    var buf: [5]u8 = undefined;
    rand.fillFn(rand.ptr, &buf);
    try std.testing.expectEqualSlices(u8, "exact", &buf);

    // 后续请求应返回0
    var zero_buf: [1]u8 = undefined;
    rand.fillFn(rand.ptr, &zero_buf);
    try std.testing.expectEqualSlices(u8, &[_]u8{0}, &zero_buf);
}
