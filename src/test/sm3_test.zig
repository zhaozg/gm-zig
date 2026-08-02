const std = @import("std");
const testing = std.testing;
const fmt = std.fmt;
const sm3 = @import("../sm3.zig");
const SM3 = sm3.SM3;

// Test helper functions
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

test "aligned final" {
    var block = @as([SM3.block_length]u8, @splat(0));
    var out: [SM3.digest_length]u8 = undefined;

    var h = SM3.init(.{});
    h.update(&block);
    h.final(&out);
}

// 基于算法源码 SM3_SelfTest 样本数据的测试
// 算法源码使用 "abc" (3字节) 和 64字节重复数据 "abcdabcdabcd..." 作为测试样本
test "algorithm source sample: 64-byte repeated pattern" {
    // 64字节重复数据: "abcdabcdabcd..."
    var msg64: [64]u8 = undefined;
    const pattern = [_]u8{ 0x61, 0x62, 0x63, 0x64 }; // "abcd"
    for (0..16) |i| {
        @memcpy(msg64[4 * i .. 4 * i + 4], &pattern);
    }

    var out: [32]u8 = undefined;
    SM3.hash(&msg64, &out, .{});

    // 验证哈希值不为空且长度为32
    try testing.expect(out.len == 32);
}

// 算法源码 SM3_SelfTest 使用 "abc" 的预期哈希值
// 算法源码中 StdHash1 = 0x66C7F0F462EEEDD9D1F2D46BDC10E4E24167C4875CF2F7A2297DA02B8F4BA8E0
test "algorithm source sample: abc" {
    try assertEqualHash(SM3, "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0", "abc");
}

// 算法源码 SM3_SelfTest 使用 64字节 "abcdabcd..." 的预期哈希值
// 算法源码中 StdHash2 = 0xDEBE9FF92275B8A138604889C18E5A4D6FDB70E5387E5765293DCBA39C0C5732
test "algorithm source sample: 64-byte abcd pattern" {
    var msg64: [64]u8 = undefined;
    const pattern = [_]u8{ 0x61, 0x62, 0x63, 0x64 }; // "abcd"
    for (0..16) |i| {
        @memcpy(msg64[4 * i .. 4 * i + 4], &pattern);
    }

    try assertEqualHash(SM3, "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732", &msg64);
}

// 测试大块数据（多块处理）
test "large data multi-block" {
    var large_data: [1024]u8 = undefined;
    for (&large_data, 0..) |*b, i| {
        b.* = @intCast(i & 0xFF);
    }

    var out1: [32]u8 = undefined;
    SM3.hash(&large_data, &out1, .{});

    // 流式处理应该得到相同结果
    var h = SM3.init(.{});
    h.update(&large_data);
    var out2: [32]u8 = undefined;
    h.final(&out2);

    try testing.expectEqualSlices(u8, &out1, &out2);
}

// 测试 HMAC-SM3
test "HMAC-SM3 basic" {
    const key = "key";
    const message = "The quick brown fox jumps over the lazy dog";

    const result = sm3.hmac(key, message);
    try testing.expect(result.len == 32);
}

// 测试 HMAC-SM3 一致性
test "HMAC-SM3 consistency" {
    const key = "key";
    const message = "The quick brown fox jumps over the lazy dog";

    const result1 = sm3.hmac(key, message);
    const result2 = sm3.hmac(key, message);
    try testing.expectEqualSlices(u8, &result1, &result2);
}

// 测试 HMAC-SM3 不同密钥产生不同结果
test "HMAC-SM3 different keys" {
    const message = "test message";
    const result1 = sm3.hmac("key1", message);
    const result2 = sm3.hmac("key2", message);
    try testing.expect(!std.mem.eql(u8, &result1, &result2));
}

// 测试 HMAC-SM3 不同消息产生不同结果
test "HMAC-SM3 different messages" {
    const key = "key";
    const result1 = sm3.hmac(key, "message1");
    const result2 = sm3.hmac(key, "message2");
    try testing.expect(!std.mem.eql(u8, &result1, &result2));
}

// 测试 HMAC-SM3 空消息
test "HMAC-SM3 empty message" {
    const key = "key";
    const result = sm3.hmac(key, "");
    try testing.expect(result.len == 32);
}

// 测试 HMAC-SM3 空密钥
test "HMAC-SM3 empty key" {
    const message = "test message";
    const result = sm3.hmac("", message);
    try testing.expect(result.len == 32);
}

// 测试 HMAC-SM3 长密钥（超过块大小）
test "HMAC-SM3 long key" {
    var long_key: [128]u8 = undefined;
    for (&long_key, 0..) |*b, i| {
        b.* = @intCast(i & 0xFF);
    }
    const message = "test message";
    const result = sm3.hmac(&long_key, message);
    try testing.expect(result.len == 32);
}

// 测试 SM3 哈希函数的一致性
test "SM3 hash function consistency" {
    const test_inputs = [_][]const u8{
        "",
        "a",
        "abc",
        "message digest",
        "abcdefghijklmnopqrstuvwxyz",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
    };

    for (test_inputs) |input| {
        const result1 = sm3.hash(input);
        const result2 = sm3.hash(input);
        try testing.expectEqualSlices(u8, &result1, &result2);
    }
}

// 测试 SM3 哈希函数不同输入产生不同输出
test "SM3 hash function different inputs" {
    const result1 = sm3.hash("hello");
    const result2 = sm3.hash("world");
    try testing.expect(!std.mem.eql(u8, &result1, &result2));
}

// 测试 SM3 哈希函数空输入
test "SM3 hash function empty input" {
    const result = sm3.hash("");
    try testing.expect(result.len == 32);
}

// 测试 SM3 哈希函数大输入
test "SM3 hash function large input" {
    var large_input: [10000]u8 = undefined;
    for (&large_input, 0..) |*b, i| {
        b.* = @intCast(i & 0xFF);
    }
    const result = sm3.hash(&large_input);
    try testing.expect(result.len == 32);
}

fn hashChunk(chunk: []const u8, out: *[32]u8) void {
    SM3.hash(chunk, out, .{});
}
