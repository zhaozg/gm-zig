const std = @import("std");
const testing = std.testing;
const fmt = std.fmt;
const sm3 = @import("../sm3.zig");
const SM3 = sm3.SM3;

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
