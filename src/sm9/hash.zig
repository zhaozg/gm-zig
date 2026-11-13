//! SM9 hash and KDF primitives from GM/T 0044-2016.

const std = @import("std");
const mem = std.mem;
const SM3 = @import("../sm3.zig").SM3;

pub const HashError = error{
    InvalidInput,
    InvalidLength,
    InvalidIdentity,
    KDFComputationFailed,
};

pub const GROUP_ORDER: [32]u8 = .{
    0xb6, 0x40, 0x00, 0x00, 0x02, 0xa3, 0xa6, 0xf1,
    0xd6, 0x03, 0xab, 0x4f, 0xf5, 0x8e, 0xc7, 0x44,
    0x49, 0xf2, 0x93, 0x4b, 0x18, 0xea, 0x8b, 0xee,
    0xe5, 0x6e, 0xe1, 0x9c, 0xd6, 0x9e, 0xcf, 0x25,
};

fn isZero32(v: [32]u8) bool {
    return mem.allEqual(u8, &v, 0);
}

fn hashToScalar(h40: [40]u8, order: [32]u8) [32]u8 {
    const n = mem.readInt(u256, &order, .big);
    const value: u256 = @intCast(mem.readInt(u320, &h40, .big) % (n - 1));
    var out: [32]u8 = undefined;
    mem.writeInt(u256, &out, value + 1, .big);
    return out;
}

fn hash40(prefix: u8, part1: []const u8, part2: []const u8) [40]u8 {
    var block1: [32]u8 = undefined;
    var block2: [32]u8 = undefined;
    var ctr: [4]u8 = undefined;

    var h1 = SM3.init(.{});
    h1.update(&[_]u8{prefix});
    h1.update(part1);
    h1.update(part2);
    mem.writeInt(u32, &ctr, 1, .big);
    h1.update(&ctr);
    block1 = h1.finalResult();

    var h2 = SM3.init(.{});
    h2.update(&[_]u8{prefix});
    h2.update(part1);
    h2.update(part2);
    mem.writeInt(u32, &ctr, 2, .big);
    h2.update(&ctr);
    block2 = h2.finalResult();

    var out: [40]u8 = undefined;
    @memcpy(out[0..32], &block1);
    @memcpy(out[32..40], block2[0..8]);
    return out;
}

/// H1: SM3(0x01 || ID || hid || ct), reduced to [1, N-1].
pub fn h1Hash(data: []const u8, hid: u8, order: [32]u8, allocator: std.mem.Allocator) ![32]u8 {
    _ = allocator;
    if (data.len == 0) return HashError.InvalidIdentity;
    if (isZero32(order)) return HashError.InvalidInput;
    return hashToScalar(hash40(0x01, data, &[_]u8{hid}), order);
}

/// H2: SM3(0x02 || Z || ct), reduced to [1, N-1].
pub fn h2Hash(message: []const u8, additional_data: []const u8, order: [32]u8, allocator: std.mem.Allocator) ![32]u8 {
    _ = allocator;
    if (isZero32(order)) return HashError.InvalidInput;
    return hashToScalar(hash40(0x02, message, additional_data), order);
}

/// KDF: SM3(Z || ct) blocks.
pub fn kdf(input: []const u8, output_len: usize, allocator: std.mem.Allocator) ![]u8 {
    if (output_len == 0) return HashError.InvalidLength;
    if (input.len == 0) return HashError.InvalidInput;

    const output = try allocator.alloc(u8, output_len);
    errdefer allocator.free(output);

    var offset: usize = 0;
    var counter: u32 = 1;
    while (offset < output_len) : (counter += 1) {
        if (counter == 0) return HashError.KDFComputationFailed;
        var hasher = SM3.init(.{});
        hasher.update(input);
        var ctr: [4]u8 = undefined;
        mem.writeInt(u32, &ctr, counter, .big);
        hasher.update(&ctr);
        const block = hasher.finalResult();
        const n = @min(32, output_len - offset);
        @memcpy(output[offset .. offset + n], block[0..n]);
        offset += n;
    }

    if (mem.allEqual(u8, output, 0)) {
        allocator.free(output);
        return HashError.KDFComputationFailed;
    }
    return output;
}

test "SM9 KDF reference vector" {
    const allocator = std.testing.allocator;
    const out = try kdf("abc", 32, allocator);
    defer allocator.free(out);
    const expected = [_]u8{
        0xfe, 0x1e, 0xa8, 0x0d, 0xac, 0x6f, 0x10, 0x0c,
        0x33, 0x53, 0x7b, 0xd2, 0x46, 0x19, 0xec, 0x7c,
        0x72, 0xa1, 0xe8, 0xb1, 0xff, 0xea, 0xef, 0xb1,
        0xeb, 0x52, 0xa3, 0x77, 0x91, 0xfd, 0xaf, 0x61,
    };
    try std.testing.expectEqualSlices(u8, &expected, out);
}

test "SM9 H1/H2 reference vectors" {
    const allocator = std.testing.allocator;
    const h1 = try h1Hash("Alice", 0x01, GROUP_ORDER, allocator);
    try std.testing.expectEqualSlices(
        u8,
        &[_]u8{
            0x2a, 0xcc, 0x46, 0x8c, 0x39, 0x26, 0xb0, 0xbd,
            0xb2, 0x76, 0x7e, 0x99, 0xff, 0x26, 0xe0, 0x84,
            0xde, 0x9c, 0xed, 0x8d, 0xbc, 0x7d, 0x5f, 0xbf,
            0x41, 0x80, 0x27, 0xb6, 0x67, 0x86, 0x2f, 0xab,
        },
        &h1,
    );

    var w: [32]u8 = undefined;
    for (&w, 0..) |*b, i| b.* = @intCast(i);
    const h2 = try h2Hash("abc", &w, GROUP_ORDER, allocator);
    try std.testing.expect(!isZero32(h2));
}
