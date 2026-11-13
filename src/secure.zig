//! Small helpers for handling secret material in memory.
//!
//! These helpers are intentionally explicit: callers still decide which data is
//! sensitive. `zero` and `zeroValue` use volatile writes so the compiler cannot
//! remove the clearing as a dead store.

const std = @import("std");

/// Overwrite a mutable byte slice with zeros.
pub fn zero(bytes: []u8) void {
    std.crypto.secureZero(u8, bytes);
}

/// Overwrite the memory of a single value with zeros.
///
/// This is useful for fixed-size secrets such as private keys, scalars, key
/// schedules, and intermediate field elements.
pub fn zeroValue(comptime T: type, value: *T) void {
    std.crypto.secureZero(u8, std.mem.asBytes(value));
}

/// Overwrite the memory of a slice with zeros.
pub fn zeroSlice(comptime T: type, slice: []T) void {
    std.crypto.secureZero(u8, std.mem.sliceAsBytes(slice));
}

/// Compare two byte strings without branching on their contents.
///
/// Lengths are assumed to be public. The loop always visits every byte when
/// both inputs have the same length.
pub fn constantTimeEqual(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;

    var diff: u8 = 0;
    for (a, b) |x, y| {
        diff |= x ^ y;
    }
    return diff == 0;
}

test "zero clears a byte buffer" {
    var data = @as([32]u8, @splat(0xaa));
    zero(&data);
    try std.testing.expect(std.mem.allEqual(u8, &data, 0));
}

test "zeroValue clears a fixed-size value" {
    var key = @as([32]u8, @splat(0x55));
    zeroValue([32]u8, &key);
    try std.testing.expect(std.mem.allEqual(u8, &key, 0));
}

test "zeroSlice clears a slice" {
    var words = @as([8]u32, @splat(0xdeadbeef));
    zeroSlice(u32, &words);
    try std.testing.expect(std.mem.allEqual(u32, &words, 0));
}

test "constantTimeEqual compares equal and unequal inputs" {
    const a = @as([32]u8, @splat(1));
    var b = a;
    try std.testing.expect(constantTimeEqual(&a, &b));
    b[31] ^= 1;
    try std.testing.expect(!constantTimeEqual(&a, &b));
    try std.testing.expect(!constantTimeEqual(a[0..31], &b));
}
