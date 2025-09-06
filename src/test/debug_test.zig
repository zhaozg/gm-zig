const std = @import("std");
const testing = std.testing;

// Import the sm9 module to test specific functions
const sm9 = @import("../sm9.zig");

test "Debug specific SM9 function that causes hang" {
    // Test the specific function that hangs in pairing test
    const elem = sm9.pairing.GtElement.random("test_seed");
    try testing.expect(!elem.isIdentity());
}

test "Debug SM9 bigint operations" {
    const a = [_]u8{0} ** 31 ++ [_]u8{3};
    const b = [_]u8{0} ** 31 ++ [_]u8{5};
    const m = [_]u8{0} ** 31 ++ [_]u8{7};

    const result = sm9.bigint.modPow(a, b, m) catch |err| {
        std.debug.print("modPow failed with error: {}\n", .{err});
        return err;
    };
    try testing.expect(result.len == 32 and !sm9.bigint.isZero(result));
}
