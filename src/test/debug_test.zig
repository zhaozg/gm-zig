const std = @import("std");
const testing = std.testing;

// Import the sm9 module to test specific functions
const sm9 = @import("../sm9.zig");

test "Debug specific SM9 function that causes hang" {
    std.debug.print("\n=== Testing SM9 GtElement.random ===\n", .{});

    // Test the specific function that hangs in pairing test
    const elem = sm9.pairing.GtElement.random("test_seed");
    std.debug.print("Random element created successfully\n", .{});

    try testing.expect(!elem.isIdentity());
    std.debug.print("Identity check passed\n", .{});
}

test "Debug SM9 bigint operations" {
    std.debug.print("\n=== Testing SM9 BigInt operations ===\n", .{});

    const a = [_]u8{0} ** 31 ++ [_]u8{3};
    const b = [_]u8{0} ** 31 ++ [_]u8{5};
    const m = [_]u8{0} ** 31 ++ [_]u8{7};

    std.debug.print("Testing modPow(3, 5, 7)...\n", .{});
    const result = sm9.bigint.modPow(a, b, m) catch |err| {
        std.debug.print("modPow failed with error: {}\n", .{err});
        return err;
    };
    std.debug.print("modPow completed successfully: {}\n", .{result[31]});
}
