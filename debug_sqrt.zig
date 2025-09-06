const std = @import("std");
const sm9 = @import("src/sm9.zig");

pub fn main() !void {
    const params = sm9.params.SystemParams.init();
    const p = params.q;
    
    std.debug.print("Testing square root computation\n", .{});
    
    // Test square root of perfect squares
    const base = [_]u8{0} ** 31 ++ [_]u8{5};
    std.debug.print("base = ", .{});
    for (base) |byte| {
        std.debug.print("{x:02}", .{byte});
    }
    std.debug.print("\n", .{});
    
    const square = sm9.bigint.mulMod(base, base, p) catch |err| {
        std.debug.print("mulMod failed: {}\n", .{err});
        return;
    };
    std.debug.print("square = ", .{});
    for (square) |byte| {
        std.debug.print("{x:02}", .{byte});
    }
    std.debug.print("\n", .{});
    
    // Compute (p+1)/4 using proper bit shifting
    const p_plus_1 = sm9.bigint.add(p, [_]u8{0} ** 31 ++ [_]u8{1}).result;
    std.debug.print("p+1 = ", .{});
    for (p_plus_1) |byte| {
        std.debug.print("{x:02}", .{byte});
    }
    std.debug.print("\n", .{});
    
    // Divide by 4 (shift right 2 bits) - use bigint shiftRight function twice
    const exponent = sm9.bigint.shiftRight(sm9.bigint.shiftRight(p_plus_1));
    std.debug.print("(p+1)/4 = ", .{});
    for (exponent) |byte| {
        std.debug.print("{x:02}", .{byte});
    }
    std.debug.print("\n", .{});
    
    const sqrt_result = sm9.field.modularExponentiation(square, exponent, p) catch |err| {
        std.debug.print("modularExponentiation failed: {}\n", .{err});
        return;
    };
    std.debug.print("sqrt_result = ", .{});
    for (sqrt_result) |byte| {
        std.debug.print("{x:02}", .{byte});
    }
    std.debug.print("\n", .{});
    
    // Verify that sqrt_result^2 = square
    const verification = sm9.bigint.mulMod(sqrt_result, sqrt_result, p) catch |err| {
        std.debug.print("verification mulMod failed: {}\n", .{err});
        return;
    };
    std.debug.print("verification = ", .{});
    for (verification) |byte| {
        std.debug.print("{x:02}", .{byte});
    }
    std.debug.print("\n", .{});
    
    if (sm9.bigint.equal(verification, square)) {
        std.debug.print("SUCCESS: sqrt_result^2 == square\n", .{});
    } else {
        std.debug.print("FAIL: sqrt_result^2 != square\n", .{});
    }
    
    // Also test with the expected result (should be ±base)
    if (sm9.bigint.equal(sqrt_result, base)) {
        std.debug.print("sqrt_result == base (positive square root)\n", .{});
    } else {
        // Check if it's the negative square root (p - base)
        const neg_base = sm9.bigint.sub(p, base).result;
        if (sm9.bigint.equal(sqrt_result, neg_base)) {
            std.debug.print("sqrt_result == -base (negative square root)\n", .{});
        } else {
            std.debug.print("sqrt_result is neither +base nor -base\n", .{});
        }
    }
}