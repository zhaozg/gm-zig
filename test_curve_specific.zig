const std = @import("std");
const sm9 = @import("src/sm9.zig");

pub fn main() !void {
    std.debug.print("Testing specific curve operations...\n", .{});
    
    const params = sm9.params.SystemParams.init();
    
    // Test G1 doubling
    const x = [_]u8{0x01} ++ [_]u8{0} ** 31;
    const y = [_]u8{0x02} ++ [_]u8{0} ** 31;
    const point = sm9.curve.G1Point.affine(x, y);
    
    std.debug.print("Testing G1 doubling...\n", .{});
    const doubled = point.double(params);
    std.debug.print("G1 doubling done\n", .{});
    
    // Test G1 scalar multiplication with 3
    std.debug.print("Testing G1 scalar multiplication with 3...\n", .{});
    const three = [_]u8{0} ** 31 ++ [_]u8{3};
    const result = point.mul(three, params);
    std.debug.print("G1 scalar mul done\n", .{});
    
    // Test G2 operations  
    std.debug.print("Testing G2...\n", .{});
    const x2 = [_]u8{0x01} ++ [_]u8{0} ** 63;
    const y2 = [_]u8{0x02} ++ [_]u8{0} ** 63;
    const point2 = sm9.curve.G2Point.affine(x2, y2);
    
    std.debug.print("Testing G2 doubling...\n", .{});
    const doubled2 = point2.double(params);
    std.debug.print("G2 doubling done\n", .{});
    
    std.debug.print("All tests completed!\n", .{});
    _ = doubled;
    _ = result;
    _ = doubled2;
}
