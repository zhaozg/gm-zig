const std = @import("std");
const sm9 = @import("src/sm9.zig");

pub fn main() !void {
    std.debug.print("Testing scalar multiplication...\n", .{});
    
    const params = sm9.params.SystemParams.init();
    
    // Create a simple test point
    const x = [_]u8{0x01} ++ [_]u8{0} ** 31;
    const y = [_]u8{0x02} ++ [_]u8{0} ** 31;
    const point = sm9.curve.G1Point.affine(x, y);
    
    std.debug.print("Created point\n", .{});
    
    // Test with scalar = 2
    const two = [_]u8{0} ** 31 ++ [_]u8{2};
    std.debug.print("Testing scalar = 2...\n", .{});
    
    const result = sm9.curve.CurveUtils.scalarMultiplyG1(point, two, params);
    _ = result;
    std.debug.print("Result obtained successfully\n", .{});
    
    std.debug.print("Test completed!\n", .{});
}
