const std = @import("std");
const sm9 = @import("src/sm9.zig");

pub fn main() !void {
    std.debug.print("Testing point.mul() method...\n", .{});
    
    const params = sm9.params.SystemParams.init();
    
    // Test G1 point creation
    const x = [_]u8{0x01} ++ [_]u8{0} ** 31;
    const y = [_]u8{0x02} ++ [_]u8{0} ** 31;
    const point = sm9.curve.G1Point.affine(x, y);
    
    std.debug.print("Created G1 point\n", .{});
    
    // Test the .mul() method directly which calls CurveUtils.scalarMultiplyG1
    std.debug.print("Testing point.mul(3)...\n", .{});
    const three = [_]u8{0} ** 31 ++ [_]u8{3};
    const result = point.mul(three, params);
    std.debug.print("point.mul(3): OK\n", .{});
    
    std.debug.print("All tests completed!\n", .{});
    _ = result;
}
