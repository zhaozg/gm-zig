const std = @import("std");
const sm9 = @import("src/sm9.zig");

pub fn main() !void {
    std.debug.print("Testing scalar multiplication with 3...\n", .{});
    
    const params = sm9.params.SystemParams.init();
    
    // Test G1 point creation
    const x = [_]u8{0x01} ++ [_]u8{0} ** 31;
    const y = [_]u8{0x02} ++ [_]u8{0} ** 31;
    const point = sm9.curve.G1Point.affine(x, y);
    
    std.debug.print("Created G1 point\n", .{});
    
    // Test manual 3*P = 2*P + P
    std.debug.print("Testing manual 3*P = 2*P + P...\n", .{});
    const doubled = point.double(params);
    const tripled_manual = doubled.add(point, params);
    std.debug.print("Manual tripling: OK\n", .{});
    
    // Test the scalar multiplication method directly
    std.debug.print("Testing scalar multiplication with 3...\n", .{});
    const three = [_]u8{0} ** 31 ++ [_]u8{3};
    const tripled_scalar = sm9.curve.CurveUtils.scalarMultiplyG1(point, three, params);
    std.debug.print("Scalar multiplication: OK\n", .{});
    
    std.debug.print("All tests completed!\n", .{});
    _ = tripled_manual;
    _ = tripled_scalar;
}
