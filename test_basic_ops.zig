const std = @import("std");
const sm9 = @import("src/sm9.zig");

pub fn main() !void {
    std.debug.print("Testing basic operations...\n", .{});
    
    const params = sm9.params.SystemParams.init();
    
    // Test G1 point creation
    const x = [_]u8{0x01} ++ [_]u8{0} ** 31;
    const y = [_]u8{0x02} ++ [_]u8{0} ** 31;
    const point = sm9.curve.G1Point.affine(x, y);
    
    std.debug.print("Created G1 point\n", .{});
    
    // Test addition with infinity (should be safe)
    const infinity = sm9.curve.G1Point.infinity();
    const sum_with_inf = point.add(infinity, params);
    std.debug.print("Addition with infinity: OK\n", .{});
    
    // Test doubling (might be where the issue is)
    std.debug.print("Testing doubling...\n", .{});
    const doubled = point.double(params);
    std.debug.print("Doubling: OK\n", .{});
    
    // Test addition with same point (should call double)
    std.debug.print("Testing addition with same point...\n", .{});
    const sum_same = point.add(point, params);
    std.debug.print("Addition with same point: OK\n", .{});
    
    // Test addition with different point  
    const x2 = [_]u8{0x03} ++ [_]u8{0} ** 31;
    const y2 = [_]u8{0x04} ++ [_]u8{0} ** 31;
    const point2 = sm9.curve.G1Point.affine(x2, y2);
    std.debug.print("Testing addition with different point...\n", .{});
    const sum_diff = point.add(point2, params);
    std.debug.print("Addition with different point: OK\n", .{});
    
    std.debug.print("All basic operations completed!\n", .{});
    _ = sum_with_inf;
    _ = doubled;
    _ = sum_same;
    _ = sum_diff;
}
