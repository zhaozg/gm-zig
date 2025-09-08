const std = @import("std");
const sm9 = @import("src/sm9.zig");

pub fn main() !void {
    std.debug.print("Testing SM9 performance with proper elliptic curve cryptography...\n", .{});
    
    const params = sm9.params.SystemParams.init();
    
    // Test G1 scalar multiplication performance
    const x = [_]u8{0x01} ++ [_]u8{0} ** 31;
    const y = [_]u8{0x02} ++ [_]u8{0} ** 31;
    const point = sm9.curve.G1Point.affine(x, y);
    
    const scalar = [_]u8{0x12, 0x34, 0x56, 0x78} ++ [_]u8{0} ** 28;
    
    std.debug.print("Starting SM9 G1 scalar multiplication timing...\n", .{});
    const start_time = std.time.nanoTimestamp();
    
    // Perform 10 scalar multiplications
    var i: u32 = 0;
    while (i < 10) : (i += 1) {
        const result = sm9.curve.CurveUtils.scalarMultiplyG1(point, scalar, params);
        _ = result;
    }
    
    const end_time = std.time.nanoTimestamp();
    const elapsed_ns = @as(u64, @intCast(end_time - start_time));
    const avg_per_op_ms = @as(f64, @floatFromInt(elapsed_ns)) / 10.0 / 1_000_000.0;
    const ops_per_sec = 1000.0 / avg_per_op_ms;
    
    std.debug.print("SM9 G1 scalar multiplication: {d:.2} ops/s (avg {d:.2} ms per op)\n", .{ ops_per_sec, avg_per_op_ms });
    std.debug.print("Compare this to SM2 which typically runs at ~80-100 ops/s\n", .{});
    
    if (ops_per_sec < 1000) {
        std.debug.print("✓ Performance is realistic for proper elliptic curve operations\n", .{});
    } else {
        std.debug.print("⚠ Performance is still too fast - might still be using hash operations\n", .{});
    }
}
