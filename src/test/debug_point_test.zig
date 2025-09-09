const std = @import("std");
const expectEqual = std.testing.expectEqual;
const expectError = std.testing.expectError;
const sm9 = @import("../sm9.zig");

test "Debug P1 point decompression issue" {
    const system = sm9.params.SM9System.init();
    
    std.debug.print("P1 bytes: ", .{});
    for (system.params.P1) |byte| {
        std.debug.print("{:02x}", .{byte});
    }
    std.debug.print("\n", .{});
    
    std.debug.print("Modulus q: ", .{});
    for (system.params.q) |byte| {
        std.debug.print("{:02x}", .{byte});
    }
    std.debug.print("\n", .{});
    
    // Try to decompress P1
    const result = sm9.curve.G1Point.fromCompressed(system.params.P1);
    if (result) |point| {
        std.debug.print("Successfully decompressed P1\n", .{});
        std.debug.print("Point x: ", .{});
        for (point.x) |byte| {
            std.debug.print("{:02x}", .{byte});
        }
        std.debug.print("\n", .{});
    } else |err| {
        std.debug.print("Failed to decompress P1: {}\n", .{err});
        
        // Try to debug the square root computation
        const x_coord = system.params.P1[1..33].*;
        std.debug.print("X coordinate: ", .{});
        for (x_coord) |byte| {
            std.debug.print("{:02x}", .{byte});
        }
        std.debug.print("\n", .{});
        
        // Check if x^3 + 3 is a quadratic residue using the modulus
        const x_cubed = sm9.bigint.mulMod(sm9.bigint.mulMod(x_coord, x_coord, system.params.q) catch unreachable, x_coord, system.params.q) catch unreachable;
        const three = [_]u8{0} ** 31 ++ [_]u8{3};
        const y_squared = sm9.bigint.addMod(x_cubed, three, system.params.q) catch unreachable;
        
        std.debug.print("y^2 = x^3 + 3: ", .{});
        for (y_squared) |byte| {
            std.debug.print("{:02x}", .{byte});
        }
        std.debug.print("\n", .{});
    }
}