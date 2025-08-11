const std = @import("std");
const sm3 = @import("./sm3.zig");
const sm4 = @import("./sm4.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    try sm3.testPerformance(allocator);
    try sm4.testPerformance_ecb(allocator);
    try sm4.testPerformance_cbc(allocator);
    try sm4.testPerformanceSIMD_ECB(allocator);
}

