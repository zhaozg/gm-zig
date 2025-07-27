const std = @import("std");
const sm3 = @import("./sm3.zig");
const sm4 = @import("./sm4.zig");

pub fn main() !void {
    const data_size = 1024 * 1024 * 10; // 10MB
    var data = [_]u8{0x61} ** data_size; // 填充 'a'
    var out: [sm3.SM3.digest_length]u8 = undefined;

    var timer = try std.time.Timer.start();
    sm3.SM3.hash(&data, &out, .{});
    const elapsed_ns = timer.read();

    const mb_per_s = @as(f64, data_size) / 1024.0 / 1024.0 / (@as(f64, @floatFromInt(elapsed_ns)) / 1e9);
    std.debug.print("SM3 10MB hash: {d:.2} ms, {d:.2} MB/s\n", .{
        @as(f64, @floatFromInt(elapsed_ns)) / 1e6,
        mb_per_s,
    });

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    try sm4.testPerformance(allocator);
}

