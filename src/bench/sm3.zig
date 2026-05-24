const std = @import("std");
const root = @import("../root.zig");
const sm3 = root.sm3;

/// SM3 hash benchmark context
const Sm3BenchContext = struct {
    data_64b: [64]u8,
    data_1k: [1024]u8,
    data_64k: [65536]u8,
    data_1m: []u8,
    data_10m: []u8,
    allocator: std.mem.Allocator,

    fn init(allocator: std.mem.Allocator) !Sm3BenchContext {
        var ctx = Sm3BenchContext{
            .data_64b = undefined,
            .data_1k = undefined,
            .data_64k = undefined,
            .data_1m = try allocator.alloc(u8, 1024 * 1024),
            .data_10m = try allocator.alloc(u8, 10 * 1024 * 1024),
            .allocator = allocator,
        };

        // Initialize small data
        @memcpy(&ctx.data_64b, "Hello, SM3! This is a benchmark test message for SM3 hash function.");

        for (&ctx.data_1k, 0..) |*b, i| {
            b.* = @as(u8, @truncate(i));
        }
        for (&ctx.data_64k, 0..) |*b, i| {
            b.* = @as(u8, @truncate(i));
        }

        // Initialize large data with random
        var prng = std.Random.DefaultPrng.init(0);
        prng.random().bytes(ctx.data_1m);
        prng.random().bytes(ctx.data_10m);

        return ctx;
    }

    fn deinit(self: *Sm3BenchContext) void {
        self.allocator.free(self.data_1m);
        self.allocator.free(self.data_10m);
    }
};

var sm3_ctx: ?Sm3BenchContext = null;

pub fn beforeAll() void {
    // Context is initialized in each benchmark function using allocator
}

pub fn afterAll() void {
    if (sm3_ctx) |*ctx| {
        ctx.deinit();
        sm3_ctx = null;
    }
}

/// SM3 hash benchmark (64 B)
pub fn benchSm3Hash64B(allocator: std.mem.Allocator) void {
    const data = "Hello, SM3! This is a benchmark test message for SM3 hash function.";
    _ = sm3.hash(data);
    _ = allocator;
}

/// SM3 hash benchmark (1 KB)
pub fn benchSm3Hash1K(allocator: std.mem.Allocator) void {
    var data: [1024]u8 = undefined;
    for (&data, 0..) |*b, i| {
        b.* = @as(u8, @truncate(i));
    }
    _ = sm3.hash(&data);
    _ = allocator;
}

/// SM3 hash benchmark (64 KB)
pub fn benchSm3Hash64K(allocator: std.mem.Allocator) void {
    var data: [65536]u8 = undefined;
    for (&data, 0..) |*b, i| {
        b.* = @as(u8, @truncate(i));
    }
    _ = sm3.hash(&data);
    _ = allocator;
}

/// SM3 hash benchmark (1 MB)
pub fn benchSm3Hash1M(allocator: std.mem.Allocator) void {
    const data = allocator.alloc(u8, 1024 * 1024) catch return;
    defer allocator.free(data);
    var prng = std.Random.DefaultPrng.init(0);
    prng.random().bytes(data);
    _ = sm3.hash(data);
}

/// SM3 hash benchmark (10 MB)
pub fn benchSm3Hash10M(allocator: std.mem.Allocator) void {
    const data = allocator.alloc(u8, 10 * 1024 * 1024) catch return;
    defer allocator.free(data);
    var prng = std.Random.DefaultPrng.init(0);
    prng.random().bytes(data);
    _ = sm3.hash(data);
}
