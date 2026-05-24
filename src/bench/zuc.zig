const std = @import("std");
const root = @import("../root.zig");
const zuc = root.zuc;

/// ZUC keystream generation benchmark (64 words)
pub fn benchZucKeystream(allocator: std.mem.Allocator) void {
    const key = [_]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
    const iv = [_]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
    var keystream: [64]u32 = undefined;
    var zuc_ctx = zuc.ZUC.init(&key, &iv);
    zuc_ctx.generateKeystream(&keystream);
    std.mem.doNotOptimizeAway(keystream);
    _ = allocator;
}

/// ZUC crypt benchmark (1 KB)
pub fn benchZucCrypt1K(allocator: std.mem.Allocator) void {
    const key = [_]u8{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    const iv = [_]u8{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    const size: usize = 1024;
    const plaintext = allocator.alloc(u8, size) catch return;
    defer allocator.free(plaintext);
    const ciphertext = allocator.alloc(u8, size) catch return;
    defer allocator.free(ciphertext);
    var prng = std.Random.DefaultPrng.init(0);
    prng.random().bytes(plaintext);
    var ctx = zuc.ZUC.init(&key, &iv);
    ctx.crypt(plaintext, ciphertext);
    std.mem.doNotOptimizeAway(ciphertext);
}

/// ZUC crypt benchmark (64 KB)
pub fn benchZucCrypt64K(allocator: std.mem.Allocator) void {
    const key = [_]u8{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    const iv = [_]u8{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    const size: usize = 64 * 1024;
    const plaintext = allocator.alloc(u8, size) catch return;
    defer allocator.free(plaintext);
    const ciphertext = allocator.alloc(u8, size) catch return;
    defer allocator.free(ciphertext);
    var prng = std.Random.DefaultPrng.init(0);
    prng.random().bytes(plaintext);
    var ctx = zuc.ZUC.init(&key, &iv);
    ctx.crypt(plaintext, ciphertext);
    std.mem.doNotOptimizeAway(ciphertext);
}

/// ZUC crypt benchmark (1 MB)
pub fn benchZucCrypt1M(allocator: std.mem.Allocator) void {
    const key = [_]u8{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    const iv = [_]u8{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    const size: usize = 1024 * 1024;
    const plaintext = allocator.alloc(u8, size) catch return;
    defer allocator.free(plaintext);
    const ciphertext = allocator.alloc(u8, size) catch return;
    defer allocator.free(ciphertext);
    var prng = std.Random.DefaultPrng.init(0);
    prng.random().bytes(plaintext);
    var ctx = zuc.ZUC.init(&key, &iv);
    ctx.crypt(plaintext, ciphertext);
    std.mem.doNotOptimizeAway(ciphertext);
}

/// ZUC MAC generation benchmark (16 B)
pub fn benchZucMac16B(allocator: std.mem.Allocator) void {
    const key = [_]u8{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    const iv = [_]u8{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    const message = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
    var zuc_ctx = zuc.ZUC.init(&key, &iv);
    const mac = zuc_ctx.generateMAC(&message);
    std.mem.doNotOptimizeAway(mac);
    _ = allocator;
}

/// ZUC MAC generation benchmark (4 KB)
pub fn benchZucMac4K(allocator: std.mem.Allocator) void {
    const key = [_]u8{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    const iv = [_]u8{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    const size: usize = 4096;
    const message = allocator.alloc(u8, size) catch return;
    defer allocator.free(message);
    var prng = std.Random.DefaultPrng.init(0);
    prng.random().bytes(message);
    var zuc_ctx = zuc.ZUC.init(&key, &iv);
    const mac = zuc_ctx.generateMAC(message);
    std.mem.doNotOptimizeAway(mac);
}

/// ZUC-AEAD seal benchmark (1 KB)
pub fn benchZucAeadSeal1K(allocator: std.mem.Allocator) void {
    const key = [_]u8{0x01} ** 16;
    const iv = [_]u8{0x02} ** 16;
    const aad = "additional authenticated data";
    const size: usize = 1024;
    const plaintext = allocator.alloc(u8, size) catch return;
    defer allocator.free(plaintext);
    const ciphertext = allocator.alloc(u8, size) catch return;
    defer allocator.free(ciphertext);
    var tag: [4]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(0);
    prng.random().bytes(plaintext);
    var aead = zuc.ZUC_AEAD.init(&key, &iv);
    aead.seal(plaintext, aad, ciphertext, &tag);
    std.mem.doNotOptimizeAway(tag);
}

/// ZUC-AEAD seal benchmark (64 KB)
pub fn benchZucAeadSeal64K(allocator: std.mem.Allocator) void {
    const key = [_]u8{0x01} ** 16;
    const iv = [_]u8{0x02} ** 16;
    const aad = "additional authenticated data";
    const size: usize = 64 * 1024;
    const plaintext = allocator.alloc(u8, size) catch return;
    defer allocator.free(plaintext);
    const ciphertext = allocator.alloc(u8, size) catch return;
    defer allocator.free(ciphertext);
    var tag: [4]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(0);
    prng.random().bytes(plaintext);
    var aead = zuc.ZUC_AEAD.init(&key, &iv);
    aead.seal(plaintext, aad, ciphertext, &tag);
    std.mem.doNotOptimizeAway(tag);
}
