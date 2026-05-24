const std = @import("std");
const root = @import("../root.zig");
const sm4 = root.sm4;

/// SM4 ECB encryption benchmark (single block)
pub fn benchSm4EcbEncrypt16B(allocator: std.mem.Allocator) void {
    const key = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
    const plaintext = [_]u8{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00 };
    var ciphertext: [16]u8 = undefined;
    var ctx = sm4.SM4_ECB.init(&key);
    ctx.encrypt(&plaintext, &ciphertext);
    _ = allocator;
}

/// SM4 ECB decryption benchmark (single block)
pub fn benchSm4EcbDecrypt16B(allocator: std.mem.Allocator) void {
    const key = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
    const ciphertext = [_]u8{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00 };
    var plaintext: [16]u8 = undefined;
    var ctx = sm4.SM4_ECB.init(&key);
    ctx.decrypt(&ciphertext, &plaintext);
    _ = allocator;
}

/// SM4 ECB encryption benchmark (1 KB)
pub fn benchSm4EcbEncrypt1K(allocator: std.mem.Allocator) void {
    const key = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
    const size: usize = 1024;
    const plaintext = allocator.alloc(u8, size) catch return;
    defer allocator.free(plaintext);
    const ciphertext = allocator.alloc(u8, size) catch return;
    defer allocator.free(ciphertext);
    var prng = std.Random.DefaultPrng.init(0);
    prng.random().bytes(plaintext);
    var ctx = sm4.SM4_ECB.init(&key);
    ctx.encrypt(plaintext, ciphertext);
}

/// SM4 ECB encryption benchmark (64 KB)
pub fn benchSm4EcbEncrypt64K(allocator: std.mem.Allocator) void {
    const key = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
    const size: usize = 64 * 1024;
    const plaintext = allocator.alloc(u8, size) catch return;
    defer allocator.free(plaintext);
    const ciphertext = allocator.alloc(u8, size) catch return;
    defer allocator.free(ciphertext);
    var prng = std.Random.DefaultPrng.init(0);
    prng.random().bytes(plaintext);
    var ctx = sm4.SM4_ECB.init(&key);
    ctx.encrypt(plaintext, ciphertext);
}

/// SM4 ECB decryption benchmark (1 KB)
pub fn benchSm4EcbDecrypt1K(allocator: std.mem.Allocator) void {
    const key = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
    const size: usize = 1024;
    const ciphertext = allocator.alloc(u8, size) catch return;
    defer allocator.free(ciphertext);
    const plaintext = allocator.alloc(u8, size) catch return;
    defer allocator.free(plaintext);
    var prng = std.Random.DefaultPrng.init(0);
    prng.random().bytes(ciphertext);
    var ctx = sm4.SM4_ECB.init(&key);
    ctx.decrypt(ciphertext, plaintext);
}

/// SM4 ECB decryption benchmark (64 KB)
pub fn benchSm4EcbDecrypt64K(allocator: std.mem.Allocator) void {
    const key = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
    const size: usize = 64 * 1024;
    const ciphertext = allocator.alloc(u8, size) catch return;
    defer allocator.free(ciphertext);
    const plaintext = allocator.alloc(u8, size) catch return;
    defer allocator.free(plaintext);
    var prng = std.Random.DefaultPrng.init(0);
    prng.random().bytes(ciphertext);
    var ctx = sm4.SM4_ECB.init(&key);
    ctx.decrypt(ciphertext, plaintext);
}

/// SM4 ECB encryption benchmark (1 MB)
pub fn benchSm4EcbEncrypt1M(allocator: std.mem.Allocator) void {
    const key = [_]u8{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10 };
    const size = 1024 * 1024;
    const buf = allocator.alloc(u8, size) catch return;
    defer allocator.free(buf);
    const out = allocator.alloc(u8, size) catch return;
    defer allocator.free(out);
    var prng = std.Random.DefaultPrng.init(0);
    prng.random().bytes(buf);
    const ctx = sm4.SM4.init(&key);
    const blocks = size / 16;
    for (0..blocks) |i| {
        const start = i * 16;
        ctx.encryptBlock(buf[start..][0..16], out[start..][0..16]);
    }
}

/// SM4 ECB decryption benchmark (1 MB)
pub fn benchSm4EcbDecrypt1M(allocator: std.mem.Allocator) void {
    const key = [_]u8{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10 };
    const size = 1024 * 1024;
    const buf = allocator.alloc(u8, size) catch return;
    defer allocator.free(buf);
    const out = allocator.alloc(u8, size) catch return;
    defer allocator.free(out);
    var prng = std.Random.DefaultPrng.init(0);
    prng.random().bytes(buf);
    const ctx = sm4.SM4.init(&key);
    const blocks = size / 16;
    for (0..blocks) |i| {
        const start = i * 16;
        ctx.decryptBlock(buf[start..][0..16], out[start..][0..16]);
    }
}

/// SM4 CBC encryption benchmark (1 KB)
pub fn benchSm4CbcEncrypt1K(allocator: std.mem.Allocator) void {
    const key = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
    const iv = [_]u8{0x00} ** 16;
    const size: usize = 1024;
    const plaintext = allocator.alloc(u8, size) catch return;
    defer allocator.free(plaintext);
    const ciphertext = allocator.alloc(u8, size + 16) catch return;
    defer allocator.free(ciphertext);
    var prng = std.Random.DefaultPrng.init(0);
    prng.random().bytes(plaintext);
    var ctx = sm4.SM4_CBC.init(&key, &iv);
    ctx.encrypt(plaintext, ciphertext);
}

/// SM4 CBC decryption benchmark (1 KB)
pub fn benchSm4CbcDecrypt1K(allocator: std.mem.Allocator) void {
    const key = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
    const iv = [_]u8{0x00} ** 16;
    const size: usize = 1024;
    const ciphertext = allocator.alloc(u8, size + 16) catch return;
    defer allocator.free(ciphertext);
    const plaintext = allocator.alloc(u8, size) catch return;
    defer allocator.free(plaintext);
    var prng = std.Random.DefaultPrng.init(0);
    prng.random().bytes(ciphertext[0..size]);
    var ctx = sm4.SM4_CBC.init(&key, &iv);
    ctx.decrypt(ciphertext[0..size], plaintext);
}

/// SM4 CTR encryption benchmark (1 KB)
pub fn benchSm4CtrEncrypt1K(allocator: std.mem.Allocator) void {
    const key = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
    const nonce = [_]u8{0x00} ** 16;
    const size: usize = 1024;
    const plaintext = allocator.alloc(u8, size) catch return;
    defer allocator.free(plaintext);
    const ciphertext = allocator.alloc(u8, size) catch return;
    defer allocator.free(ciphertext);
    var prng = std.Random.DefaultPrng.init(0);
    prng.random().bytes(plaintext);
    var ctx = sm4.SM4_CTR.init(&key, &nonce);
    ctx.encrypt(plaintext, ciphertext);
}

/// SM4 CTR encryption benchmark (64 KB)
pub fn benchSm4CtrEncrypt64K(allocator: std.mem.Allocator) void {
    const key = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
    const nonce = [_]u8{0x00} ** 16;
    const size: usize = 64 * 1024;
    const plaintext = allocator.alloc(u8, size) catch return;
    defer allocator.free(plaintext);
    const ciphertext = allocator.alloc(u8, size) catch return;
    defer allocator.free(ciphertext);
    var prng = std.Random.DefaultPrng.init(0);
    prng.random().bytes(plaintext);
    var ctx = sm4.SM4_CTR.init(&key, &nonce);
    ctx.encrypt(plaintext, ciphertext);
}

/// SM4 CTR decryption benchmark (1 KB)
pub fn benchSm4CtrDecrypt1K(allocator: std.mem.Allocator) void {
    const key = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
    const nonce = [_]u8{0x00} ** 16;
    const size: usize = 1024;
    const ciphertext = allocator.alloc(u8, size) catch return;
    defer allocator.free(ciphertext);
    const plaintext = allocator.alloc(u8, size) catch return;
    defer allocator.free(plaintext);
    var prng = std.Random.DefaultPrng.init(0);
    prng.random().bytes(ciphertext);
    var ctx = sm4.SM4_CTR.init(&key, &nonce);
    ctx.decrypt(ciphertext, plaintext);
}

/// SM4 CTR decryption benchmark (64 KB)
pub fn benchSm4CtrDecrypt64K(allocator: std.mem.Allocator) void {
    const key = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
    const nonce = [_]u8{0x00} ** 16;
    const size: usize = 64 * 1024;
    const ciphertext = allocator.alloc(u8, size) catch return;
    defer allocator.free(ciphertext);
    const plaintext = allocator.alloc(u8, size) catch return;
    defer allocator.free(plaintext);
    var prng = std.Random.DefaultPrng.init(0);
    prng.random().bytes(ciphertext);
    var ctx = sm4.SM4_CTR.init(&key, &nonce);
    ctx.decrypt(ciphertext, plaintext);
}

/// SM4 GCM seal benchmark (1 KB)
pub fn benchSm4GcmSeal1K(allocator: std.mem.Allocator) void {
    const key = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
    const nonce = [_]u8{0x00} ** 12;
    const aad = "additional data";
    const size: usize = 1024;
    const plaintext = allocator.alloc(u8, size) catch return;
    defer allocator.free(plaintext);
    const ciphertext = allocator.alloc(u8, size) catch return;
    defer allocator.free(ciphertext);
    var tag: [16]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(0);
    prng.random().bytes(plaintext);
    var ctx = sm4.SM4_GCM.init(&key);
    ctx.encrypt(&nonce, plaintext, aad, ciphertext, &tag);
    std.mem.doNotOptimizeAway(tag);
}

/// SM4 GCM seal benchmark (64 KB)
pub fn benchSm4GcmSeal64K(allocator: std.mem.Allocator) void {
    const key = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
    const nonce = [_]u8{0x00} ** 12;
    const aad = "additional data";
    const size: usize = 64 * 1024;
    const plaintext = allocator.alloc(u8, size) catch return;
    defer allocator.free(plaintext);
    const ciphertext = allocator.alloc(u8, size) catch return;
    defer allocator.free(ciphertext);
    var tag: [16]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(0);
    prng.random().bytes(plaintext);
    var ctx = sm4.SM4_GCM.init(&key);
    ctx.encrypt(&nonce, plaintext, aad, ciphertext, &tag);
    std.mem.doNotOptimizeAway(tag);
}

/// SM4 XTS encryption benchmark (1 KB)
pub fn benchSm4XtsEncrypt1K(allocator: std.mem.Allocator) void {
    const key = [_]u8{0x01} ** 32;
    const size: usize = 1024;
    const plaintext = allocator.alloc(u8, size) catch return;
    defer allocator.free(plaintext);
    const ciphertext = allocator.alloc(u8, size) catch return;
    defer allocator.free(ciphertext);
    var prng = std.Random.DefaultPrng.init(0);
    prng.random().bytes(plaintext);
    var ctx = sm4.SM4_XTS.init(&key);
    ctx.encrypt(0, plaintext, ciphertext);
}

/// SM4 XTS encryption benchmark (64 KB)
pub fn benchSm4XtsEncrypt64K(allocator: std.mem.Allocator) void {
    const key = [_]u8{0x01} ** 32;
    const size: usize = 64 * 1024;
    const plaintext = allocator.alloc(u8, size) catch return;
    defer allocator.free(plaintext);
    const ciphertext = allocator.alloc(u8, size) catch return;
    defer allocator.free(ciphertext);
    var prng = std.Random.DefaultPrng.init(0);
    prng.random().bytes(plaintext);
    var ctx = sm4.SM4_XTS.init(&key);
    ctx.encrypt(0, plaintext, ciphertext);
}

/// SM4 XTS decryption benchmark (1 KB)
pub fn benchSm4XtsDecrypt1K(allocator: std.mem.Allocator) void {
    const key = [_]u8{0x01} ** 32;
    const size: usize = 1024;
    const ciphertext = allocator.alloc(u8, size) catch return;
    defer allocator.free(ciphertext);
    const plaintext = allocator.alloc(u8, size) catch return;
    defer allocator.free(plaintext);
    var prng = std.Random.DefaultPrng.init(0);
    prng.random().bytes(ciphertext);
    var ctx = sm4.SM4_XTS.init(&key);
    ctx.decrypt(0, ciphertext, plaintext);
}

/// SM4 XTS decryption benchmark (64 KB)
pub fn benchSm4XtsDecrypt64K(allocator: std.mem.Allocator) void {
    const key = [_]u8{0x01} ** 32;
    const size: usize = 64 * 1024;
    const ciphertext = allocator.alloc(u8, size) catch return;
    defer allocator.free(ciphertext);
    const plaintext = allocator.alloc(u8, size) catch return;
    defer allocator.free(plaintext);
    var prng = std.Random.DefaultPrng.init(0);
    prng.random().bytes(ciphertext);
    var ctx = sm4.SM4_XTS.init(&key);
    ctx.decrypt(0, ciphertext, plaintext);
}
