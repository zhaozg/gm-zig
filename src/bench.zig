const std = @import("std");
const root = @import("./root.zig");
const sm3 = root.sm3;
const sm4 = root.sm4;
const sm2 = root.sm2;
const sm9 = root.sm9;
const zuc = root.zuc;
const zbench = @import("zbench");

/// SM3 hash benchmark (small data)
fn benchSm3HashSmall(allocator: std.mem.Allocator) void {
    const data = "Hello, SM3! This is a benchmark test message for SM3 hash function.";
    _ = sm3.hash(data);
    _ = allocator;
}

/// SM3 hash benchmark (1KB data)
fn benchSm3Hash1K(allocator: std.mem.Allocator) void {
    var data: [1024]u8 = undefined;
    for (&data, 0..) |*b, i| {
        b.* = @as(u8, @truncate(i));
    }
    _ = sm3.hash(&data);
    _ = allocator;
}

/// SM3 hash benchmark (64KB data)
fn benchSm3Hash64K(allocator: std.mem.Allocator) void {
    var data: [65536]u8 = undefined;
    for (&data, 0..) |*b, i| {
        b.* = @as(u8, @truncate(i));
    }
    _ = sm3.hash(&data);
    _ = allocator;
}

/// SM4 ECB encryption benchmark (single block)
fn benchSm4EcbEncrypt(allocator: std.mem.Allocator) void {
    const key = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
    const plaintext = [_]u8{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00 };
    var ciphertext: [16]u8 = undefined;
    var ctx = sm4.SM4_ECB.init(&key);
    ctx.encrypt(&plaintext, &ciphertext);
    _ = allocator;
}

/// SM4 ECB decryption benchmark (single block)
fn benchSm4EcbDecrypt(allocator: std.mem.Allocator) void {
    const key = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
    const ciphertext = [_]u8{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00 };
    var plaintext: [16]u8 = undefined;
    var ctx = sm4.SM4_ECB.init(&key);
    ctx.decrypt(&ciphertext, &plaintext);
    _ = allocator;
}

/// SM4 ECB encryption benchmark (1KB)
fn benchSm4EcbEncrypt1K(allocator: std.mem.Allocator) void {
    const key = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
    var plaintext: [1024]u8 = undefined;
    for (&plaintext, 0..) |*b, i| {
        b.* = @as(u8, @truncate(i));
    }
    var ciphertext: [1024]u8 = undefined;
    var ctx = sm4.SM4_ECB.init(&key);
    ctx.encrypt(&plaintext, &ciphertext);
    _ = allocator;
}

/// SM4 ECB encryption benchmark (64KB)
fn benchSm4EcbEncrypt64K(allocator: std.mem.Allocator) void {
    const key = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
    var plaintext: [65536]u8 = undefined;
    for (&plaintext, 0..) |*b, i| {
        b.* = @as(u8, @truncate(i));
    }
    var ciphertext: [65536]u8 = undefined;
    var ctx = sm4.SM4_ECB.init(&key);
    ctx.encrypt(&plaintext, &ciphertext);
    _ = allocator;
}

/// ZUC keystream generation benchmark
fn benchZucGenerate(allocator: std.mem.Allocator) void {
    const key = [_]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
    const iv = [_]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
    var keystream: [64]u32 = undefined;
    var zuc_ctx = zuc.ZUC.init(&key, &iv);
    zuc_ctx.generateKeystream(&keystream);
    _ = allocator;
}

/// SM2 key generation benchmark
fn benchSm2KeyGen(allocator: std.mem.Allocator) void {
    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();
    const key_pair = sm2.kp.generateKeyPair(io);
    _ = key_pair;
    _ = allocator;
}

/// SM2 signature benchmark
fn benchSm2Sign(allocator: std.mem.Allocator) void {
    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();
    const key_pair = sm2.kp.generateKeyPair(io);
    const message = "Benchmark test message for SM2 signature";
    const options = sm2.signature.SignatureOptions{
        .user_id = "benchmark@test.com",
        .hash_type = .sm3,
    };
    const signature = sm2.signature.sign(io, message, key_pair.private_key, key_pair.public_key, options) catch return;
    _ = signature;
    _ = allocator;
}

/// SM2 signature verification benchmark
fn benchSm2Verify(allocator: std.mem.Allocator) void {
    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();
    const key_pair = sm2.kp.generateKeyPair(io);
    const message = "Benchmark test message for SM2 signature";
    const options = sm2.signature.SignatureOptions{
        .user_id = "benchmark@test.com",
        .hash_type = .sm3,
    };
    const signature = sm2.signature.sign(io, message, key_pair.private_key, key_pair.public_key, options) catch return;
    const valid = sm2.signature.verify(message, signature, key_pair.public_key, options) catch false;
    _ = valid;
    _ = allocator;
}

/// SM2 encryption benchmark
fn benchSm2Encrypt(allocator: std.mem.Allocator) void {
    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();
    const key_pair = sm2.kp.generateKeyPair(io);
    const plaintext = "Hello SM2 Encryption!";
    const ciphertext = sm2.encryption.encrypt(io, allocator, plaintext, key_pair.public_key, .c1c3c2) catch return;
    defer ciphertext.deinit(allocator);
}

/// SM2 decryption benchmark
fn benchSm2Decrypt(allocator: std.mem.Allocator) void {
    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();
    const key_pair = sm2.kp.generateKeyPair(io);
    const plaintext = "Hello SM2 Encryption!";
    const ciphertext = sm2.encryption.encrypt(io, allocator, plaintext, key_pair.public_key, .c1c3c2) catch return;
    defer ciphertext.deinit(allocator);
    const decrypted = sm2.encryption.decrypt(allocator, ciphertext, key_pair.private_key) catch return;
    allocator.free(decrypted);
}

/// SM9 signature benchmark
fn benchSm9Sign(allocator: std.mem.Allocator) void {
    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();
    const system = sm9.params.SM9System.init();
    var sign_ctx = sm9.sign.SignatureContext.init(system, io, allocator);
    const user_id = "Alice";
    var extract_ctx = sm9.key_extract.KeyExtractionContext.init(system, io, allocator);
    const user_key = extract_ctx.extractSignKey(user_id) catch return;
    const message = "Benchmark test message for SM9 signature";
    const signature = sign_ctx.sign(message, user_key, .{}) catch return;
    _ = signature;
}

/// SM9 signature verification benchmark
fn benchSm9Verify(allocator: std.mem.Allocator) void {
    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();
    const system = sm9.params.SM9System.init();
    var sign_ctx = sm9.sign.SignatureContext.init(system, io, allocator);
    const user_id = "Alice";
    var extract_ctx = sm9.key_extract.KeyExtractionContext.init(system, io, allocator);
    const user_key = extract_ctx.extractSignKey(user_id) catch return;
    const message = "Benchmark test message for SM9 signature";
    const signature = sign_ctx.sign(message, user_key, .{}) catch return;
    const valid = sign_ctx.verify(message, signature, user_id, .{}) catch false;
    _ = valid;
}

/// SM9 encryption benchmark
fn benchSm9Encrypt(allocator: std.mem.Allocator) void {
    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();
    const system = sm9.params.SM9System.init();
    var enc_ctx = sm9.encrypt.EncryptionContext.init(system, io, allocator);
    const user_id = "Bob";
    const message = "Benchmark test message for SM9 encryption";
    const ciphertext = enc_ctx.encrypt(message, user_id, .{}) catch return;
    defer ciphertext.deinit();
}

/// SM9 decryption benchmark
fn benchSm9Decrypt(allocator: std.mem.Allocator) void {
    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();
    const system = sm9.params.SM9System.init();
    var enc_ctx = sm9.encrypt.EncryptionContext.init(system, io, allocator);
    const user_id = "Bob";
    var extract_ctx = sm9.key_extract.KeyExtractionContext.init(system, io, allocator);
    const user_key = extract_ctx.extractEncryptKey(user_id) catch return;
    const message = "Benchmark test message for SM9 encryption";
    const ciphertext = enc_ctx.encrypt(message, user_id, .{}) catch return;
    defer ciphertext.deinit();
    const decrypted = enc_ctx.decrypt(ciphertext, user_key, .{}) catch return;
    allocator.free(decrypted);
}

pub fn main() !void {
    var gpa = std.heap.DebugAllocator(.{}).init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();
    const stdout: std.Io.File = .stdout();
    var stdout_w = stdout.writerStreaming(io, &.{});
    const writer: *std.Io.Writer = &stdout_w.interface;

    // Print system information
    const sysinfo = try zbench.getSystemInfo();
    var w: std.Io.File.Writer = stdout.writerStreaming(io, &.{});
    try sysinfo.format(&w.interface);
    writer.print("\n", .{}) catch {};

    var bench = zbench.Benchmark.init(allocator, .{});
    defer bench.deinit();

    // SM3 benchmarks
    try bench.add("SM3 (64 B)    ", benchSm3HashSmall, .{});
    try bench.add("SM3 (1 KB)    ", benchSm3Hash1K, .{});
    try bench.add("SM3 (64KB)    ", benchSm3Hash64K, .{});

    // SM4 benchmarks
    try bench.add("SM4 ECB E/16B ", benchSm4EcbEncrypt, .{});
    try bench.add("SM4 ECB D/16B ", benchSm4EcbDecrypt, .{});
    try bench.add("SM4 ECB E/1KB ", benchSm4EcbEncrypt1K, .{});
    try bench.add("SM4 ECB E/64KB", benchSm4EcbEncrypt64K, .{});

    // ZUC benchmarks
    try bench.add("ZUC KeyGen(64)", benchZucGenerate, .{});

    // SM2 benchmarks
    try bench.add("SM2 KP Gen    ", benchSm2KeyGen, .{});
    try bench.add("SM2 Sign      ", benchSm2Sign, .{});
    try bench.add("SM2 Verify    ", benchSm2Verify, .{});
    try bench.add("SM2 Encrypt   ", benchSm2Encrypt, .{});
    try bench.add("SM2 Decrypt   ", benchSm2Decrypt, .{});

    // SM9 benchmarks
    try bench.add("SM9 Sign      ", benchSm9Sign, .{});
    try bench.add("SM9 Verify    ", benchSm9Verify, .{});
    try bench.add("SM9 Encrypt   ", benchSm9Encrypt, .{});
    try bench.add("SM9 Decrypt   ", benchSm9Decrypt, .{});

    try bench.run(io, stdout);
}
