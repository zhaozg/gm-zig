const std = @import("std");
const root = @import("../root.zig");
const sm9 = root.sm9;

var bench_threaded: std.Io.Threaded = .init_single_threaded;

fn getIo() std.Io {
    return bench_threaded.io();
}

/// SM9 sign key extraction benchmark
pub fn benchSm9ExtractSignKey(allocator: std.mem.Allocator) void {
    const io = getIo();
    const system = sm9.params.SM9System.init();
    var extract_ctx = sm9.key_extract.KeyExtractionContext.init(system, io, allocator);
    const user_id = "benchmark@test.edu.cn";
    const user_key = extract_ctx.extractSignKey(user_id) catch return;
    _ = user_key;
}

/// SM9 encrypt key extraction benchmark
pub fn benchSm9ExtractEncryptKey(allocator: std.mem.Allocator) void {
    const io = getIo();
    const system = sm9.params.SM9System.init();
    var extract_ctx = sm9.key_extract.KeyExtractionContext.init(system, io, allocator);
    const user_id = "benchmark@test.edu.cn";
    const user_key = extract_ctx.extractEncryptKey(user_id) catch return;
    _ = user_key;
}

/// SM9 signature benchmark (small message)
pub fn benchSm9SignSmall(allocator: std.mem.Allocator) void {
    const io = getIo();
    const system = sm9.params.SM9System.init();
    var sign_ctx = sm9.sign.SignatureContext.init(system, io, allocator);
    const user_id = "benchmark@test.edu.cn";
    var extract_ctx = sm9.key_extract.KeyExtractionContext.init(system, io, allocator);
    const user_key = extract_ctx.extractSignKey(user_id) catch return;
    const message = "Hello SM9!";
    const signature = sign_ctx.sign(message, user_key, .{}) catch return;
    _ = signature;
}

/// SM9 signature benchmark (medium message)
pub fn benchSm9SignMedium(allocator: std.mem.Allocator) void {
    const io = getIo();
    const system = sm9.params.SM9System.init();
    var sign_ctx = sm9.sign.SignatureContext.init(system, io, allocator);
    const user_id = "benchmark@test.edu.cn";
    var extract_ctx = sm9.key_extract.KeyExtractionContext.init(system, io, allocator);
    const user_key = extract_ctx.extractSignKey(user_id) catch return;
    const message = "This is a medium length message for SM9 identity-based cryptography testing.";
    const signature = sign_ctx.sign(message, user_key, .{}) catch return;
    _ = signature;
}

/// SM9 signature verification benchmark (small message)
pub fn benchSm9VerifySmall(allocator: std.mem.Allocator) void {
    const io = getIo();
    const system = sm9.params.SM9System.init();
    var sign_ctx = sm9.sign.SignatureContext.init(system, io, allocator);
    const user_id = "benchmark@test.edu.cn";
    var extract_ctx = sm9.key_extract.KeyExtractionContext.init(system, io, allocator);
    const user_key = extract_ctx.extractSignKey(user_id) catch return;
    const message = "Hello SM9!";
    const signature = sign_ctx.sign(message, user_key, .{}) catch return;
    const valid = sign_ctx.verify(message, signature, user_id, .{}) catch false;
    _ = valid;
}

/// SM9 signature verification benchmark (medium message)
pub fn benchSm9VerifyMedium(allocator: std.mem.Allocator) void {
    const io = getIo();
    const system = sm9.params.SM9System.init();
    var sign_ctx = sm9.sign.SignatureContext.init(system, io, allocator);
    const user_id = "benchmark@test.edu.cn";
    var extract_ctx = sm9.key_extract.KeyExtractionContext.init(system, io, allocator);
    const user_key = extract_ctx.extractSignKey(user_id) catch return;
    const message = "This is a medium length message for SM9 identity-based cryptography testing.";
    const signature = sign_ctx.sign(message, user_key, .{}) catch return;
    const valid = sign_ctx.verify(message, signature, user_id, .{}) catch false;
    _ = valid;
}

/// SM9 encryption benchmark (small message)
pub fn benchSm9EncryptSmall(allocator: std.mem.Allocator) void {
    const io = getIo();
    const system = sm9.params.SM9System.init();
    var enc_ctx = sm9.encrypt.EncryptionContext.init(system, io, allocator);
    const user_id = "benchmark@test.edu.cn";
    const message = "Hello SM9!";
    const ciphertext = enc_ctx.encrypt(message, user_id, .{}) catch return;
    defer ciphertext.deinit();
}

/// SM9 encryption benchmark (medium message)
pub fn benchSm9EncryptMedium(allocator: std.mem.Allocator) void {
    const io = getIo();
    const system = sm9.params.SM9System.init();
    var enc_ctx = sm9.encrypt.EncryptionContext.init(system, io, allocator);
    const user_id = "benchmark@test.edu.cn";
    const message = "This is a medium length message for SM9 identity-based cryptography testing.";
    const ciphertext = enc_ctx.encrypt(message, user_id, .{}) catch return;
    defer ciphertext.deinit();
}

/// SM9 decryption benchmark (small message)
pub fn benchSm9DecryptSmall(allocator: std.mem.Allocator) void {
    const io = getIo();
    const system = sm9.params.SM9System.init();
    var enc_ctx = sm9.encrypt.EncryptionContext.init(system, io, allocator);
    const user_id = "benchmark@test.edu.cn";
    var extract_ctx = sm9.key_extract.KeyExtractionContext.init(system, io, allocator);
    const user_key = extract_ctx.extractEncryptKey(user_id) catch return;
    const message = "Hello SM9!";
    const ciphertext = enc_ctx.encrypt(message, user_id, .{}) catch return;
    defer ciphertext.deinit();
    const decrypted = enc_ctx.decrypt(ciphertext, user_key, .{}) catch return;
    allocator.free(decrypted);
}

/// SM9 decryption benchmark (medium message)
pub fn benchSm9DecryptMedium(allocator: std.mem.Allocator) void {
    const io = getIo();
    const system = sm9.params.SM9System.init();
    var enc_ctx = sm9.encrypt.EncryptionContext.init(system, io, allocator);
    const user_id = "benchmark@test.edu.cn";
    var extract_ctx = sm9.key_extract.KeyExtractionContext.init(system, io, allocator);
    const user_key = extract_ctx.extractEncryptKey(user_id) catch return;
    const message = "This is a medium length message for SM9 identity-based cryptography testing.";
    const ciphertext = enc_ctx.encrypt(message, user_id, .{}) catch return;
    defer ciphertext.deinit();
    const decrypted = enc_ctx.decrypt(ciphertext, user_key, .{}) catch return;
    allocator.free(decrypted);
}
