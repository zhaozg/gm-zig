const std = @import("std");
const root = @import("./root.zig");
const sm3 = root.sm3;
const sm4 = root.sm4;
const sm2 = root.sm2;
const sm9 = root.sm9;
const zuc = root.zuc;
const zbench = @import("zbench");

/// SM3 hash benchmark (64 B)
fn benchSm3Hash64B(allocator: std.mem.Allocator) void {
    const data = "Hello, SM3! This is a benchmark test message for SM3 hash function.";
    _ = sm3.hash(data);
    _ = allocator;
}

/// SM3 hash benchmark (1 KB)
fn benchSm3Hash1K(allocator: std.mem.Allocator) void {
    var data: [1024]u8 = undefined;
    for (&data, 0..) |*b, i| {
        b.* = @as(u8, @truncate(i));
    }
    _ = sm3.hash(&data);
    _ = allocator;
}

/// SM3 hash benchmark (64 KB)
fn benchSm3Hash64K(allocator: std.mem.Allocator) void {
    var data: [65536]u8 = undefined;
    for (&data, 0..) |*b, i| {
        b.* = @as(u8, @truncate(i));
    }
    _ = sm3.hash(&data);
    _ = allocator;
}

/// SM3 hash benchmark (1 MB)
fn benchSm3Hash1M(allocator: std.mem.Allocator) void {
    const data = allocator.alloc(u8, 1024 * 1024) catch return;
    defer allocator.free(data);
    var prng = std.Random.DefaultPrng.init(0);
    prng.random().bytes(data);
    _ = sm3.hash(data);
}

/// SM3 hash benchmark (10 MB)
fn benchSm3Hash10M(allocator: std.mem.Allocator) void {
    const data = allocator.alloc(u8, 10 * 1024 * 1024) catch return;
    defer allocator.free(data);
    var prng = std.Random.DefaultPrng.init(0);
    prng.random().bytes(data);
    _ = sm3.hash(data);
}

/// SM4 ECB encryption benchmark (single block)
fn benchSm4EcbEncrypt16B(allocator: std.mem.Allocator) void {
    const key = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
    const plaintext = [_]u8{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00 };
    var ciphertext: [16]u8 = undefined;
    var ctx = sm4.SM4_ECB.init(&key);
    ctx.encrypt(&plaintext, &ciphertext);
    _ = allocator;
}

/// SM4 ECB decryption benchmark (single block)
fn benchSm4EcbDecrypt16B(allocator: std.mem.Allocator) void {
    const key = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
    const ciphertext = [_]u8{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00 };
    var plaintext: [16]u8 = undefined;
    var ctx = sm4.SM4_ECB.init(&key);
    ctx.decrypt(&ciphertext, &plaintext);
    _ = allocator;
}

/// SM4 ECB encryption benchmark (1 KB)
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

/// SM4 ECB encryption benchmark (64 KB)
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

/// SM4 ECB encryption benchmark (1 MB)
fn benchSm4EcbEncrypt1M(allocator: std.mem.Allocator) void {
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
fn benchSm4EcbDecrypt1M(allocator: std.mem.Allocator) void {
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

/// ZUC keystream generation benchmark (64 words)
fn benchZucKeystream(allocator: std.mem.Allocator) void {
    const key = [_]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
    const iv = [_]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
    var keystream: [64]u32 = undefined;
    var zuc_ctx = zuc.ZUC.init(&key, &iv);
    zuc_ctx.generateKeystream(&keystream);
    _ = allocator;
}

/// ZUC crypt benchmark (1 KB)
fn benchZucCrypt1K(allocator: std.mem.Allocator) void {
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
}

/// ZUC crypt benchmark (64 KB)
fn benchZucCrypt64K(allocator: std.mem.Allocator) void {
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
}

/// ZUC crypt benchmark (1 MB)
fn benchZucCrypt1M(allocator: std.mem.Allocator) void {
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
}

/// ZUC MAC generation benchmark (16 B)
fn benchZucMac16B(allocator: std.mem.Allocator) void {
    const key = [_]u8{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    const iv = [_]u8{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    const message = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
    _ = zuc.ZUC.generateMACWithKey(&key, &iv, &message);
    _ = allocator;
}

/// ZUC MAC generation benchmark (4 KB)
fn benchZucMac4K(allocator: std.mem.Allocator) void {
    const key = [_]u8{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    const iv = [_]u8{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    const size: usize = 4096;
    const message = allocator.alloc(u8, size) catch return;
    defer allocator.free(message);
    var prng = std.Random.DefaultPrng.init(0);
    prng.random().bytes(message);
    _ = zuc.ZUC.generateMACWithKey(&key, &iv, message);
}

/// SM2 key generation benchmark
fn benchSm2KeyGen(allocator: std.mem.Allocator) void {
    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();
    const key_pair = sm2.kp.generateKeyPair(io);
    _ = key_pair;
    _ = allocator;
}

/// SM2 signature benchmark (small message)
fn benchSm2SignSmall(allocator: std.mem.Allocator) void {
    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();
    const key_pair = sm2.kp.generateKeyPair(io);
    const message = "Hello SM2!";
    const options = sm2.signature.SignatureOptions{
        .user_id = "benchmark@test.com",
        .hash_type = .sm3,
    };
    const signature = sm2.signature.sign(io, message, key_pair.private_key, key_pair.public_key, options) catch return;
    _ = signature;
    _ = allocator;
}

/// SM2 signature benchmark (medium message)
fn benchSm2SignMedium(allocator: std.mem.Allocator) void {
    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();
    const key_pair = sm2.kp.generateKeyPair(io);
    const message = "This is a medium length message for SM2 testing that contains multiple words and sentences to provide a realistic benchmark scenario.";
    const options = sm2.signature.SignatureOptions{
        .user_id = "benchmark@test.com",
        .hash_type = .sm3,
    };
    const signature = sm2.signature.sign(io, message, key_pair.private_key, key_pair.public_key, options) catch return;
    _ = signature;
    _ = allocator;
}

/// SM2 signature verification benchmark (small message)
fn benchSm2VerifySmall(allocator: std.mem.Allocator) void {
    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();
    const key_pair = sm2.kp.generateKeyPair(io);
    const message = "Hello SM2!";
    const options = sm2.signature.SignatureOptions{
        .user_id = "benchmark@test.com",
        .hash_type = .sm3,
    };
    const signature = sm2.signature.sign(io, message, key_pair.private_key, key_pair.public_key, options) catch return;
    const valid = sm2.signature.verify(message, signature, key_pair.public_key, options) catch false;
    _ = valid;
    _ = allocator;
}

/// SM2 signature verification benchmark (medium message)
fn benchSm2VerifyMedium(allocator: std.mem.Allocator) void {
    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();
    const key_pair = sm2.kp.generateKeyPair(io);
    const message = "This is a medium length message for SM2 testing that contains multiple words and sentences to provide a realistic benchmark scenario.";
    const options = sm2.signature.SignatureOptions{
        .user_id = "benchmark@test.com",
        .hash_type = .sm3,
    };
    const signature = sm2.signature.sign(io, message, key_pair.private_key, key_pair.public_key, options) catch return;
    const valid = sm2.signature.verify(message, signature, key_pair.public_key, options) catch false;
    _ = valid;
    _ = allocator;
}

/// SM2 encryption benchmark (small message)
fn benchSm2EncryptSmall(allocator: std.mem.Allocator) void {
    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();
    const key_pair = sm2.kp.generateKeyPair(io);
    const plaintext = "Hello SM2!";
    const ciphertext = sm2.encryption.encrypt(io, allocator, plaintext, key_pair.public_key, .c1c3c2) catch return;
    defer ciphertext.deinit(allocator);
}

/// SM2 encryption benchmark (medium message)
fn benchSm2EncryptMedium(allocator: std.mem.Allocator) void {
    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();
    const key_pair = sm2.kp.generateKeyPair(io);
    const plaintext = "This is a medium length message for SM2 testing that contains multiple words and sentences to provide a realistic benchmark scenario.";
    const ciphertext = sm2.encryption.encrypt(io, allocator, plaintext, key_pair.public_key, .c1c3c2) catch return;
    defer ciphertext.deinit(allocator);
}

/// SM2 decryption benchmark (small message)
fn benchSm2DecryptSmall(allocator: std.mem.Allocator) void {
    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();
    const key_pair = sm2.kp.generateKeyPair(io);
    const plaintext = "Hello SM2!";
    const ciphertext = sm2.encryption.encrypt(io, allocator, plaintext, key_pair.public_key, .c1c3c2) catch return;
    defer ciphertext.deinit(allocator);
    const decrypted = sm2.encryption.decrypt(allocator, ciphertext, key_pair.private_key) catch return;
    allocator.free(decrypted);
}

/// SM2 decryption benchmark (medium message)
fn benchSm2DecryptMedium(allocator: std.mem.Allocator) void {
    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();
    const key_pair = sm2.kp.generateKeyPair(io);
    const plaintext = "This is a medium length message for SM2 testing that contains multiple words and sentences to provide a realistic benchmark scenario.";
    const ciphertext = sm2.encryption.encrypt(io, allocator, plaintext, key_pair.public_key, .c1c3c2) catch return;
    defer ciphertext.deinit(allocator);
    const decrypted = sm2.encryption.decrypt(allocator, ciphertext, key_pair.private_key) catch return;
    allocator.free(decrypted);
}

/// SM9 sign key extraction benchmark
fn benchSm9ExtractSignKey(allocator: std.mem.Allocator) void {
    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();
    const system = sm9.params.SM9System.init();
    var extract_ctx = sm9.key_extract.KeyExtractionContext.init(system, io, allocator);
    const user_id = "benchmark@test.edu.cn";
    const user_key = extract_ctx.extractSignKey(user_id) catch return;
    _ = user_key;
}

/// SM9 encrypt key extraction benchmark
fn benchSm9ExtractEncryptKey(allocator: std.mem.Allocator) void {
    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();
    const system = sm9.params.SM9System.init();
    var extract_ctx = sm9.key_extract.KeyExtractionContext.init(system, io, allocator);
    const user_id = "benchmark@test.edu.cn";
    const user_key = extract_ctx.extractEncryptKey(user_id) catch return;
    _ = user_key;
}

/// SM9 signature benchmark (small message)
fn benchSm9SignSmall(allocator: std.mem.Allocator) void {
    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();
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
fn benchSm9SignMedium(allocator: std.mem.Allocator) void {
    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();
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
fn benchSm9VerifySmall(allocator: std.mem.Allocator) void {
    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();
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
fn benchSm9VerifyMedium(allocator: std.mem.Allocator) void {
    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();
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
fn benchSm9EncryptSmall(allocator: std.mem.Allocator) void {
    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();
    const system = sm9.params.SM9System.init();
    var enc_ctx = sm9.encrypt.EncryptionContext.init(system, io, allocator);
    const user_id = "benchmark@test.edu.cn";
    const message = "Hello SM9!";
    const ciphertext = enc_ctx.encrypt(message, user_id, .{}) catch return;
    defer ciphertext.deinit();
}

/// SM9 encryption benchmark (medium message)
fn benchSm9EncryptMedium(allocator: std.mem.Allocator) void {
    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();
    const system = sm9.params.SM9System.init();
    var enc_ctx = sm9.encrypt.EncryptionContext.init(system, io, allocator);
    const user_id = "benchmark@test.edu.cn";
    const message = "This is a medium length message for SM9 identity-based cryptography testing.";
    const ciphertext = enc_ctx.encrypt(message, user_id, .{}) catch return;
    defer ciphertext.deinit();
}

/// SM9 decryption benchmark (small message)
fn benchSm9DecryptSmall(allocator: std.mem.Allocator) void {
    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();
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
fn benchSm9DecryptMedium(allocator: std.mem.Allocator) void {
    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();
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

pub fn main() !void {
    const allocator = std.heap.c_allocator;

    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();
    const stdout: std.Io.File = .stdout();

    // Print system information
    const sysinfo = try zbench.getSystemInfo();
    var w: std.Io.File.Writer = stdout.writerStreaming(io, &.{});
    try sysinfo.format(&w.interface);

    var bench = zbench.Benchmark.init(allocator, .{});
    defer bench.deinit();

    // SM3 benchmarks
    try bench.add("SM3 hash 64B  ", benchSm3Hash64B, .{});
    try bench.add("SM3 hash 1K   ", benchSm3Hash1K, .{});
    try bench.add("SM3 hash 64K  ", benchSm3Hash64K, .{});
    try bench.add("SM3 hash 1M   ", benchSm3Hash1M, .{});
    try bench.add("SM3 hash 10M  ", benchSm3Hash10M, .{});

    // SM4 benchmarks
    try bench.add("SM4 ECB E 16B ", benchSm4EcbEncrypt16B, .{});
    try bench.add("SM4 ECB D 16B ", benchSm4EcbDecrypt16B, .{});
    try bench.add("SM4 ECB E 1K  ", benchSm4EcbEncrypt1K, .{});
    try bench.add("SM4 ECB E 64K ", benchSm4EcbEncrypt64K, .{});
    try bench.add("SM4 ECB E 1M  ", benchSm4EcbEncrypt1M, .{});
    try bench.add("SM4 ECB D 1M  ", benchSm4EcbDecrypt1M, .{});

    // ZUC benchmarks
    try bench.add("ZUC key stream ", benchZucKeystream, .{});
    try bench.add("ZUC crypt 1K   ", benchZucCrypt1K, .{});
    try bench.add("ZUC crypt 64K  ", benchZucCrypt64K, .{});
    try bench.add("ZUC crypt 1M   ", benchZucCrypt1M, .{});
    try bench.add("ZUC MAC 16B    ", benchZucMac16B, .{});
    try bench.add("ZUC MAC 4K     ", benchZucMac4K, .{});

    // SM2 benchmarks
    try bench.add("SM2 key gen    ", benchSm2KeyGen, .{});
    try bench.add("SM2 sign small ", benchSm2SignSmall, .{});
    try bench.add("SM2 sign med   ", benchSm2SignMedium, .{});
    try bench.add("SM2 verify sml ", benchSm2VerifySmall, .{});
    try bench.add("SM2 verify med ", benchSm2VerifyMedium, .{});
    try bench.add("SM2 enc small  ", benchSm2EncryptSmall, .{});
    try bench.add("SM2 enc med    ", benchSm2EncryptMedium, .{});
    try bench.add("SM2 dec small  ", benchSm2DecryptSmall, .{});
    try bench.add("SM2 dec med    ", benchSm2DecryptMedium, .{});

    // SM9 benchmarks
    try bench.add("SM9 ext sign   ", benchSm9ExtractSignKey, .{});
    try bench.add("SM9 ext enc    ", benchSm9ExtractEncryptKey, .{});
    try bench.add("SM9 sign small ", benchSm9SignSmall, .{});
    try bench.add("SM9 sign med   ", benchSm9SignMedium, .{});
    try bench.add("SM9 verify sml ", benchSm9VerifySmall, .{});
    try bench.add("SM9 verify med ", benchSm9VerifyMedium, .{});
    try bench.add("SM9 enc small  ", benchSm9EncryptSmall, .{});
    try bench.add("SM9 enc med    ", benchSm9EncryptMedium, .{});
    try bench.add("SM9 dec small  ", benchSm9DecryptSmall, .{});
    try bench.add("SM9 dec med    ", benchSm9DecryptMedium, .{});

    try bench.run(io, stdout);
}
