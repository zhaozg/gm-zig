const std = @import("std");
const root = @import("../root.zig");
const sm2 = root.sm2;

var bench_threaded: std.Io.Threaded = .init_single_threaded;

fn getIo() std.Io {
    return bench_threaded.io();
}

fn genKeyPair() sm2.kp.KeyPair {
    return sm2.kp.generateKeyPair(getIo());
}

const small_msg = "Hello SM2!";
const med_msg = "This is a medium length message for SM2 testing that contains multiple words and sentences to provide a realistic benchmark scenario.";

const sign_options = sm2.signature.SignatureOptions{
    .user_id = "benchmark@test.com",
    .hash_type = .sm3,
};

/// SM2 key generation benchmark
pub fn benchSm2KeyGen(allocator: std.mem.Allocator) void {
    _ = genKeyPair();
    _ = allocator;
}

/// SM2 signature benchmark (small message)
pub fn benchSm2SignSmall(allocator: std.mem.Allocator) void {
    const kp = genKeyPair();
    _ = sm2.signature.sign(getIo(), small_msg, kp.private_key, kp.public_key, sign_options) catch return;
    _ = allocator;
}

/// SM2 signature benchmark (medium message)
pub fn benchSm2SignMedium(allocator: std.mem.Allocator) void {
    const kp = genKeyPair();
    _ = sm2.signature.sign(getIo(), med_msg, kp.private_key, kp.public_key, sign_options) catch return;
    _ = allocator;
}

/// SM2 signature verification benchmark (small message)
pub fn benchSm2VerifySmall(allocator: std.mem.Allocator) void {
    const kp = genKeyPair();
    const sig = sm2.signature.sign(getIo(), small_msg, kp.private_key, kp.public_key, sign_options) catch return;
    _ = sm2.signature.verify(small_msg, sig, kp.public_key, sign_options) catch false;
    _ = allocator;
}

/// SM2 signature verification benchmark (medium message)
pub fn benchSm2VerifyMedium(allocator: std.mem.Allocator) void {
    const kp = genKeyPair();
    const sig = sm2.signature.sign(getIo(), med_msg, kp.private_key, kp.public_key, sign_options) catch return;
    _ = sm2.signature.verify(med_msg, sig, kp.public_key, sign_options) catch false;
    _ = allocator;
}

/// SM2 encryption benchmark (small message)
pub fn benchSm2EncryptSmall(allocator: std.mem.Allocator) void {
    const kp = genKeyPair();
    const ct = sm2.encryption.encrypt(getIo(), allocator, small_msg, kp.public_key, .c1c3c2) catch return;
    defer ct.deinit(allocator);
}

/// SM2 encryption benchmark (medium message)
pub fn benchSm2EncryptMedium(allocator: std.mem.Allocator) void {
    const kp = genKeyPair();
    const ct = sm2.encryption.encrypt(getIo(), allocator, med_msg, kp.public_key, .c1c3c2) catch return;
    defer ct.deinit(allocator);
}

/// SM2 decryption benchmark (small message)
pub fn benchSm2DecryptSmall(allocator: std.mem.Allocator) void {
    const kp = genKeyPair();
    const ct = sm2.encryption.encrypt(getIo(), allocator, small_msg, kp.public_key, .c1c3c2) catch return;
    defer ct.deinit(allocator);
    const pt = sm2.encryption.decrypt(allocator, ct, kp.private_key) catch return;
    allocator.free(pt);
}

/// SM2 decryption benchmark (medium message)
pub fn benchSm2DecryptMedium(allocator: std.mem.Allocator) void {
    const kp = genKeyPair();
    const ct = sm2.encryption.encrypt(getIo(), allocator, med_msg, kp.public_key, .c1c3c2) catch return;
    defer ct.deinit(allocator);
    const pt = sm2.encryption.decrypt(allocator, ct, kp.private_key) catch return;
    allocator.free(pt);
}
