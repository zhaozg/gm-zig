const std = @import("std");
const root = @import("../root.zig");
const sm2 = root.sm2;

var bench_threaded: std.Io.Threaded = .init_single_threaded;

fn getIo() std.Io {
    return bench_threaded.io();
}

const small_msg = "Hello SM2!";
const med_msg = "This is a medium length message for SM2 testing that contains multiple words and sentences to provide a realistic benchmark scenario.";

const sign_options = sm2.signature.SignatureOptions{
    .user_id = "benchmark@test.com",
    .hash_type = .sm3,
};

var key_cache: ?sm2.KeyPair = null;
var sig_small: ?sm2.signature.Signature = null;
var sig_med: ?sm2.signature.Signature = null;
var ct_small: ?sm2.encryption.Ciphertext = null;
var ct_med: ?sm2.encryption.Ciphertext = null;

fn key() *sm2.KeyPair {
    if (key_cache == null) key_cache = sm2.kp.generateKeyPair(getIo());
    return &key_cache.?;
}

fn signatureSmall() *sm2.signature.Signature {
    if (sig_small == null) {
        const kp = key();
        sig_small = sm2.signature.sign(getIo(), small_msg, kp.private_key, kp.public_key, sign_options) catch unreachable;
    }
    return &sig_small.?;
}

fn signatureMedium() *sm2.signature.Signature {
    if (sig_med == null) {
        const kp = key();
        sig_med = sm2.signature.sign(getIo(), med_msg, kp.private_key, kp.public_key, sign_options) catch unreachable;
    }
    return &sig_med.?;
}

fn ciphertextSmall(allocator: std.mem.Allocator) *sm2.encryption.Ciphertext {
    if (ct_small == null) {
        ct_small = sm2.encryption.encrypt(getIo(), allocator, small_msg, key().public_key, .c1c3c2) catch unreachable;
    }
    return &ct_small.?;
}

fn ciphertextMedium(allocator: std.mem.Allocator) *sm2.encryption.Ciphertext {
    if (ct_med == null) {
        ct_med = sm2.encryption.encrypt(getIo(), allocator, med_msg, key().public_key, .c1c3c2) catch unreachable;
    }
    return &ct_med.?;
}

/// SM2 key generation benchmark
pub fn benchSm2KeyGen(allocator: std.mem.Allocator) void {
    _ = sm2.kp.generateKeyPair(getIo());
    _ = allocator;
}

/// SM2 signature benchmark (small message)
pub fn benchSm2SignSmall(allocator: std.mem.Allocator) void {
    const kp = key();
    _ = sm2.signature.sign(getIo(), small_msg, kp.private_key, kp.public_key, sign_options) catch return;
    _ = allocator;
}

/// SM2 signature benchmark (medium message)
pub fn benchSm2SignMedium(allocator: std.mem.Allocator) void {
    const kp = key();
    _ = sm2.signature.sign(getIo(), med_msg, kp.private_key, kp.public_key, sign_options) catch return;
    _ = allocator;
}

/// SM2 signature verification benchmark (small message)
pub fn benchSm2VerifySmall(allocator: std.mem.Allocator) void {
    _ = sm2.signature.verify(small_msg, signatureSmall().*, key().public_key, sign_options) catch false;
    _ = allocator;
}

/// SM2 signature verification benchmark (medium message)
pub fn benchSm2VerifyMedium(allocator: std.mem.Allocator) void {
    _ = sm2.signature.verify(med_msg, signatureMedium().*, key().public_key, sign_options) catch false;
    _ = allocator;
}

/// SM2 encryption benchmark (small message)
pub fn benchSm2EncryptSmall(allocator: std.mem.Allocator) void {
    const ct = sm2.encryption.encrypt(getIo(), allocator, small_msg, key().public_key, .c1c3c2) catch return;
    ct.deinit(allocator);
}

/// SM2 encryption benchmark (medium message)
pub fn benchSm2EncryptMedium(allocator: std.mem.Allocator) void {
    const ct = sm2.encryption.encrypt(getIo(), allocator, med_msg, key().public_key, .c1c3c2) catch return;
    ct.deinit(allocator);
}

/// SM2 decryption benchmark (small message)
pub fn benchSm2DecryptSmall(allocator: std.mem.Allocator) void {
    const pt = sm2.encryption.decrypt(allocator, ciphertextSmall(allocator).*, key().private_key) catch return;
    allocator.free(pt);
}

/// SM2 decryption benchmark (medium message)
pub fn benchSm2DecryptMedium(allocator: std.mem.Allocator) void {
    const pt = sm2.encryption.decrypt(allocator, ciphertextMedium(allocator).*, key().private_key) catch return;
    allocator.free(pt);
}
