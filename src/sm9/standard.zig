//! Standards-compliant SM9 (GM/T 0044-2016) built on the BN254 core.

const std = @import("std");
const bn = @import("bn.zig");
const pairing = @import("pairing_bn.zig");
const hash = @import("hash.zig");
const sm3_mod = @import("../sm3.zig");
const SM3 = sm3_mod.SM3;

pub const SignMaster = struct { private_key: bn.Fp, public_key: bn.G2 };
pub const EncryptMaster = struct { private_key: bn.Fp, public_key: bn.G1 };
pub const Signature = struct { h: [32]u8, S: bn.G1 };
pub const Ciphertext = struct { C1: bn.G1, C2: []u8, C3: [32]u8, allocator: std.mem.Allocator };

pub const Error = error{
    InvalidIdentity,
    InvalidPrivateKey,
    InvalidCiphertext,
    InvalidMac,
    EmptyMessage,
};

fn bytes32(x: bn.Fp) [32]u8 {
    var out: [32]u8 = undefined;
    std.mem.writeInt(bn.Fp, &out, x, .big);
    return out;
}

fn load32(b: [32]u8) bn.Fp {
    return std.mem.readInt(bn.Fp, &b, .big);
}

fn mulN(a: bn.Fp, b: bn.Fp) bn.Fp {
    return @intCast((@as(u512, a) * b) % bn.N);
}
fn addN(a: bn.Fp, b: bn.Fp) bn.Fp {
    return @intCast((@as(u512, a) + b) % bn.N);
}
fn subN(a: bn.Fp, b: bn.Fp) bn.Fp {
    return @intCast((@as(u512, a) + bn.N - b) % bn.N);
}
fn powN(a: bn.Fp, e: bn.Fp) bn.Fp {
    var r: bn.Fp = 1;
    var base = a;
    var exp = e;
    while (exp != 0) : (exp >>= 1) {
        if (exp & 1 != 0) r = mulN(r, base);
        base = mulN(base, base);
    }
    return r;
}
fn invN(a: bn.Fp) bn.Fp {
    if (a == 0) return 0;
    var u = a;
    var v: bn.Fp = bn.N;
    var x1: bn.Fp = 1;
    var x2: bn.Fp = 0;
    while (u != 1 and v != 1) {
        while ((u & 1) == 0) {
            u >>= 1;
            if ((x1 & 1) == 0) x1 >>= 1 else x1 = (x1 >> 1) + (bn.N >> 1) + 1;
        }
        while ((v & 1) == 0) {
            v >>= 1;
            if ((x2 & 1) == 0) x2 >>= 1 else x2 = (x2 >> 1) + (bn.N >> 1) + 1;
        }
        if (u >= v) {
            u -= v;
            x1 = if (x1 >= x2) x1 - x2 else x1 -% x2 +% bn.N;
        } else {
            v -= u;
            x2 = if (x2 >= x1) x2 - x1 else x2 -% x1 +% bn.N;
        }
    }
    return if (u == 1) x1 else x2;
}

fn h1(allocator: std.mem.Allocator, id: []const u8, hid: u8) !bn.Fp {
    if (id.len == 0) return Error.InvalidIdentity;
    const out = try hash.h1Hash(id, hid, bytes32(bn.N), allocator);
    return load32(out);
}

fn h2(allocator: std.mem.Allocator, message: []const u8, w: []const u8) !bn.Fp {
    const out = try hash.h2Hash(message, w, bytes32(bn.N), allocator);
    return load32(out);
}

fn wBytes(w: bn.Fp12) [384]u8 {
    return pairing.toBytes(w);
}

pub fn signMaster(private_key: bn.Fp) SignMaster {
    return .{ .private_key = private_key, .public_key = bn.g2Mul(private_key, bn.P2) };
}

pub fn encryptMaster(private_key: bn.Fp) EncryptMaster {
    return .{ .private_key = private_key, .public_key = bn.g1Mul(private_key, bn.P1) };
}

pub fn signUserKey(allocator: std.mem.Allocator, master: SignMaster, id: []const u8) !bn.G1 {
    const x = try h1(allocator, id, 0x01);
    const t1 = addN(x, master.private_key);
    if (t1 == 0) return Error.InvalidPrivateKey;
    const t2 = mulN(master.private_key, invN(t1));
    return bn.g1Mul(t2, bn.P1);
}

pub fn encryptUserKey(allocator: std.mem.Allocator, master: EncryptMaster, id: []const u8) !bn.G2 {
    const x = try h1(allocator, id, 0x03);
    const t1 = addN(x, master.private_key);
    if (t1 == 0) return Error.InvalidPrivateKey;
    const t2 = mulN(master.private_key, invN(t1));
    return bn.g2Mul(t2, bn.P2);
}

/// Sign with an explicit nonce. `r` must be in [1, N-1].
pub fn sign(
    allocator: std.mem.Allocator,
    message: []const u8,
    user_key: bn.G1,
    master_public: bn.G2,
    r: bn.Fp,
) !Signature {
    if (r == 0 or r >= bn.N) return Error.InvalidPrivateKey;

    const g = pairing.pairing(bn.P1, master_public);
    const w = pairing.f12Pow(g, r);
    const h = try h2(allocator, message, &wBytes(w));
    const l = subN(r, h);
    if (l == 0) return Error.InvalidPrivateKey;
    const S = bn.g1Mul(l, user_key);
    return .{ .h = bytes32(h), .S = S };
}

pub fn verify(
    allocator: std.mem.Allocator,
    message: []const u8,
    signature: Signature,
    id: []const u8,
    master_public: bn.G2,
) !bool {
    const h = load32(signature.h);
    if (h == 0 or h >= bn.N) return false;
    if (!bn.g1OnCurve(signature.S)) return false;

    const g = pairing.pairing(bn.P1, master_public);
    const t = pairing.f12Pow(g, h);

    const h1x = try h1(allocator, id, 0x01);
    const p = bn.g2Add(bn.g2Mul(h1x, bn.P2), master_public);
    const u = pairing.pairing(signature.S, p);
    const w = bn.f12Mul(u, t);
    const h2x = try h2(allocator, message, &wBytes(w));
    return std.crypto.timing_safe.eql([32]u8, signature.h, bytes32(h2x));
}

fn g1Bytes(p: bn.G1) [65]u8 {
    var out: [65]u8 = undefined;
    out[0] = 0x04;
    std.mem.writeInt(bn.Fp, out[1..33], p.x, .big);
    std.mem.writeInt(bn.Fp, out[33..65], p.y, .big);
    return out;
}

pub fn encrypt(
    allocator: std.mem.Allocator,
    message: []const u8,
    id: []const u8,
    master_public: bn.G1,
    r: bn.Fp,
) !Ciphertext {
    if (message.len == 0) return Error.EmptyMessage;
    if (r == 0 or r >= bn.N) return Error.InvalidPrivateKey;

    const h1x = try h1(allocator, id, 0x03);
    const q = bn.g1Add(bn.g1Mul(h1x, bn.P1), master_public);
    const c1 = bn.g1Mul(r, q);
    const c1_bytes = g1Bytes(c1);

    const g = pairing.pairing(master_public, bn.P2);
    const w = pairing.f12Pow(g, r);
    const w_bytes = wBytes(w);

    const kdf_input = try allocator.alloc(u8, 64 + 384 + id.len);
    defer allocator.free(kdf_input);
    @memcpy(kdf_input[0..64], c1_bytes[1..65]);
    @memcpy(kdf_input[64 .. 64 + 384], &w_bytes);
    @memcpy(kdf_input[64 + 384 ..], id);

    const k = try hash.kdf(kdf_input, message.len + 32, allocator);
    defer allocator.free(k);

    const c2 = try allocator.alloc(u8, message.len);
    errdefer allocator.free(c2);
    for (message, k[0..message.len], 0..) |m, key, i| c2[i] = m ^ key;

    const c3 = sm3_mod.hmac(k[message.len .. message.len + 32], c2);

    return .{ .C1 = c1, .C2 = c2, .C3 = c3, .allocator = allocator };
}

pub fn decrypt(
    allocator: std.mem.Allocator,
    ct: Ciphertext,
    id: []const u8,
    user_key: bn.G2,
) ![]u8 {
    if (!bn.g1OnCurve(ct.C1)) return Error.InvalidCiphertext;
    const c1_bytes = g1Bytes(ct.C1);
    const w = pairing.pairing(ct.C1, user_key);
    const w_bytes = wBytes(w);

    const kdf_input = try allocator.alloc(u8, 64 + 384 + id.len);
    defer allocator.free(kdf_input);
    @memcpy(kdf_input[0..64], c1_bytes[1..65]);
    @memcpy(kdf_input[64 .. 64 + 384], &w_bytes);
    @memcpy(kdf_input[64 + 384 ..], id);

    const k = try hash.kdf(kdf_input, ct.C2.len + 32, allocator);
    defer allocator.free(k);

    const message = try allocator.alloc(u8, ct.C2.len);
    errdefer allocator.free(message);
    for (ct.C2, k[0..ct.C2.len], 0..) |c, key, i| message[i] = c ^ key;

    const c3 = sm3_mod.hmac(k[ct.C2.len .. ct.C2.len + 32], ct.C2);
    if (!std.crypto.timing_safe.eql([32]u8, c3, ct.C3)) return Error.InvalidMac;
    return message;
}

pub const KeyExchangeRole = enum { initiator, responder };

fn g1Raw(p: bn.G1) [64]u8 {
    var out: [64]u8 = undefined;
    std.mem.writeInt(bn.Fp, out[0..32], p.x, .big);
    std.mem.writeInt(bn.Fp, out[32..64], p.y, .big);
    return out;
}

/// Generate the ephemeral G1 point sent to the peer.
pub fn keyExchangeBegin(
    allocator: std.mem.Allocator,
    master_public: bn.G1,
    peer_id: []const u8,
    r: bn.Fp,
) !bn.G1 {
    if (r == 0 or r >= bn.N) return Error.InvalidPrivateKey;
    const h1x = try h1(allocator, peer_id, 0x03);
    const q = bn.g1Add(bn.g1Mul(h1x, bn.P1), master_public);
    return bn.g1Mul(r, q);
}

/// Derive the shared key from both ephemeral points.
pub fn keyExchangeShared(
    allocator: std.mem.Allocator,
    master_public: bn.G1,
    user_key: bn.G2,
    own_id: []const u8,
    peer_id: []const u8,
    own_r: bn.Fp,
    own_R: bn.G1,
    peer_R: bn.G1,
    role: KeyExchangeRole,
    key_len: usize,
) ![]u8 {
    if (own_r == 0 or own_r >= bn.N) return Error.InvalidPrivateKey;
    if (!bn.g1OnCurve(own_R) or !bn.g1OnCurve(peer_R)) return Error.InvalidCiphertext;

    const g = pairing.pairing(master_public, bn.P2);
    const g1 = pairing.f12Pow(g, own_r);
    const g2 = pairing.pairing(peer_R, user_key);
    const g3 = pairing.f12Pow(g2, own_r);
    const g1_bytes = wBytes(g1);
    const g2_bytes = wBytes(g2);
    const g3_bytes = wBytes(g3);
    const own_R_bytes = g1Raw(own_R);
    const peer_R_bytes = g1Raw(peer_R);

    const id_a = if (role == .initiator) own_id else peer_id;
    const id_b = if (role == .initiator) peer_id else own_id;
    const r_a = if (role == .initiator) own_R_bytes else peer_R_bytes;
    const r_b = if (role == .initiator) peer_R_bytes else own_R_bytes;

    const z_len = id_a.len + id_b.len + 64 + 64 + 384 * 3;
    const z = try allocator.alloc(u8, z_len);
    defer allocator.free(z);
    var o: usize = 0;
    @memcpy(z[o .. o + id_a.len], id_a);
    o += id_a.len;
    @memcpy(z[o .. o + id_b.len], id_b);
    o += id_b.len;
    @memcpy(z[o .. o + 64], &r_a);
    o += 64;
    @memcpy(z[o .. o + 64], &r_b);
    o += 64;
    if (role == .initiator) {
        @memcpy(z[o .. o + 384], &g1_bytes);
    } else {
        @memcpy(z[o .. o + 384], &g2_bytes);
    }
    o += 384;
    if (role == .initiator) {
        @memcpy(z[o .. o + 384], &g2_bytes);
    } else {
        @memcpy(z[o .. o + 384], &g1_bytes);
    }
    o += 384;
    @memcpy(z[o .. o + 384], &g3_bytes);

    return hash.kdf(z, key_len, allocator);
}
