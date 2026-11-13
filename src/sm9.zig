//! SM9 Identity-Based Cryptography (GM/T 0044-2016).
//!
//! The public API is `sm9.standard`; the previous simplified implementation
//! has been removed.

const std = @import("std");
pub const mod = @import("sm9/mod.zig");

pub const bn = mod.bn;
pub const pairing = mod.pairing;
pub const standard = mod.standard;
pub const hash = mod.hash;

pub const SignMaster = mod.SignMaster;
pub const EncryptMaster = mod.EncryptMaster;
pub const Signature = mod.Signature;
pub const Ciphertext = mod.Ciphertext;
pub const KeyExchangeRole = mod.KeyExchangeRole;

pub const version = .{ .major = 1, .minor = 0, .patch = 0, .pre_release = "alpha" };

pub fn getVersion(allocator: std.mem.Allocator) ![]u8 {
    return std.fmt.allocPrint(allocator, "{}.{}.{}-{s}", .{ version.major, version.minor, version.patch, version.pre_release });
}

pub const info = .{
    .name = "SM9-Zig",
    .description = "SM9 Identity-Based Cryptographic Algorithm Implementation in Zig",
    .standard = "GM/T 0044-2016",
    .author = "GM-Zig Project",
    .license = "MIT",
};

pub fn getInfo() @TypeOf(info) {
    return info;
}
