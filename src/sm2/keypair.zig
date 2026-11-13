const std = @import("std");
const crypto = std.crypto;
const mem = std.mem;
const SM2 = @import("group.zig").SM2;
const SM3 = @import("../sm3.zig").SM3;
const utils = @import("utils.zig");
const secure = @import("../secure.zig");

/// SM2 Key Pair
pub const KeyPair = struct {
    private_key: [32]u8,
    public_key: SM2,

    /// Generate a new SM2 key pair
    pub fn generate(io: std.Io) KeyPair {
        const private_key = SM2.scalar.random(io, .big);
        const public_key = SM2.basePoint.mul(private_key, .big) catch unreachable;

        return KeyPair{
            .private_key = private_key,
            .public_key = public_key,
        };
    }

    /// Create key pair from existing private key
    pub fn fromPrivateKey(private_key: [32]u8) !KeyPair {
        const public_key = try SM2.basePoint.mul(private_key, .big);

        return KeyPair{
            .private_key = private_key,
            .public_key = public_key,
        };
    }

    /// Get public key as uncompressed SEC1 format (65 bytes)
    pub fn getPublicKeyUncompressed(self: KeyPair) [65]u8 {
        return self.public_key.toUncompressedSec1();
    }

    /// Get public key as compressed SEC1 format (33 bytes)
    pub fn getPublicKeyCompressed(self: KeyPair) [33]u8 {
        return self.public_key.toCompressedSec1();
    }

    /// Get public key coordinates
    pub fn getPublicKeyCoordinates(self: KeyPair) struct { x: [32]u8, y: [32]u8 } {
        const affine = self.public_key.affineCoordinates();
        return .{
            .x = affine.x.toBytes(.big),
            .y = affine.y.toBytes(.big),
        };
    }

    /// Overwrite the private key material with zeros.
    ///
    /// The public key is not secret and is left untouched. Call this before
    /// discarding a key pair that was used to handle real private keys.
    pub fn zeroize(self: *KeyPair) void {
        secure.zeroValue([32]u8, &self.private_key);
    }

    /// Alias for `zeroize`, for callers that use `deinit` consistently.
    pub fn deinit(self: *KeyPair) void {
        self.zeroize();
    }
};

/// Create public key from coordinates
pub fn publicKeyFromCoordinates(x: [32]u8, y: [32]u8) !SM2 {
    const fe_x = try SM2.Fe.fromBytes(x, .big);
    const fe_y = try SM2.Fe.fromBytes(y, .big);
    return try SM2.fromAffineCoordinates(.{ .x = fe_x, .y = fe_y });
}

/// Create public key from SEC1 encoding
pub fn publicKeyFromSec1(sec1_bytes: []const u8) !SM2 {
    return try SM2.fromSec1(sec1_bytes);
}

/// Create public key from private key
pub fn publicKeyFromPrivateKey(private_key: [32]u8) !SM2 {
    return try SM2.basePoint.mul(private_key, .big);
}

/// Generate SM2 key pair
pub fn generateKeyPair(io: std.Io) KeyPair {
    return KeyPair.generate(io);
}
