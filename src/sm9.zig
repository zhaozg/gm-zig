/// SM9 Cryptographic Algorithm Library
/// Based on GM/T 0044-2016 Chinese National Standard
///
/// This module provides a complete implementation framework for the SM9
/// identity-based cryptographic algorithm, including:
/// - System parameter generation and master key management
/// - User key extraction from identities
/// - Digital signature and verification
/// - Public key encryption and decryption
///
/// Usage:
/// ```zig
/// const sm9 = @import("sm9.zig");
///
/// // Initialize SM9 system
/// var context = sm9.SM9Context.init(allocator);
///
/// // Extract user keys
/// const user_sign_key = try context.extractSignKey("alice@example.com");
/// const user_encrypt_key = try context.extractEncryptKey("bob@example.com");
///
/// // Sign and verify
/// const signature = try context.signMessage(message, user_sign_key, .{});
/// const is_valid = try context.verifySignature(message, signature, "alice@example.com", .{});
///
/// // Encrypt and decrypt
/// const ciphertext = try context.encryptMessage(message, "bob@example.com", .{});
/// const plaintext = try context.decryptMessage(ciphertext, user_encrypt_key, .{});
/// ```

const std = @import("std");

// Export the main SM9 interface module
pub const mod = @import("sm9/mod.zig");

pub const key_extract = mod.key_extract;
pub const sign = mod.sign;
pub const encrypt = mod.encrypt;
pub const key_agreement = mod.key_agreement;
pub const params = mod.params;

// Import new core modules
pub const bigint = mod.bigint;
pub const curve = mod.curve;
pub const hash = mod.hash;
pub const pairing = mod.pairing;

// Phase 3: Enhanced core operations
pub const field = mod.field;
pub const random = mod.random;
pub const SM9Context = mod.SM9Context;
pub const SM9Error = mod.SM9Error;
pub const TestVectors = mod.TestVectors;
pub const SystemParams = mod.SystemParams;
pub const SignatureOptions = mod.SignatureOptions;
pub const Utils = mod.Utils;
pub const EncryptionOptions = mod.EncryptionOptions;

// Version information
pub const version = .{
    .major = 1,
    .minor = 0,
    .patch = 0,
    .pre_release = "alpha",
};

/// Get SM9 library version string
pub fn getVersion(allocator: std.mem.Allocator) ![]u8 {
    return std.fmt.allocPrint(
        allocator,
        "{}.{}.{}-{s}",
        .{ version.major, version.minor, version.patch, version.pre_release },
    );
}

/// SM9 library information
pub const info = .{
    .name = "SM9-Zig",
    .description = "SM9 Identity-Based Cryptographic Algorithm Implementation in Zig",
    .standard = "GM/T 0044-2016",
    .author = "GM-Zig Project",
    .license = "MIT",
};

/// Get library information
pub fn getInfo() @TypeOf(info) {
    return info;
}
