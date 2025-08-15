const std = @import("std");
const crypto = std.crypto;
const mem = std.mem;
const SM2 = @import("group.zig").SM2;
const SM3 = @import("../sm3.zig").SM3;
const utils = @import("utils.zig");

/// SM2 Public Key Encryption implementation
/// Based on GM/T 0003.4-2012 standard

/// Ciphertext format options
pub const CiphertextFormat = enum {
    c1c3c2, // C1 || C3 || C2 (standard format)
    c1c2c3, // C1 || C2 || C3 (alternative format)
};

/// SM2 ciphertext structure
pub const Ciphertext = struct {
    c1: [65]u8,    // Uncompressed point (0x04 + 32 bytes x + 32 bytes y)
    c2: []u8,      // Encrypted message (same length as plaintext)
    c3: [32]u8,    // MAC value (SM3 hash)
    format: CiphertextFormat,

    /// Get total ciphertext length
    pub fn getLength(self: Ciphertext) usize {
        return 65 + self.c2.len + 32; // C1 + C2 + C3
    }

    /// Serialize ciphertext to bytes
    pub fn toBytes(self: Ciphertext, allocator: std.mem.Allocator) ![]u8 {
        const total_len = self.getLength();
        var result = try allocator.alloc(u8, total_len);

        switch (self.format) {
            .c1c3c2 => {
                // C1 || C3 || C2
                @memcpy(result[0..65], &self.c1);
                @memcpy(result[65..97], &self.c3);
                @memcpy(result[97..], self.c2);
            },
            .c1c2c3 => {
                // C1 || C2 || C3
                @memcpy(result[0..65], &self.c1);
                @memcpy(result[65..65 + self.c2.len], self.c2);
                @memcpy(result[65 + self.c2.len..], &self.c3);
            },
        }

        return result;
    }

    /// Create ciphertext from bytes
    pub fn fromBytes(
        allocator: std.mem.Allocator,
        bytes: []const u8,
        format: CiphertextFormat,
    ) !Ciphertext {
        if (bytes.len < 97) return error.InvalidCiphertextLength; // Minimum: C1(65) + C3(32)

        const message_len = bytes.len - 97; // Total - C1 - C3
        const c2 = try allocator.alloc(u8, message_len);

        var result = Ciphertext{
            .c1 = undefined,
            .c2 = c2,
            .c3 = undefined,
            .format = format,
        };

        switch (format) {
            .c1c3c2 => {
                // C1 || C3 || C2
                @memcpy(&result.c1, bytes[0..65]);
                @memcpy(&result.c3, bytes[65..97]);
                @memcpy(result.c2, bytes[97..]);
            },
            .c1c2c3 => {
                // C1 || C2 || C3
                @memcpy(&result.c1, bytes[0..65]);
                @memcpy(result.c2, bytes[65..65 + message_len]);
                @memcpy(&result.c3, bytes[65 + message_len..]);
            },
        }

        return result;
    }

    pub fn deinit(self: Ciphertext, allocator: std.mem.Allocator) void {
        allocator.free(self.c2);
    }
};

/// Encrypt a message using SM2 public key encryption
/// Implements the encryption process as specified in GM/T 0003.4-2012
pub fn encrypt(
    allocator: std.mem.Allocator,
    message: []const u8,
    public_key: SM2,
    format: CiphertextFormat,
    rng: ?*std.Random,
) !Ciphertext {
    if (message.len == 0) return error.EmptyMessage;

    // Verify public key is valid
    try public_key.rejectIdentity();

    while (true) {
        // Step 1: Generate random k ∈ [1, n-1]
        const k_bytes = SM2.scalar.random(rng, .big);
        const k_scalar = SM2.scalar.Scalar.fromBytes(k_bytes, .big) catch continue;

        if (k_scalar.isZero()) continue;

        // Step 2: Compute C1 = k * G
        const c1_point = SM2.basePoint.mul(k_bytes, .big) catch continue;
        const c1_bytes = c1_point.toUncompressedSec1();

        // Step 3: Check if h * PB = O (should not happen for valid public key)
        // h = 1 for SM2 curve, so this is just checking if PB is the identity
        public_key.rejectIdentity() catch continue;

        // Step 4: Compute k * PB = (x2, y2)
        const kpb_point = public_key.mul(k_bytes, .big) catch continue;
        const kpb_coords = kpb_point.affineCoordinates();

        // Step 5: Compute t = KDF(x2 || y2, klen)
        var kdf_input: [64]u8 = undefined;
        @memcpy(kdf_input[0..32], &kpb_coords.x.toBytes(.big));
        @memcpy(kdf_input[32..64], &kpb_coords.y.toBytes(.big));

        const t = utils.kdf(allocator, &kdf_input, message.len) catch continue;
        defer allocator.free(t);

        // Check if t is all zeros
        var all_zero = true;
        for (t) |byte| {
            if (byte != 0) {
                all_zero = false;
                break;
            }
        }
        if (all_zero) continue;

        // Step 6: Compute C2 = M ⊕ t
        var c2 = try allocator.alloc(u8, message.len);
        for (message, t, 0..) |m_byte, t_byte, i| {
            c2[i] = m_byte ^ t_byte;
        }

        // Step 7: Compute C3 = SM3(x2 || M || y2)
        var hasher = SM3.init(.{});
        hasher.update(&kpb_coords.x.toBytes(.big));
        hasher.update(message);
        hasher.update(&kpb_coords.y.toBytes(.big));
        const c3 = hasher.finalResult();

        return Ciphertext{
            .c1 = c1_bytes,
            .c2 = c2,
            .c3 = c3,
            .format = format,
        };
    }
}

/// Decrypt a ciphertext using SM2 private key
/// Implements the decryption process as specified in GM/T 0003.4-2012
pub fn decrypt(
    allocator: std.mem.Allocator,
    ciphertext: Ciphertext,
    private_key: [32]u8,
) ![]u8 {
    // Step 1: Extract C1 from ciphertext and verify it's a valid point
    const c1_point = SM2.fromSec1(&ciphertext.c1) catch return error.InvalidC1Point;
    try c1_point.rejectIdentity();

    // Step 2: Check if h * C1 = O (should not happen for valid C1)
    // h = 1 for SM2 curve, so this is just checking if C1 is the identity

    // Step 3: Compute d * C1 = (x2, y2)
    const dc1_point = c1_point.mul(private_key, .big) catch |err| {
        // 区分错误类型
        if (err == error.IdentityElement) {
            return error.InvalidPrivateKey;
        }
        return err;
    };
    const dc1_coords = dc1_point.affineCoordinates();

    // Step 4: Compute t = KDF(x2 || y2, klen)
    var kdf_input: [64]u8 = undefined;
    @memcpy(kdf_input[0..32], &dc1_coords.x.toBytes(.big));
    @memcpy(kdf_input[32..64], &dc1_coords.y.toBytes(.big));

    const t = try utils.kdf(allocator, &kdf_input, ciphertext.c2.len);
    defer allocator.free(t);

    // 修复：只检查 KDF 输出是否全为零，而不是是否包含零字节
    var all_zero = true;
    for (t) |byte| {
        if (byte != 0) {
            all_zero = false;
            break;
        }
    }
    if (all_zero) return error.InvalidKDFOutput;

    // Step 5: Compute M = C2 ⊕ t
    var message = try allocator.alloc(u8, ciphertext.c2.len);
    for (ciphertext.c2, t, 0..) |c2_byte, t_byte, i| {
        message[i] = c2_byte ^ t_byte;
    }

    // Step 6: Compute u = SM3(x2 || M || y2) and verify u = C3
    var hasher = SM3.init(.{});
    hasher.update(&dc1_coords.x.toBytes(.big));
    hasher.update(message);
    hasher.update(&dc1_coords.y.toBytes(.big));
    const u = hasher.finalResult();

    if (!utils.constantTimeEqual(&u, &ciphertext.c3)) {
        allocator.free(message);
        return error.InvalidMAC;
    }

    return message;
}

/// Encrypt with specified format (convenience function)
pub fn encryptWithFormat(
    allocator: std.mem.Allocator,
    message: []const u8,
    public_key: SM2,
    format: CiphertextFormat,
    rng: ?*std.Random,
) ![]u8 {
    const ciphertext = try encrypt(allocator, message, public_key, format, rng);
    defer ciphertext.deinit(allocator);

    return try ciphertext.toBytes(allocator);
}

/// Decrypt with specified format (convenience function)
pub fn decryptWithFormat(
    allocator: std.mem.Allocator,
    ciphertext_bytes: []const u8,
    private_key: [32]u8,
    format: CiphertextFormat,
) ![]u8 {
    const ciphertext = try Ciphertext.fromBytes(allocator, ciphertext_bytes, format);
    defer ciphertext.deinit(allocator);

    return try decrypt(allocator, ciphertext, private_key);
}

