const std = @import("std");
const crypto = std.crypto;
const mem = std.mem;
const SM2 = @import("../sm2.zig").SM2;
const SM3 = @import("../sm3.zig").SM3;
const utils = @import("utils.zig");

/// SM2 Key Pair
pub const KeyPair = struct {
    private_key: [32]u8,
    public_key: SM2,
    
    /// Generate a new SM2 key pair
    pub fn generate() KeyPair {
        const private_key = SM2.scalar.random(.big);
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
};

/// SM2 Digital Signature
pub const Signature = struct {
    r: [32]u8,
    s: [32]u8,
    
    /// Encode signature as raw bytes (R || S, 64 bytes total)
    pub fn toBytes(self: Signature) [64]u8 {
        var result: [64]u8 = undefined;
        @memcpy(result[0..32], &self.r);
        @memcpy(result[32..64], &self.s);
        return result;
    }
    
    /// Create signature from raw bytes
    pub fn fromBytes(bytes: [64]u8) Signature {
        return Signature{
            .r = bytes[0..32].*,
            .s = bytes[32..64].*,
        };
    }
    
    /// Encode signature in DER format
    pub fn toDER(self: Signature, allocator: std.mem.Allocator) ![]u8 {
        return try utils.encodeSignatureDER(allocator, self.r, self.s);
    }
    
    /// Create signature from DER format
    pub fn fromDER(der_bytes: []const u8) !Signature {
        const decoded = try utils.decodeSignatureDER(der_bytes);
        return Signature{
            .r = decoded.r,
            .s = decoded.s,
        };
    }
};

/// SM2 signature context for pre-computed hash
pub const SignatureOptions = struct {
    user_id: ?[]const u8 = null, // If null, uses default "1234567812345678"
    hash_type: enum { sm3, precomputed } = .sm3,
};

/// Generate SM2 key pair
pub fn generateKeyPair() KeyPair {
    return KeyPair.generate();
}

/// Sign a message using SM2 digital signature algorithm
/// Implements the signing process as specified in GM/T 0003.2-2012
pub fn sign(
    message: []const u8,
    private_key: [32]u8,
    public_key: SM2,
    options: SignatureOptions,
) !Signature {
    // Compute message hash based on options
    var message_hash: [32]u8 = undefined;
    
    switch (options.hash_type) {
        .precomputed => {
            if (message.len != 32) return error.InvalidPrecomputedHashLength;
            @memcpy(&message_hash, message);
        },
        .sm3 => {
            // Get user ID (default if not provided)
            const user_id = options.user_id orelse "1234567812345678";
            
            // Get public key coordinates
            const pub_coords = public_key.affineCoordinates();
            const pub_x = pub_coords.x.toBytes(.big);
            const pub_y = pub_coords.y.toBytes(.big);
            
            // Compute user hash Z_A
            const za = utils.computeUserHash(user_id, pub_x, pub_y);
            
            // Compute e = SM3(Z_A || M)
            var hasher = SM3.init(.{});
            hasher.update(&za);
            hasher.update(message);
            message_hash = hasher.finalResult();
        },
    }
    
    // Convert private key to scalar
    const d = try SM2.scalar.Scalar.fromBytes(private_key, .big);
    
    while (true) {
        // Step 1: Generate random k
        var k_bytes = SM2.scalar.random(.big);
        const k = SM2.scalar.Scalar.fromBytes(k_bytes, .big) catch continue;
        
        // Ensure k is not zero
        if (k.isZero()) continue;
        
        // Step 2: Compute (x1, y1) = k * G
        const point = SM2.basePoint.mul(k_bytes, .big) catch continue;
        const coords = point.affineCoordinates();
        const x1_bytes = coords.x.toBytes(.big);
        
        // Step 3: Compute r = (e + x1) mod n
        const e_scalar = SM2.scalar.Scalar.fromBytes(message_hash, .big) catch continue;
        const x1_scalar = SM2.scalar.Scalar.fromBytes(x1_bytes, .big) catch continue;
        const r_scalar = e_scalar.add(x1_scalar);
        const r_bytes = r_scalar.toBytes(.big);
        
        // Check if r = 0 or r + k = n
        if (r_scalar.isZero()) continue;
        
        const r_plus_k = r_scalar.add(k);
        if (r_plus_k.equivalent(SM2.scalar.Scalar.zero)) continue;
        
        // Step 4: Compute s = (1 + d)^(-1) * (k - r * d) mod n
        const one = SM2.scalar.Scalar.one;
        const one_plus_d = one.add(d);
        const one_plus_d_inv = one_plus_d.invert();
        
        const r_times_d = r_scalar.mul(d);
        const k_minus_rd = k.sub(r_times_d);
        const s_scalar = one_plus_d_inv.mul(k_minus_rd);
        const s_bytes = s_scalar.toBytes(.big);
        
        // Check if s = 0
        if (s_scalar.isZero()) continue;
        
        return Signature{
            .r = r_bytes,
            .s = s_bytes,
        };
    }
}

/// Verify an SM2 digital signature
/// Implements the verification process as specified in GM/T 0003.2-2012
pub fn verify(
    message: []const u8,
    signature: Signature,
    public_key: SM2,
    options: SignatureOptions,
) !bool {
    // Verify public key is valid
    try public_key.rejectIdentity();
    
    // Convert signature components to scalars
    const r_scalar = SM2.scalar.Scalar.fromBytes(signature.r, .big) catch return false;
    const s_scalar = SM2.scalar.Scalar.fromBytes(signature.s, .big) catch return false;
    
    // Check if r and s are in valid range [1, n-1]
    if (r_scalar.isZero() or s_scalar.isZero()) return false;
    
    // Compute message hash based on options
    var message_hash: [32]u8 = undefined;
    
    switch (options.hash_type) {
        .precomputed => {
            if (message.len != 32) return error.InvalidPrecomputedHashLength;
            @memcpy(&message_hash, message);
        },
        .sm3 => {
            // Get user ID (default if not provided)
            const user_id = options.user_id orelse "1234567812345678";
            
            // Get public key coordinates
            const pub_coords = public_key.affineCoordinates();
            const pub_x = pub_coords.x.toBytes(.big);
            const pub_y = pub_coords.y.toBytes(.big);
            
            // Compute user hash Z_A
            const za = utils.computeUserHash(user_id, pub_x, pub_y);
            
            // Compute e = SM3(Z_A || M)
            var hasher = SM3.init(.{});
            hasher.update(&za);
            hasher.update(message);
            message_hash = hasher.finalResult();
        },
    }
    
    // Step 1: Compute t = (r + s) mod n
    const t_scalar = r_scalar.add(s_scalar);
    
    // Check if t = 0
    if (t_scalar.isZero()) return false;
    
    // Step 2: Compute (x1', y1') = s*G + t*PA
    const s_bytes = s_scalar.toBytes(.big);
    const t_bytes = t_scalar.toBytes(.big);
    
    const point = SM2.mulDoubleBasePublic(
        SM2.basePoint, s_bytes,
        public_key, t_bytes,
        .big
    ) catch return false;
    
    // Step 3: Compute R = (e + x1') mod n
    const coords = point.affineCoordinates();
    const x1_prime_bytes = coords.x.toBytes(.big);
    
    const e_scalar = SM2.scalar.Scalar.fromBytes(message_hash, .big) catch return false;
    const x1_prime_scalar = SM2.scalar.Scalar.fromBytes(x1_prime_bytes, .big) catch return false;
    const R_scalar = e_scalar.add(x1_prime_scalar);
    const R_bytes = R_scalar.toBytes(.big);
    
    // Step 4: Verify R = r
    return utils.constantTimeEqual(&R_bytes, &signature.r);
}

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

test "SM2 key pair generation" {
    const testing = std.testing;
    
    const key_pair = generateKeyPair();
    
    // Verify public key is valid (not identity element)
    try key_pair.public_key.rejectIdentity();
    
    // Test serialization
    const uncompressed = key_pair.getPublicKeyUncompressed();
    try testing.expect(uncompressed[0] == 0x04); // Uncompressed marker
    
    const compressed = key_pair.getPublicKeyCompressed();
    try testing.expect(compressed[0] == 0x02 or compressed[0] == 0x03); // Compressed marker
}

test "SM2 signature creation and verification" {
    const testing = std.testing;
    
    const key_pair = generateKeyPair();
    const message = "hello world";
    const options = SignatureOptions{ .hash_type = .sm3 };
    
    // Create signature
    const signature = try sign(message, key_pair.private_key, key_pair.public_key, options);
    
    // Verify signature
    const is_valid = try verify(message, signature, key_pair.public_key, options);
    try testing.expect(is_valid);
    
    // Test with wrong message
    const wrong_message = "hello world!";
    const is_invalid = try verify(wrong_message, signature, key_pair.public_key, options);
    try testing.expect(!is_invalid);
}

test "SM2 signature with precomputed hash" {
    const testing = std.testing;
    
    const key_pair = generateKeyPair();
    const message_hash = [_]u8{0x01} ** 32;
    const options = SignatureOptions{ .hash_type = .precomputed };
    
    // Create signature
    const signature = try sign(&message_hash, key_pair.private_key, key_pair.public_key, options);
    
    // Verify signature
    const is_valid = try verify(&message_hash, signature, key_pair.public_key, options);
    try testing.expect(is_valid);
}

test "SM2 signature serialization" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    const key_pair = generateKeyPair();
    const message = "test message";
    const options = SignatureOptions{};
    
    const signature = try sign(message, key_pair.private_key, key_pair.public_key, options);
    
    // Test raw bytes serialization
    const bytes = signature.toBytes();
    const signature2 = Signature.fromBytes(bytes);
    
    try testing.expectEqualSlices(u8, &signature.r, &signature2.r);
    try testing.expectEqualSlices(u8, &signature.s, &signature2.s);
    
    // Test DER serialization
    const der_bytes = try signature.toDER(allocator);
    defer allocator.free(der_bytes);
    
    const signature3 = try Signature.fromDER(der_bytes);
    try testing.expectEqualSlices(u8, &signature.r, &signature3.r);
    try testing.expectEqualSlices(u8, &signature.s, &signature3.s);
}

test "SM2 public key from coordinates" {
    const testing = std.testing;
    
    const key_pair = generateKeyPair();
    const coords = key_pair.getPublicKeyCoordinates();
    
    const reconstructed_key = try publicKeyFromCoordinates(coords.x, coords.y);
    
    try testing.expect(key_pair.public_key.equivalent(reconstructed_key));
}

test "SM2 public key from SEC1" {
    const testing = std.testing;
    
    const key_pair = generateKeyPair();
    
    // Test uncompressed format
    const uncompressed = key_pair.getPublicKeyUncompressed();
    const key_from_uncompressed = try publicKeyFromSec1(&uncompressed);
    try testing.expect(key_pair.public_key.equivalent(key_from_uncompressed));
    
    // Test compressed format
    const compressed = key_pair.getPublicKeyCompressed();
    const key_from_compressed = try publicKeyFromSec1(&compressed);
    try testing.expect(key_pair.public_key.equivalent(key_from_compressed));
}