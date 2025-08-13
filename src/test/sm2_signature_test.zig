const std = @import("std");
const testing = std.testing;
const SM2 = @import("../sm2.zig");
const signature = SM2.signature;


test "SM2 signature comprehensive tests" {
    const allocator = testing.allocator;

    // Test 1: Basic key generation
    const key_pair = signature.generateKeyPair();
    try key_pair.public_key.rejectIdentity();

    // Test 2: Key pair from private key
    const private_key = SM2.SM2.scalar.random(.big);
    const key_pair2 = try signature.KeyPair.fromPrivateKey(private_key);
    try testing.expect(std.mem.eql(u8, &key_pair2.private_key, &private_key));

    // Test 3: Basic signature and verification
    const message = "SM2 digital signature test";
    const options = signature.SignatureOptions{};

    const sig = try signature.sign(message, key_pair.private_key, key_pair.public_key, options);
    const is_valid = try signature.verify(message, sig, key_pair.public_key, options);
    try testing.expect(is_valid);

    // Test 4: Signature with custom user ID
    const custom_options = signature.SignatureOptions{
        .user_id = "test@example.com",
        .hash_type = .sm3,
    };

    const sig_custom = try signature.sign(message, key_pair.private_key, key_pair.public_key, custom_options);
    const is_valid_custom = try signature.verify(message, sig_custom, key_pair.public_key, custom_options);
    try testing.expect(is_valid_custom);

    // Test 5: Precomputed hash signature
    const hash_options = signature.SignatureOptions{ .hash_type = .precomputed };
    const message_hash = [_]u8{0x12, 0x34, 0x56, 0x78} ** 8; // 32 bytes

    const sig_hash = try signature.sign(&message_hash, key_pair.private_key, key_pair.public_key, hash_options);
    const is_valid_hash = try signature.verify(&message_hash, sig_hash, key_pair.public_key, hash_options);
    try testing.expect(is_valid_hash);

    // Test 6: Wrong message should fail verification
    const wrong_message = "Wrong message";
    const is_invalid = try signature.verify(wrong_message, sig, key_pair.public_key, options);
    try testing.expect(!is_invalid);

    // Test 7: Public key serialization formats
    const uncompressed = key_pair.getPublicKeyUncompressed();
    try testing.expect(uncompressed[0] == 0x04);
    try testing.expect(uncompressed.len == 65);

    const compressed = key_pair.getPublicKeyCompressed();
    try testing.expect(compressed[0] == 0x02 or compressed[0] == 0x03);
    try testing.expect(compressed.len == 33);

    // Test 8: Public key coordinate extraction
    const coords = key_pair.getPublicKeyCoordinates();
    const reconstructed = try signature.publicKeyFromCoordinates(coords.x, coords.y);
    try testing.expect(key_pair.public_key.equivalent(reconstructed));

    // Test 9: Signature DER encoding/decoding
    const der_bytes = try sig.toDER(allocator);
    defer allocator.free(der_bytes);

    const sig_from_der = try signature.Signature.fromDER(der_bytes);
    try testing.expectEqualSlices(u8, &sig.r, &sig_from_der.r);
    try testing.expectEqualSlices(u8, &sig.s, &sig_from_der.s);

    // Test 10: Signature raw bytes serialization
    const raw_bytes = sig.toBytes();
    const sig_from_bytes = signature.Signature.fromBytes(raw_bytes);
    try testing.expectEqualSlices(u8, &sig.r, &sig_from_bytes.r);
    try testing.expectEqualSlices(u8, &sig.s, &sig_from_bytes.s);
}

test "SM2 signature error handling" {

    const key_pair = signature.generateKeyPair();
    const message = "test message";
    const options = signature.SignatureOptions{};

    // Test invalid precomputed hash length
    const invalid_hash = [_]u8{0x01} ** 16; // Wrong length
    const hash_options = signature.SignatureOptions{ .hash_type = .precomputed };

    try testing.expectError(
        error.InvalidPrecomputedHashLength,
        signature.sign(&invalid_hash, key_pair.private_key, key_pair.public_key, hash_options)
    );

    // Test signature verification with identity element should fail
    const identity_key = SM2.SM2.identityElement;
    const sig = try signature.sign(message, key_pair.private_key, key_pair.public_key, options);

    try testing.expectError(
        error.IdentityElement,
        signature.verify(message, sig, identity_key, options)
    );
}

test "SM2 signature compatibility" {
    // Test signature compatibility across different key pairs
    const key_pair1 = signature.generateKeyPair();
    const key_pair2 = signature.generateKeyPair();

    const message = "cross compatibility test";
    const options = signature.SignatureOptions{};

    // Sign with key_pair1
    const sig1 = try signature.sign(message, key_pair1.private_key, key_pair1.public_key, options);

    // Should verify with key_pair1 public key
    const valid1 = try signature.verify(message, sig1, key_pair1.public_key, options);
    try testing.expect(valid1);

    // Should NOT verify with key_pair2 public key
    const invalid1 = try signature.verify(message, sig1, key_pair2.public_key, options);
    try testing.expect(!invalid1);
}

test "SM2 signature deterministic properties" {
    // Test that signatures are non-deterministic (due to random k)
    const key_pair = signature.generateKeyPair();
    const message = "deterministic test";
    const options = signature.SignatureOptions{};

    const sig1 = try signature.sign(message, key_pair.private_key, key_pair.public_key, options);
    const sig2 = try signature.sign(message, key_pair.private_key, key_pair.public_key, options);

    // Signatures should be different (due to random k)
    const different = !std.mem.eql(u8, &sig1.r, &sig2.r) or !std.mem.eql(u8, &sig1.s, &sig2.s);
    try testing.expect(different);

    // But both should verify
    const valid1 = try signature.verify(message, sig1, key_pair.public_key, options);
    const valid2 = try signature.verify(message, sig2, key_pair.public_key, options);
    try testing.expect(valid1);
    try testing.expect(valid2);
}

test "SM2 signature large message handling" {
    const allocator = testing.allocator;

    const key_pair = signature.generateKeyPair();
    const options = signature.SignatureOptions{};

    // Test with large message (1MB)
    const large_message = try allocator.alloc(u8, 1024 * 1024);
    defer allocator.free(large_message);

    // Fill with pattern
    for (large_message, 0..) |*byte, i| {
        byte.* = @intCast(i & 0xFF);
    }

    const sig = try signature.sign(large_message, key_pair.private_key, key_pair.public_key, options);
    const is_valid = try signature.verify(large_message, sig, key_pair.public_key, options);
    try testing.expect(is_valid);
}
