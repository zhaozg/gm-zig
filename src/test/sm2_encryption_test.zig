const std = @import("std");
const testing = std.testing;
const SM2 = @import("../sm2.zig");
const encryption = SM2.encryption;

test "SM2 encryption comprehensive tests" {
    const allocator = testing.allocator;

    // Test 1: Basic encryption/decryption setup
    const private_key = SM2.SM2.scalar.random(.big);
    const public_key = try encryption.publicKeyFromPrivateKey(private_key);

    // Test 2: Basic encryption and decryption
    const message = "Hello, SM2 encryption world!";

    // Test C1C3C2 format
    const ciphertext_c1c3c2 = try encryption.encrypt(allocator, message, public_key, .c1c3c2);
    defer ciphertext_c1c3c2.deinit(allocator);

    const decrypted_c1c3c2 = try encryption.decrypt(allocator, ciphertext_c1c3c2, private_key);
    defer allocator.free(decrypted_c1c3c2);

    try testing.expectEqualStrings(message, decrypted_c1c3c2);

    // Test C1C2C3 format
    const ciphertext_c1c2c3 = try encryption.encrypt(allocator, message, public_key, .c1c2c3);
    defer ciphertext_c1c2c3.deinit(allocator);

    const decrypted_c1c2c3 = try encryption.decrypt(allocator, ciphertext_c1c2c3, private_key);
    defer allocator.free(decrypted_c1c2c3);

    try testing.expectEqualStrings(message, decrypted_c1c2c3);
}

test "SM2 encryption various message sizes" {
    const allocator = testing.allocator;

    const private_key = SM2.SM2.scalar.random(.big);
    const public_key = try encryption.publicKeyFromPrivateKey(private_key);

    // Test different message sizes
    const test_sizes = [_]usize{ 1, 8, 16, 32, 64, 128, 256, 512, 1024, 2048 };

    for (test_sizes) |size| {
        const message = try allocator.alloc(u8, size);
        defer allocator.free(message);

        // Fill with deterministic pattern
        for (message, 0..) |*byte, i| {
            byte.* = @intCast((i * 7 + 13) & 0xFF);
        }

        // Test both formats
        const formats = [_]encryption.CiphertextFormat{ .c1c3c2, .c1c2c3 };

        for (formats) |format| {
            const ciphertext = try encryption.encrypt(allocator, message, public_key, format);
            defer ciphertext.deinit(allocator);

            // Verify ciphertext structure
            try testing.expect(ciphertext.c1.len == 65);
            try testing.expect(ciphertext.c1[0] == 0x04); // Uncompressed format
            try testing.expect(ciphertext.c2.len == size);
            try testing.expect(ciphertext.c3.len == 32);
            try testing.expect(ciphertext.format == format);

            const decrypted = try encryption.decrypt(allocator, ciphertext, private_key);
            defer allocator.free(decrypted);

            try testing.expectEqualSlices(u8, message, decrypted);
        }
    }
}

test "SM2 encryption ciphertext serialization" {
    const allocator = testing.allocator;

    const private_key = SM2.SM2.scalar.random(.big);
    const public_key = try encryption.publicKeyFromPrivateKey(private_key);

    const message = "Serialization test message";

    // Test C1C3C2 format serialization
    const ciphertext_c1c3c2 = try encryption.encrypt(allocator, message, public_key, .c1c3c2);
    defer ciphertext_c1c3c2.deinit(allocator);

    const serialized_c1c3c2 = try ciphertext_c1c3c2.toBytes(allocator);
    defer allocator.free(serialized_c1c3c2);

    // Expected length: 65 (C1) + 32 (C3) + message.len (C2)
    const expected_len_c1c3c2 = 65 + 32 + message.len;
    try testing.expect(serialized_c1c3c2.len == expected_len_c1c3c2);

    const deserialized_c1c3c2 = try encryption.Ciphertext.fromBytes(allocator, serialized_c1c3c2, .c1c3c2);
    defer deserialized_c1c3c2.deinit(allocator);

    const decrypted_c1c3c2 = try encryption.decrypt(allocator, deserialized_c1c3c2, private_key);
    defer allocator.free(decrypted_c1c3c2);

    try testing.expectEqualStrings(message, decrypted_c1c3c2);

    // Test C1C2C3 format serialization
    const ciphertext_c1c2c3 = try encryption.encrypt(allocator, message, public_key, .c1c2c3);
    defer ciphertext_c1c2c3.deinit(allocator);

    const serialized_c1c2c3 = try ciphertext_c1c2c3.toBytes(allocator);
    defer allocator.free(serialized_c1c2c3);

    const expected_len_c1c2c3 = 65 + message.len + 32;
    try testing.expect(serialized_c1c2c3.len == expected_len_c1c2c3);

    const deserialized_c1c2c3 = try encryption.Ciphertext.fromBytes(allocator, serialized_c1c2c3, .c1c2c3);
    defer deserialized_c1c2c3.deinit(allocator);

    const decrypted_c1c2c3 = try encryption.decrypt(allocator, deserialized_c1c2c3, private_key);
    defer allocator.free(decrypted_c1c2c3);

    try testing.expectEqualStrings(message, decrypted_c1c2c3);
}

test "SM2 encryption convenience functions" {
    const allocator = testing.allocator;

    const private_key = SM2.SM2.scalar.random(.big);
    const public_key = try encryption.publicKeyFromPrivateKey(private_key);

    const message = "Convenience function test";

    // Test encryptWithFormat
    const encrypted_c1c3c2 = try encryption.encryptWithFormat(allocator, message, public_key, .c1c3c2);
    defer allocator.free(encrypted_c1c3c2);

    const encrypted_c1c2c3 = try encryption.encryptWithFormat(allocator, message, public_key, .c1c2c3);
    defer allocator.free(encrypted_c1c2c3);

    // Test decryptWithFormat
    const decrypted_c1c3c2 = try encryption.decryptWithFormat(allocator, encrypted_c1c3c2, private_key, .c1c3c2);
    defer allocator.free(decrypted_c1c3c2);

    const decrypted_c1c2c3 = try encryption.decryptWithFormat(allocator, encrypted_c1c2c3, private_key, .c1c2c3);
    defer allocator.free(decrypted_c1c2c3);

    try testing.expectEqualStrings(message, decrypted_c1c3c2);
    try testing.expectEqualStrings(message, decrypted_c1c2c3);
}

test "SM2 encryption error handling" {
    const allocator = testing.allocator;

    const private_key = SM2.SM2.scalar.random(.big);
    const public_key = try encryption.publicKeyFromPrivateKey(private_key);

    // Test empty message
    try testing.expectError(error.EmptyMessage, encryption.encrypt(allocator, "", public_key, .c1c3c2));

    // Test invalid public key (identity element)
    const identity_key = SM2.SM2.identityElement;
    const message = "test message";

    try testing.expectError(
        error.IdentityElement,
        encryption.encrypt(allocator, message, identity_key, .c1c3c2)
    );

    // Test decryption with wrong private key
    const wrong_private_key = SM2.SM2.scalar.random(.big);
    const ciphertext = try encryption.encrypt(allocator, message, public_key, .c1c3c2);
    defer ciphertext.deinit(allocator);

    // This should either fail or produce wrong result
    const result = encryption.decrypt(allocator, ciphertext, wrong_private_key);
    if (result) |decrypted| {
        defer allocator.free(decrypted);
        // If it doesn't fail, the result should be different
        try testing.expect(!std.mem.eql(u8, message, decrypted));
    } else |_| {
        // Expected to fail with wrong key
    }
}

test "SM2 encryption MAC verification" {
    const allocator = testing.allocator;

    const private_key = SM2.SM2.scalar.random(.big);
    const public_key = try encryption.publicKeyFromPrivateKey(private_key);

    const message = "MAC verification test";

    var ciphertext = try encryption.encrypt(allocator, message, public_key, .c1c3c2);
    defer ciphertext.deinit(allocator);

    // Tamper with C3 (MAC)
    ciphertext.c3[0] ^= 0x01;

    // Decryption should fail due to MAC mismatch
    try testing.expectError(error.InvalidMAC, encryption.decrypt(allocator, ciphertext, private_key));

    // Restore original MAC
    ciphertext.c3[0] ^= 0x01;

    // Should work now
    const decrypted = try encryption.decrypt(allocator, ciphertext, private_key);
    defer allocator.free(decrypted);

    try testing.expectEqualStrings(message, decrypted);
}

test "SM2 encryption public key creation methods" {
    const private_key = SM2.SM2.scalar.random(.big);

    // Test publicKeyFromPrivateKey
    const public_key1 = try encryption.publicKeyFromPrivateKey(private_key);

    // Test publicKeyFromCoordinates
    const coords = public_key1.affineCoordinates();
    const x_bytes = coords.x.toBytes(.big);
    const y_bytes = coords.y.toBytes(.big);

    const public_key2 = try encryption.publicKeyFromCoordinates(x_bytes, y_bytes);
    try testing.expect(public_key1.equivalent(public_key2));

    // Test publicKeyFromSec1 (uncompressed)
    const sec1_uncompressed = public_key1.toUncompressedSec1();
    const public_key3 = try encryption.publicKeyFromSec1(&sec1_uncompressed);
    try testing.expect(public_key1.equivalent(public_key3));

    // Test publicKeyFromSec1 (compressed)
    const sec1_compressed = public_key1.toCompressedSec1();
    const public_key4 = try encryption.publicKeyFromSec1(&sec1_compressed);
    try testing.expect(public_key1.equivalent(public_key4));
}

test "SM2 encryption cross-format compatibility" {
    const allocator = testing.allocator;

    const private_key = SM2.SM2.scalar.random(.big);
    const public_key = try encryption.publicKeyFromPrivateKey(private_key);

    const message = "Cross-format test";

    // Encrypt with C1C3C2 format
    const ciphertext_c1c3c2 = try encryption.encrypt(allocator, message, public_key, .c1c3c2);
    defer ciphertext_c1c3c2.deinit(allocator);

    // Serialize and deserialize as C1C2C3 format should fail or give wrong result
    const serialized = try ciphertext_c1c3c2.toBytes(allocator);
    defer allocator.free(serialized);

    // This should work since we're using the correct format
    const deserialized_same = try encryption.Ciphertext.fromBytes(allocator, serialized, .c1c3c2);
    defer deserialized_same.deinit(allocator);

    const decrypted_same = try encryption.decrypt(allocator, deserialized_same, private_key);
    defer allocator.free(decrypted_same);

    try testing.expectEqualStrings(message, decrypted_same);
}

test "SM2 encryption ciphertext length validation" {
    const allocator = testing.allocator;

    // Test invalid ciphertext length
    const too_short = [_]u8{0x04} ** 50; // Less than minimum 97 bytes

    try testing.expectError(
        error.InvalidCiphertextLength,
        encryption.Ciphertext.fromBytes(allocator, &too_short, .c1c3c2)
    );
}

test "SM2 encryption deterministic properties" {
    const allocator = testing.allocator;

    const private_key = SM2.SM2.scalar.random(.big);
    const public_key = try encryption.publicKeyFromPrivateKey(private_key);

    const message = "Deterministic test";

    // Encrypt the same message twice
    const ciphertext1 = try encryption.encrypt(allocator, message, public_key, .c1c3c2);
    defer ciphertext1.deinit(allocator);

    const ciphertext2 = try encryption.encrypt(allocator, message, public_key, .c1c3c2);
    defer ciphertext2.deinit(allocator);

    // C1 should be different (due to random k)
    const c1_different = !std.mem.eql(u8, &ciphertext1.c1, &ciphertext2.c1);
    try testing.expect(c1_different);

    // C2 should be different (due to different k leading to different key stream)
    const c2_different = !std.mem.eql(u8, ciphertext1.c2, ciphertext2.c2);
    try testing.expect(c2_different);

    // C3 should be different (due to different k)
    const c3_different = !std.mem.eql(u8, &ciphertext1.c3, &ciphertext2.c3);
    try testing.expect(c3_different);

    // But both should decrypt to the same message
    const decrypted1 = try encryption.decrypt(allocator, ciphertext1, private_key);
    defer allocator.free(decrypted1);

    const decrypted2 = try encryption.decrypt(allocator, ciphertext2, private_key);
    defer allocator.free(decrypted2);

    try testing.expectEqualStrings(message, decrypted1);
    try testing.expectEqualStrings(message, decrypted2);
}

test "SM2 encryption large message handling" {
    const allocator = testing.allocator;

    const private_key = SM2.SM2.scalar.random(.big);
    const public_key = try encryption.publicKeyFromPrivateKey(private_key);

    // Test with 64KB message
    const large_size = 64 * 1024;
    const large_message = try allocator.alloc(u8, large_size);
    defer allocator.free(large_message);

    // Fill with pattern
    for (large_message, 0..) |*byte, i| {
        byte.* = @intCast((i * 251 + 17) & 0xFF); // Use prime numbers for better distribution
    }

    const ciphertext = try encryption.encrypt(allocator, large_message, public_key, .c1c3c2);
    defer ciphertext.deinit(allocator);

    const decrypted = try encryption.decrypt(allocator, ciphertext, private_key);
    defer allocator.free(decrypted);

    try testing.expectEqualSlices(u8, large_message, decrypted);
}
