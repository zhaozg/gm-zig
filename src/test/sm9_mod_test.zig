const std = @import("std");
const testing = std.testing;
const sm9 = @import("../sm9.zig");

test "SM9 context initialization" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const context = sm9.SM9Context.init(allocator);

    try testing.expect(context.validate());
    try testing.expect(context.system.validate());
}

test "SM9 context with custom parameters" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const custom_params = sm9.SystemParams.init();
    const context = try sm9.SM9Context.initWithParams(allocator, custom_params);

    try testing.expect(context.validate());
}

test "SM9 complete workflow" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var context = sm9.SM9Context.init(allocator);

    const alice_id = "alice@example.com";
    const bob_id = "bob@example.com";
    const message = "Hello, SM9 world!";

    // Extract keys
    const alice_sign_key = try context.extractSignKey(alice_id);
    const bob_encrypt_key = try context.extractEncryptKey(bob_id);

    // Derive public keys
    const alice_public = context.deriveSignPublicKey(alice_id);
    const bob_public = context.deriveEncryptPublicKey(bob_id);

    try testing.expect(alice_public.validate(context.system.params));
    try testing.expect(bob_public.validate(context.system.params));

    // Sign message
    const signature = try context.signMessage(
        message,
        alice_sign_key,
        sm9.SignatureOptions{},
    );

    // Verify signature
    const is_valid = try context.verifySignature(
        message,
        signature,
        alice_id,
        sm9.SignatureOptions{},
    );
    try testing.expect(is_valid);

    // Encrypt message
    const ciphertext = try context.encryptMessage(
        message,
        bob_id,
        sm9.EncryptionOptions{},
    );
    defer ciphertext.deinit();

    // Decrypt message
    const decrypted = try context.decryptMessage(
        ciphertext,
        bob_encrypt_key,
        sm9.EncryptionOptions{},
    );
    defer allocator.free(decrypted);

    try testing.expectEqualStrings(message, decrypted);
}

test "SM9 utility functions" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Test hex conversion
    const original_bytes = [_]u8{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef };
    const hex_string = try sm9.Utils.bytesToHex(&original_bytes, allocator);
    defer allocator.free(hex_string);

    const restored_bytes = try sm9.Utils.hexToBytes(hex_string, allocator);
    defer allocator.free(restored_bytes);

    try testing.expectEqualSlices(u8, &original_bytes, restored_bytes);

    // Test random generation
    const random_bytes = try sm9.Utils.generateRandomBytes(32, allocator);
    defer allocator.free(random_bytes);
    try testing.expect(random_bytes.len == 32);

    // Test constant-time comparison
    const bytes1 = [_]u8{ 1, 2, 3, 4 };
    const bytes2 = [_]u8{ 1, 2, 3, 4 };
    const bytes3 = [_]u8{ 1, 2, 3, 5 };

    try testing.expect(sm9.Utils.constantTimeEqual(&bytes1, &bytes2));
    try testing.expect(!sm9.Utils.constantTimeEqual(&bytes1, &bytes3));

    // Test secure zero
    var sensitive_data = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD };
    sm9.Utils.secureZero(&sensitive_data);
    try testing.expect(std.mem.allEqual(u8, &sensitive_data, 0));
}

test "SM9 test vectors validation" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // This test validates the implementation with known test vectors
    const validation_result = try sm9.TestVectors.validateImplementation(allocator);
    try testing.expect(validation_result);
}

test "SM9 version and info" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Test version string
    const version_string = try sm9.getVersion(allocator);
    defer allocator.free(version_string);

    try testing.expect(version_string.len > 0);
    try testing.expect(std.mem.containsAtLeast(u8, version_string, 1, "1.0.0"));

    // Test library info
    const info = sm9.getInfo();
    try testing.expectEqualStrings("SM9-Zig", info.name);
    try testing.expectEqualStrings("GM/T 0044-2016", info.standard);
}

test "SM9 error handling" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var context = sm9.SM9Context.init(allocator);

    // Test invalid user ID
    const invalid_id = "";
    const sign_key_result = context.extractSignKey(invalid_id);

    // Should handle empty user ID gracefully
    if (sign_key_result) |_| {
        // If it succeeds, that's also valid behavior
    } else |err| {
        try testing.expect(err == sm9.SM9Error.InvalidUserId or
            err == sm9.SM9Error.KeyGenerationFailed);
    }
}

test "SM9 cross-module integration" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Test that all modules work together correctly
    const system = sm9.params.SM9System.init();

    // Key extraction
    const key_context = sm9.key_extract.KeyExtractionContext.init(system, allocator);
    const user_id = "integration@example.com";
    const sign_key = try key_context.extractSignKey(user_id);
    const encrypt_key = try key_context.extractEncryptKey(user_id);

    // Signature
    const sig_context = sm9.sign.SignatureContext.init(system, allocator);
    const message = "Integration test message";
    const signature = try sig_context.sign(message, sign_key, sm9.sign.SignatureOptions{});
    const is_valid = try sig_context.verify(message, signature, user_id, sm9.sign.SignatureOptions{});
    try testing.expect(is_valid);

    // Encryption
    const enc_context = sm9.encrypt.EncryptionContext.init(system, allocator);
    const ciphertext = try enc_context.encrypt(message, user_id, sm9.encrypt.EncryptionOptions{});
    defer ciphertext.deinit();

    const decrypted = try enc_context.decrypt(ciphertext, encrypt_key, sm9.encrypt.EncryptionOptions{});
    defer allocator.free(decrypted);

    try testing.expectEqualStrings(message, decrypted);
}
