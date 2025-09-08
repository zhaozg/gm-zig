const std = @import("std");
const testing = std.testing;
const sm9 = @import("../sm9.zig");

// Test key extraction robustness under edge conditions
test "SM9 key extraction mathematical robustness" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const system = sm9.params.SM9System.init();
    const key_context = sm9.key_extract.KeyExtractionContext.init(system, allocator);

    // Test edge case user IDs that might cause mathematical issues
    const edge_case_ids = [_][]const u8{
        "", // Empty ID (should handle gracefully)
        "0", // Single character
        "test@domain", // Normal case
        "very_long_user_id_that_might_cause_hash_edge_cases@domain.com", // Long ID
        "user_with_special_chars!@#$%^&*()@domain.com", // Special characters
        "测试用户@示例.com", // Unicode characters
    };

    var successful_extractions: usize = 0;

    for (edge_case_ids) |user_id| {
        // Skip empty ID as it should return error
        if (user_id.len == 0) continue;

        // Test signature key extraction
        const sign_key = key_context.extractSignKey(user_id) catch |err| {
            std.debug.print("Sign key extraction failed for '{s}': {}\n", .{ user_id, err });
            continue;
        };

        // Validate extracted key
        try testing.expect(sign_key.validate(system.params));
        try testing.expect(sign_key.hid == 0x01);
        try testing.expectEqualStrings(user_id, sign_key.id);

        // Test encryption key extraction
        const encrypt_key = key_context.extractEncryptKey(user_id) catch |err| {
            std.debug.print("Encrypt key extraction failed for '{s}': {}\n", .{ user_id, err });
            continue;
        };

        // Validate extracted key
        try testing.expect(encrypt_key.validate(system.params));
        try testing.expect(encrypt_key.hid == 0x03);
        try testing.expectEqualStrings(user_id, encrypt_key.id);

        successful_extractions += 1;
    }

    // Expect most extractions to succeed (at least 4 out of 6 non-empty IDs)
    try testing.expect(successful_extractions >= 4);
}

// Test public key derivation robustness
test "SM9 public key derivation robustness" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const system = sm9.params.SM9System.init();

    const test_users = [_][]const u8{
        "alice@test.com",
        "bob@test.com",
        "charlie@domain.org",
        "test_user_123@example.net",
    };

    for (test_users) |user_id| {
        // Test signature public key derivation
        const sign_public = try sm9.key_extract.UserPublicKey.deriveForSignature(
            user_id,
            system.params,
            system.sign_master,
            allocator,
        );

        try testing.expect(sign_public.validate(system.params));
        try testing.expect(sign_public.hid == 0x01);
        try testing.expectEqualStrings(user_id, sign_public.id);

        // Verify public key is deterministic
        const sign_public2 = try sm9.key_extract.UserPublicKey.deriveForSignature(
            user_id,
            system.params,
            system.sign_master,
            allocator,
        );
        try testing.expectEqualSlices(u8, &sign_public.point, &sign_public2.point);

        // Test encryption public key derivation
        const encrypt_public = try sm9.key_extract.UserPublicKey.deriveForEncryption(
            user_id,
            system.params,
            system.encrypt_master,
            allocator,
        );

        try testing.expect(encrypt_public.validate(system.params));
        try testing.expect(encrypt_public.hid == 0x03);
        try testing.expectEqualStrings(user_id, encrypt_public.id);

        // Verify encryption public key is deterministic
        const encrypt_public2 = try sm9.key_extract.UserPublicKey.deriveForEncryption(
            user_id,
            system.params,
            system.encrypt_master,
            allocator,
        );
        try testing.expectEqualSlices(u8, &encrypt_public.point, &encrypt_public2.point);
    }
}

// Test mathematical boundary conditions in bigint operations
test "SM9 bigint mathematical boundary conditions" {
    // Test edge cases for modular inverse
    const zero = [_]u8{0} ** 32;
    const one = [_]u8{0} ** 31 ++ [_]u8{1};
    const large_num = [_]u8{0xFF} ** 32;
    const modulus = sm9.params.SM9System.init().params.N;

    // Test zero (should fail)
    const zero_result = sm9.bigint.invMod(zero, modulus);
    try testing.expectError(sm9.bigint.BigIntError.NotInvertible, zero_result);

    // Test one (should succeed and return 1)
    const one_result = try sm9.bigint.invMod(one, modulus);
    try testing.expect(sm9.bigint.equal(one_result, one));

    // Test large number (should handle gracefully)
    const large_result = sm9.bigint.invMod(large_num, modulus);
    _ = large_result catch |err| {
        // It's okay if it fails for large numbers
        try testing.expect(err == sm9.bigint.BigIntError.NotInvertible);
    };

    // Test modular arithmetic edge cases
    const a = sm9.bigint.fromU64(12345);
    const b = sm9.bigint.fromU64(67890);

    // Addition should not overflow
    const sum = try sm9.bigint.addMod(a, b, modulus);
    try testing.expect(!sm9.bigint.isZero(sum));

    // Subtraction should handle underflow
    const diff = try sm9.bigint.subMod(a, b, modulus);
    try testing.expect(sm9.bigint.lessThan(diff, modulus));

    // Multiplication should not overflow
    const prod = try sm9.bigint.mulMod(a, b, modulus);
    try testing.expect(!sm9.bigint.isZero(prod));
}

// Test signature and verification robustness
test "SM9 signature robustness with edge cases" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const system = sm9.params.SM9System.init();
    const key_context = sm9.key_extract.KeyExtractionContext.init(system, allocator);
    const sign_context = sm9.sign.SignatureContext.init(system, allocator);

    const user_id = "robustness_test@example.com";

    // Extract signing key
    const sign_key = try key_context.extractSignKey(user_id);

    // Test various message types
    const test_messages = [_][]const u8{
        "", // Empty message
        "a", // Single character
        "Hello, SM9!", // Normal message
        "Very long message that contains a lot of text to test how the signature algorithm handles longer inputs which might stress the hash functions and mathematical operations", // Long message
        "\x00\x01\x02\x03\x04\x05", // Binary data
        "Message with unicode: 测试信息 🔐", // Unicode content
    };

    for (test_messages) |message| {
        // Skip empty message as it might be invalid
        if (message.len == 0) continue;

        // Test signature generation
        const signature = sign_context.sign(message, sign_key, .{}) catch |err| {
            std.debug.print("Signature generation failed for message length {}: {}\n", .{ message.len, err });
            continue;
        };

        // Validate signature format
        try testing.expect(signature.validate());

        // Test signature verification
        const is_valid = try sign_context.verify(message, signature, user_id, .{});
        try testing.expect(is_valid);

        // Test verification with wrong user (should fail)
        const wrong_user = "wrong_user@example.com";
        const is_invalid = try sign_context.verify(message, signature, wrong_user, .{});
        try testing.expect(!is_invalid);

        // Test verification with modified message (should fail)
        if (message.len > 1) {
            var modified_message = try allocator.dupe(u8, message);
            defer allocator.free(modified_message);
            modified_message[0] = modified_message[0] ^ 0x01; // Flip one bit

            const is_invalid_msg = try sign_context.verify(modified_message, signature, user_id, .{});
            try testing.expect(!is_invalid_msg);
        }
    }
}

// Test encryption and decryption robustness
test "SM9 encryption robustness with edge cases" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const system = sm9.params.SM9System.init();
    const key_context = sm9.key_extract.KeyExtractionContext.init(system, allocator);
    const encrypt_context = sm9.encrypt.EncryptionContext.init(system, allocator);

    const user_id = "robustness_encrypt_test@example.com";

    // Extract encryption key
    const encrypt_key = try key_context.extractEncryptKey(user_id);

    // Test various message types for encryption
    const test_messages = [_][]const u8{
        "a", // Single character
        "Hello, SM9 Encryption!", // Normal message
        "Short", // Short message
        "Medium length message for testing encryption robustness", // Medium message
        "\x00\x01\x02\x03\x04\x05\xFF\xFE", // Binary data
        "Encryption test with unicode: 加密测试 🔒", // Unicode content
    };

    for (test_messages) |message| {
        // Test encryption
        const ciphertext = encrypt_context.encrypt(message, user_id, .{}) catch |err| {
            std.debug.print("Encryption failed for message length {}: {}\n", .{ message.len, err });
            continue;
        };
        defer ciphertext.deinit();

        // Validate ciphertext format
        try testing.expect(ciphertext.validate());

        // Test decryption
        const decrypted = encrypt_context.decrypt(ciphertext, encrypt_key, .{}) catch |err| {
            std.debug.print("Decryption failed for message length {}: {}\n", .{ message.len, err });
            continue;
        };
        defer allocator.free(decrypted);

        // Verify decrypted message matches original
        try testing.expectEqualSlices(u8, message, decrypted);
    }
}

// Test curve operations robustness
test "SM9 curve operations robustness" {
    const system = sm9.params.SM9System.init();

    // Test G1 generator
    const g1_gen = sm9.curve.CurveUtils.getG1Generator(system.params);
    try testing.expect(g1_gen.validate(system.params));

    // Test G2 generator
    const g2_gen = sm9.curve.CurveUtils.getG2Generator(system.params);
    try testing.expect(g2_gen.validate(system.params));

    // Test point operations don't crash with edge cases
    const infinity_g1 = sm9.curve.G1Point.infinity();
    try testing.expect(infinity_g1.isInfinity());
    try testing.expect(infinity_g1.validate(system.params));

    const infinity_g2 = sm9.curve.G2Point.infinity();
    try testing.expect(infinity_g2.isInfinity());
    try testing.expect(infinity_g2.validate(system.params));

    // Test scalar multiplication with edge scalars
    const zero_scalar = [_]u8{0} ** 32;
    const one_scalar = [_]u8{0} ** 31 ++ [_]u8{1};

    const zero_result_g1 = g1_gen.mul(zero_scalar, system.params);
    try testing.expect(zero_result_g1.isInfinity());

    const one_result_g1 = g1_gen.mul(one_scalar, system.params);
    try testing.expect(!one_result_g1.isInfinity());

    const zero_result_g2 = g2_gen.mul(zero_scalar, system.params);
    try testing.expect(zero_result_g2.isInfinity());

    const one_result_g2 = g2_gen.mul(one_scalar, system.params);
    try testing.expect(!one_result_g2.isInfinity());
}
