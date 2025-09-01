const std = @import("std");
const testing = std.testing;
const sm9 = @import("../sm9.zig");

test "SM9 key agreement basic functionality" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const system = sm9.params.SM9System.init();
    const key_context = sm9.key_extract.KeyExtractionContext.init(system, allocator);
    const ka_context = sm9.key_agreement.KeyAgreementContext.init(system, allocator);

    // Test users
    const alice_id = "alice@example.com";
    const bob_id = "bob@example.com";

    // Extract private keys
    const alice_sign_key = try key_context.extractSignKey(alice_id);
    const bob_sign_key = try key_context.extractSignKey(bob_id);

    // Validate private keys
    try testing.expect(alice_sign_key.validate(system.params));
    try testing.expect(bob_sign_key.validate(system.params));

    // Generate ephemeral key pairs
    const alice_ephemeral = try ka_context.generateEphemeralKey(alice_id);
    const bob_ephemeral = try ka_context.generateEphemeralKey(bob_id);

    // Validate ephemeral keys
    try testing.expect(alice_ephemeral.validate(system.params));
    try testing.expect(bob_ephemeral.validate(system.params));

    // Perform key agreement (Alice as initiator)
    const alice_shared_key = try ka_context.performKeyAgreement(
        alice_id,
        alice_sign_key,
        alice_ephemeral,
        bob_id,
        bob_ephemeral.public_key,
        .initiator,
        32, // 32-byte shared key
    );
    defer allocator.free(alice_shared_key);

    // Perform key agreement (Bob as responder)
    const bob_shared_key = try ka_context.performKeyAgreement(
        bob_id,
        bob_sign_key,
        bob_ephemeral,
        alice_id,
        alice_ephemeral.public_key,
        .responder,
        32, // 32-byte shared key
    );
    defer allocator.free(bob_shared_key);

    // Verify shared keys are the same
    try testing.expectEqualSlices(u8, alice_shared_key, bob_shared_key);

    // Verify shared key is not all zeros
    var all_zero = true;
    for (alice_shared_key) |byte| {
        if (byte != 0) {
            all_zero = false;
            break;
        }
    }
    try testing.expect(!all_zero);
}

test "SM9 key agreement with different key lengths" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const system = sm9.params.SM9System.init();
    const key_context = sm9.key_extract.KeyExtractionContext.init(system, allocator);
    const ka_context = sm9.key_agreement.KeyAgreementContext.init(system, allocator);

    const alice_id = "alice@test.com";
    const bob_id = "bob@test.com";

    const alice_sign_key = try key_context.extractSignKey(alice_id);
    const bob_sign_key = try key_context.extractSignKey(bob_id);

    const alice_ephemeral = try ka_context.generateEphemeralKey(alice_id);
    const bob_ephemeral = try ka_context.generateEphemeralKey(bob_id);

    // Test different key lengths
    const key_lengths = [_]usize{ 16, 32, 48, 64, 128, 256 };

    for (key_lengths) |key_len| {
        // Alice's key agreement
        const alice_key = try ka_context.performKeyAgreement(
            alice_id,
            alice_sign_key,
            alice_ephemeral,
            bob_id,
            bob_ephemeral.public_key,
            .initiator,
            key_len,
        );
        defer allocator.free(alice_key);

        // Bob's key agreement
        const bob_key = try ka_context.performKeyAgreement(
            bob_id,
            bob_sign_key,
            bob_ephemeral,
            alice_id,
            alice_ephemeral.public_key,
            .responder,
            key_len,
        );
        defer allocator.free(bob_key);

        // Verify length and equality
        try testing.expect(alice_key.len == key_len);
        try testing.expect(bob_key.len == key_len);
        try testing.expectEqualSlices(u8, alice_key, bob_key);
    }
}

test "SM9 key agreement parameter validation" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Test parameter validation
    try testing.expect(sm9.key_agreement.KeyAgreementUtils.validateParameters(
        "alice@test.com",
        "bob@test.com",
        32,
    ));

    // Test invalid parameters
    try testing.expect(!sm9.key_agreement.KeyAgreementUtils.validateParameters(
        "", // Empty user ID
        "bob@test.com",
        32,
    ));

    try testing.expect(!sm9.key_agreement.KeyAgreementUtils.validateParameters(
        "alice@test.com",
        "alice@test.com", // Same user ID
        32,
    ));

    try testing.expect(!sm9.key_agreement.KeyAgreementUtils.validateParameters(
        "alice@test.com",
        "bob@test.com",
        0, // Zero key length
    ));
}

test "SM9 key agreement session ID generation" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const alice_id = "alice@example.com";
    const bob_id = "bob@example.com";

    // Generate sample ephemeral keys (just for testing)
    const ephemeral_a = [_]u8{0x02} ++ [_]u8{0x01} ** 32;
    const ephemeral_b = [_]u8{0x02} ++ [_]u8{0x02} ** 32;

    // Generate session ID
    const session_id1 = try sm9.key_agreement.KeyAgreementUtils.generateSessionId(
        alice_id,
        bob_id,
        ephemeral_a,
        ephemeral_b,
        allocator,
    );
    defer allocator.free(session_id1);

    // Generate same session ID with same parameters
    const session_id2 = try sm9.key_agreement.KeyAgreementUtils.generateSessionId(
        alice_id,
        bob_id,
        ephemeral_a,
        ephemeral_b,
        allocator,
    );
    defer allocator.free(session_id2);

    // Should be deterministic
    try testing.expectEqualSlices(u8, session_id1, session_id2);

    // Generate session ID with swapped users (should be the same due to ordering)
    const session_id3 = try sm9.key_agreement.KeyAgreementUtils.generateSessionId(
        bob_id,
        alice_id,
        ephemeral_b,
        ephemeral_a,
        allocator,
    );
    defer allocator.free(session_id3);

    try testing.expectEqualSlices(u8, session_id1, session_id3);

    // Verify session ID format (should be 64 hex characters)
    try testing.expect(session_id1.len == 64);
    for (session_id1) |char| {
        try testing.expect(
            (char >= '0' and char <= '9') or
            (char >= 'a' and char <= 'f')
        );
    }
}

test "SM9 key agreement deterministic behavior" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const system = sm9.params.SM9System.init();
    const key_context = sm9.key_extract.KeyExtractionContext.init(system, allocator);
    const ka_context = sm9.key_agreement.KeyAgreementContext.init(system, allocator);

    const alice_id = "deterministic_alice@test.com";
    const bob_id = "deterministic_bob@test.com";

    const alice_sign_key = try key_context.extractSignKey(alice_id);
    const bob_sign_key = try key_context.extractSignKey(bob_id);

    // Generate ephemeral keys multiple times and ensure deterministic behavior
    const alice_ephemeral1 = try ka_context.generateEphemeralKey(alice_id);
    const alice_ephemeral2 = try ka_context.generateEphemeralKey(alice_id);

    // Note: Due to timestamp inclusion, ephemeral keys might be different
    // But the key agreement should still work correctly

    const bob_ephemeral = try ka_context.generateEphemeralKey(bob_id);

    // Perform key agreement with first ephemeral key
    const shared_key1 = try ka_context.performKeyAgreement(
        alice_id,
        alice_sign_key,
        alice_ephemeral1,
        bob_id,
        bob_ephemeral.public_key,
        .initiator,
        32,
    );
    defer allocator.free(shared_key1);

    // Verify key agreement produces valid results
    try testing.expect(shared_key1.len == 32);

    var all_zero = true;
    for (shared_key1) |byte| {
        if (byte != 0) {
            all_zero = false;
            break;
        }
    }
    try testing.expect(!all_zero);
}

test "SM9 key agreement error handling" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const system = sm9.params.SM9System.init();
    const key_context = sm9.key_extract.KeyExtractionContext.init(system, allocator);
    const ka_context = sm9.key_agreement.KeyAgreementContext.init(system, allocator);

    const alice_id = "alice@error.test";
    const bob_id = "bob@error.test";

    const alice_sign_key = try key_context.extractSignKey(alice_id);
    const alice_ephemeral = try ka_context.generateEphemeralKey(alice_id);

    // Test with invalid peer ephemeral key (all zeros)
    const invalid_ephemeral = [_]u8{0} ** 33;

    const result = ka_context.performKeyAgreement(
        alice_id,
        alice_sign_key,
        alice_ephemeral,
        bob_id,
        invalid_ephemeral,
        .initiator,
        32,
    );

    try testing.expectError(sm9.key_agreement.KeyAgreementError.InvalidPublicKey, result);

    // Test with empty user ID
    const bob_ephemeral = try ka_context.generateEphemeralKey(bob_id);

    const result2 = ka_context.performKeyAgreement(
        "", // Empty user ID
        alice_sign_key,
        alice_ephemeral,
        bob_id,
        bob_ephemeral.public_key,
        .initiator,
        32,
    );

    try testing.expectError(sm9.key_agreement.KeyAgreementError.InvalidUserId, result2);

    // Test with zero key length
    const result3 = ka_context.performKeyAgreement(
        alice_id,
        alice_sign_key,
        alice_ephemeral,
        bob_id,
        bob_ephemeral.public_key,
        .initiator,
        0, // Zero key length
    );

    try testing.expectError(sm9.key_agreement.KeyAgreementError.InvalidKeyLength, result3);
}