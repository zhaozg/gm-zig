const std = @import("std");
const testing = std.testing;
const SM2 = @import("../sm2.zig");
const key_exchange = SM2.key_exchange;

test "SM2 key exchange comprehensive tests" {
    const allocator = testing.allocator;

    // Test 1: Basic key exchange setup
    const alice_private = SM2.SM2.scalar.random(.big);
    const alice_public = try SM2.SM2.basePoint.mul(alice_private, .big);
    const alice_id = "alice@example.com";

    const bob_private = SM2.SM2.scalar.random(.big);
    const bob_public = try SM2.SM2.basePoint.mul(bob_private, .big);
    const bob_id = "bob@example.com";

    // Test 2: Context initialization
    var alice_ctx = key_exchange.KeyExchangeContext.init(.initiator, alice_private, alice_public, alice_id);
    var bob_ctx = key_exchange.KeyExchangeContext.init(.responder, bob_private, bob_public, bob_id);

    try testing.expect(alice_ctx.role == .initiator);
    try testing.expect(bob_ctx.role == .responder);

    // Test 3: Ephemeral key generation
    try alice_ctx.ephemeral_public.rejectIdentity();
    try bob_ctx.ephemeral_public.rejectIdentity();

    const alice_ephemeral_sec1 = alice_ctx.getEphemeralPublicKey();
    const bob_ephemeral_sec1 = bob_ctx.getEphemeralPublicKey();

    try testing.expect(alice_ephemeral_sec1[0] == 0x04); // Uncompressed format
    try testing.expect(bob_ephemeral_sec1[0] == 0x04);

    // Test 4: Basic key exchange without confirmation
    const key_length = 32;

    const alice_result = try key_exchange.keyExchangeInitiator(
        allocator,
        &alice_ctx,
        bob_public,
        bob_ctx.ephemeral_public,
        bob_id,
        key_length,
        false,
    );
    defer alice_result.deinit(allocator);

    const bob_result = try key_exchange.keyExchangeResponder(
        allocator,
        &bob_ctx,
        alice_public,
        alice_ctx.ephemeral_public,
        alice_id,
        key_length,
        false,
    );
    defer bob_result.deinit(allocator);

    // Test 5: Shared keys should be equal
    try testing.expectEqualSlices(u8, alice_result.shared_key, bob_result.shared_key);
    try testing.expect(alice_result.key_confirmation == null);
    try testing.expect(bob_result.key_confirmation == null);

    // Test 6: Key exchange with confirmation
    const alice_result_conf = try key_exchange.keyExchangeInitiator(
        allocator,
        &alice_ctx,
        bob_public,
        bob_ctx.ephemeral_public,
        bob_id,
        key_length,
        true,
    );
    defer alice_result_conf.deinit(allocator);

    const bob_result_conf = try key_exchange.keyExchangeResponder(
        allocator,
        &bob_ctx,
        alice_public,
        alice_ctx.ephemeral_public,
        alice_id,
        key_length,
        true,
    );
    defer bob_result_conf.deinit(allocator);

    // Test 7: Confirmation values should exist
    try testing.expect(alice_result_conf.key_confirmation != null);
    try testing.expect(bob_result_conf.key_confirmation != null);

    // Shared keys should still be equal
    try testing.expectEqualSlices(u8, alice_result_conf.shared_key, bob_result_conf.shared_key);
}

test "SM2 key exchange different key lengths" {
    const allocator = testing.allocator;

    // Setup participants
    const alice_private = SM2.SM2.scalar.random(.big);
    const alice_public = try SM2.SM2.basePoint.mul(alice_private, .big);
    const alice_id = "alice";

    const bob_private = SM2.SM2.scalar.random(.big);
    const bob_public = try SM2.SM2.basePoint.mul(bob_private, .big);
    const bob_id = "bob";

    var alice_ctx = key_exchange.KeyExchangeContext.init(.initiator, alice_private, alice_public, alice_id);
    var bob_ctx = key_exchange.KeyExchangeContext.init(.responder, bob_private, bob_public, bob_id);

    // Test different key lengths
    const key_lengths = [_]usize{ 16, 32, 48, 64, 128, 256 };

    for (key_lengths) |length| {
        const alice_result = try key_exchange.keyExchangeInitiator(
            allocator,
            &alice_ctx,
            bob_public,
            bob_ctx.ephemeral_public,
            bob_id,
            length,
            false,
        );
        defer alice_result.deinit(allocator);

        const bob_result = try key_exchange.keyExchangeResponder(
            allocator,
            &bob_ctx,
            alice_public,
            alice_ctx.ephemeral_public,
            alice_id,
            length,
            false,
        );
        defer bob_result.deinit(allocator);

        // Verify key length and equality
        try testing.expect(alice_result.shared_key.len == length);
        try testing.expect(bob_result.shared_key.len == length);
        try testing.expectEqualSlices(u8, alice_result.shared_key, bob_result.shared_key);
    }
}

test "SM2 key exchange role validation" {
    const allocator = testing.allocator;

    const alice_private = SM2.SM2.scalar.random(.big);
    const alice_public = try SM2.SM2.basePoint.mul(alice_private, .big);
    const alice_id = "alice";

    const bob_private = SM2.SM2.scalar.random(.big);
    const bob_public = try SM2.SM2.basePoint.mul(bob_private, .big);
    const bob_id = "bob";

    // Create contexts with wrong roles
    var alice_ctx_wrong = key_exchange.KeyExchangeContext.init(.responder, alice_private, alice_public, alice_id);
    var bob_ctx_wrong = key_exchange.KeyExchangeContext.init(.initiator, bob_private, bob_public, bob_id);

    const key_length = 32;

    // Should fail with wrong roles
    try testing.expectError(
        error.InvalidRole,
        key_exchange.keyExchangeInitiator(
            allocator,
            &alice_ctx_wrong,
            bob_public,
            bob_ctx_wrong.ephemeral_public,
            bob_id,
            key_length,
            false,
        )
    );

    try testing.expectError(
        error.InvalidRole,
        key_exchange.keyExchangeResponder(
            allocator,
            &bob_ctx_wrong,
            alice_public,
            alice_ctx_wrong.ephemeral_public,
            alice_id,
            key_length,
            false,
        )
    );
}

test "SM2 key exchange identity element rejection" {
    const allocator = testing.allocator;

    const alice_private = SM2.SM2.scalar.random(.big);
    const alice_public = try SM2.SM2.basePoint.mul(alice_private, .big);
    const alice_id = "alice";

    const bob_private = SM2.SM2.scalar.random(.big);
    const bob_public = try SM2.SM2.basePoint.mul(bob_private, .big);
    const bob_id = "bob";

    var alice_ctx = key_exchange.KeyExchangeContext.init(.initiator, alice_private, alice_public, alice_id);
    const bob_ctx = key_exchange.KeyExchangeContext.init(.responder, bob_private, bob_public, bob_id);

    const identity = SM2.SM2.identityElement;
    const key_length = 32;

    // Should fail with identity element as public key
    try testing.expectError(
        error.IdentityElement,
        key_exchange.keyExchangeInitiator(
            allocator,
            &alice_ctx,
            identity,
            bob_ctx.ephemeral_public,
            bob_id,
            key_length,
            false,
        )
    );

    // Should fail with identity element as ephemeral key
    try testing.expectError(
        error.IdentityElement,
        key_exchange.keyExchangeInitiator(
            allocator,
            &alice_ctx,
            bob_public,
            identity,
            bob_id,
            key_length,
            false,
        )
    );
}

test "SM2 key exchange coordinate extraction" {
    const alice_private = SM2.SM2.scalar.random(.big);
    const alice_public = try SM2.SM2.basePoint.mul(alice_private, .big);
    const alice_id = "alice";

    var alice_ctx = key_exchange.KeyExchangeContext.init(.initiator, alice_private, alice_public, alice_id);

    // Test coordinate extraction
    const coords = alice_ctx.getEphemeralCoordinates();

    // Verify coordinates can be used to reconstruct the point
    const reconstructed = try key_exchange.ephemeralKeyFromCoordinates(coords.x, coords.y);
    try testing.expect(alice_ctx.ephemeral_public.equivalent(reconstructed));
}

test "SM2 key exchange SEC1 format handling" {
    const alice_private = SM2.SM2.scalar.random(.big);
    const alice_public = try SM2.SM2.basePoint.mul(alice_private, .big);
    const alice_id = "alice";

    var alice_ctx = key_exchange.KeyExchangeContext.init(.initiator, alice_private, alice_public, alice_id);

    // Test SEC1 format
    const sec1_bytes = alice_ctx.getEphemeralPublicKey();
    const reconstructed = try key_exchange.ephemeralKeyFromSec1(&sec1_bytes);

    try testing.expect(alice_ctx.ephemeral_public.equivalent(reconstructed));
}

test "SM2 key exchange confirmation verification" {
    const allocator = testing.allocator;

    const alice_private = SM2.SM2.scalar.random(.big);
    const alice_public = try SM2.SM2.basePoint.mul(alice_private, .big);
    const alice_id = "alice@test.com";

    const bob_private = SM2.SM2.scalar.random(.big);
    const bob_public = try SM2.SM2.basePoint.mul(bob_private, .big);
    const bob_id = "bob@test.com";

    var alice_ctx = key_exchange.KeyExchangeContext.init(.initiator, alice_private, alice_public, alice_id);
    var bob_ctx = key_exchange.KeyExchangeContext.init(.responder, bob_private, bob_public, bob_id);

    const key_length = 32;

    // Perform key exchange with confirmation
    const alice_result = try key_exchange.keyExchangeInitiator(
        allocator,
        &alice_ctx,
        bob_public,
        bob_ctx.ephemeral_public,
        bob_id,
        key_length,
        true,
    );
    defer alice_result.deinit(allocator);

    const bob_result = try key_exchange.keyExchangeResponder(
        allocator,
        &bob_ctx,
        alice_public,
        alice_ctx.ephemeral_public,
        alice_id,
        key_length,
        true,
    );
    defer bob_result.deinit(allocator);

    // Test confirmation verification (this is a simplified test)
    // In practice, the confirmation values would be computed differently
    try testing.expect(alice_result.key_confirmation != null);
    try testing.expect(bob_result.key_confirmation != null);
}

test "SM2 key exchange multiple rounds" {
    const allocator = testing.allocator;

    // Test that multiple key exchanges with the same participants produce different keys
    const alice_private = SM2.SM2.scalar.random(.big);
    const alice_public = try SM2.SM2.basePoint.mul(alice_private, .big);
    const alice_id = "alice";

    const bob_private = SM2.SM2.scalar.random(.big);
    const bob_public = try SM2.SM2.basePoint.mul(bob_private, .big);
    const bob_id = "bob";

    const key_length = 32;

    // First round
    var alice_ctx1 = key_exchange.KeyExchangeContext.init(.initiator, alice_private, alice_public, alice_id);
    const bob_ctx1 = key_exchange.KeyExchangeContext.init(.responder, bob_private, bob_public, bob_id);

    const alice_result1 = try key_exchange.keyExchangeInitiator(
        allocator,
        &alice_ctx1,
        bob_public,
        bob_ctx1.ephemeral_public,
        bob_id,
        key_length,
        false,
    );
    defer alice_result1.deinit(allocator);

    // Second round with new ephemeral keys
    var alice_ctx2 = key_exchange.KeyExchangeContext.init(.initiator, alice_private, alice_public, alice_id);
    const bob_ctx2 = key_exchange.KeyExchangeContext.init(.responder, bob_private, bob_public, bob_id);

    const alice_result2 = try key_exchange.keyExchangeInitiator(
        allocator,
        &alice_ctx2,
        bob_public,
        bob_ctx2.ephemeral_public,
        bob_id,
        key_length,
        false,
    );
    defer alice_result2.deinit(allocator);

    // Results should be different (due to different ephemeral keys)
    const are_different = !std.mem.eql(u8, alice_result1.shared_key, alice_result2.shared_key);
    try testing.expect(are_different);
}
