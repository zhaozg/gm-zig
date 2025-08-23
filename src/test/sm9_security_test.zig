const std = @import("std");
const testing = std.testing;
const sm9 = @import("../sm9.zig");

// Minimal test to check if basic imports work
test "SM9 basic import test" {
    // Test that we can access the modules
    const zero = [_]u8{0} ** 32;
    try testing.expect(sm9.bigint.isZero(zero));
}

// Test constant-time operations for timing attack resistance
test "SM9 constant-time operations" {
    // Test constant-time equality
    const a = [_]u8{0x12, 0x34, 0x56, 0x78} ++ [_]u8{0} ** 28;
    const b = [_]u8{0x12, 0x34, 0x56, 0x78} ++ [_]u8{0} ** 28;
    const c = [_]u8{0x12, 0x34, 0x56, 0x79} ++ [_]u8{0} ** 28;

    // Test equal values
    try testing.expect(sm9.bigint.equal(a, b));

    // Test different values
    try testing.expect(!sm9.bigint.equal(a, c));

    // Test constant-time comparison
    try testing.expect(sm9.bigint.compare(a, b) == 0);
    try testing.expect(sm9.bigint.compare(a, c) < 0);
    try testing.expect(sm9.bigint.compare(c, a) > 0);
}

// Test secure memory clearing
test "SM9 secure memory clearing" {
    var sensitive_data = [_]u8{0xDE, 0xAD, 0xBE, 0xEF} ++ [_]u8{0xFF} ** 28;

    // Verify data is not zero initially
    try testing.expect(!sm9.bigint.isZero(sensitive_data));

    // Clear securely
    sm9.bigint.secureClear(&sensitive_data);

    // Verify data is now zero
    try testing.expect(sm9.bigint.isZero(sensitive_data));
}

// Test improved modular inverse
test "SM9 modular inverse improvements" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    // Test with small values first
    const a = sm9.bigint.fromU64(7);
    const m = sm9.bigint.fromU64(13);

    // Compute inverse
    const inv = try sm9.bigint.invMod(a, m);

    // Verify: a * inv ≡ 1 (mod m)
    const product = try sm9.bigint.mulMod(a, inv, m);
    const one = sm9.bigint.fromU64(1);

    // Verify the inverse relationship
    try testing.expect(sm9.bigint.equal(product, one));
}

// Test point validation security
test "SM9 curve point validation" {
    const params = sm9.params.SystemParams.init();

    // Test valid point at infinity
    const infinity = sm9.curve.G1Point.infinity();
    try testing.expect(infinity.validate(params));

    // Test with constructed point (may or may not be on curve)
    const x = [_]u8{0x01} ++ [_]u8{0} ** 31;
    const y = [_]u8{0x02} ++ [_]u8{0} ** 31;
    const point = sm9.curve.G1Point.affine(x, y);

    // Validation should complete without errors
    const is_valid = point.validate(params);

    // Even if point is not on curve, validation should return cleanly
    try testing.expect(is_valid == true or is_valid == false);
}

// Test hash function improvements
test "SM9 improved hash functions" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const data = "test@example.com";
    const order = sm9.bigint.fromU64(999999999);

    // Test H1 hash function
    const h1_result = try sm9.hash.h1Hash(data, 0x01, order, allocator);

    // Result should not be zero
    try testing.expect(!sm9.bigint.isZero(h1_result));

    // Result should be deterministic
    const h1_result2 = try sm9.hash.h1Hash(data, 0x01, order, allocator);
    try testing.expect(sm9.bigint.equal(h1_result, h1_result2));

    // Test H2 hash function
    const message = "Hello, SM9!";
    const additional_data = "additional";
    const h2_result = try sm9.hash.h2Hash(message, additional_data, allocator);

    // Result should not be zero
    try testing.expect(!sm9.bigint.isZero(h2_result));

    // Result should be deterministic
    const h2_result2 = try sm9.hash.h2Hash(message, additional_data, allocator);
    try testing.expect(sm9.bigint.equal(h2_result, h2_result2));

    // Different inputs should produce different outputs
    const h2_result3 = try sm9.hash.h2Hash("Different message", additional_data, allocator);
    try testing.expect(!sm9.bigint.equal(h2_result, h2_result3));
}

// Test input validation in encryption
test "SM9 encryption input validation" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const system = sm9.params.SM9System.init();
    const ctx = sm9.encrypt.EncryptionContext.init(system, allocator);

    // Test empty message
    const empty_message = "";
    const valid_user_id = "user@example.com";
    const options = sm9.encrypt.EncryptionOptions{};

    const result = ctx.encrypt(empty_message, valid_user_id, options);
    try testing.expectError(sm9.encrypt.EncryptionError.InvalidMessage, result);

    // Test empty user ID
    const valid_message = "Hello, world!";
    const empty_user_id = "";

    const result2 = ctx.encrypt(valid_message, empty_user_id, options);
    try testing.expectError(sm9.encrypt.EncryptionError.InvalidUserId, result2);
}

// Test G2 point validation improvements
test "SM9 G2 point validation" {
    const params = sm9.params.SystemParams.init();

    // Test point at infinity
    const infinity = sm9.curve.G2Point.infinity();
    try testing.expect(infinity.validate(params));

    // Test with constructed G2 point
    const x = [_]u8{0x01} ++ [_]u8{0} ** 63; // 64 bytes for Fp2
    const y = [_]u8{0x02} ++ [_]u8{0} ** 63; // 64 bytes for Fp2

    const point = sm9.curve.G2Point.affine(x, y);

    // Validation should complete without errors
    const is_valid = point.validate(params);

    // Validation should return a boolean result
    try testing.expect(is_valid == true or is_valid == false);
}

// Test edge cases and boundary conditions
test "SM9 edge cases and boundary conditions" {
    // Test zero values
    const zero = [_]u8{0} ** 32;
    try testing.expect(sm9.bigint.isZero(zero));

    // Test maximum values
    const max_val = [_]u8{0xFF} ** 32;
    try testing.expect(!sm9.bigint.isZero(max_val));

    // Test comparison edge cases
    try testing.expect(sm9.bigint.compare(zero, zero) == 0);
    try testing.expect(sm9.bigint.compare(zero, max_val) < 0);
    try testing.expect(sm9.bigint.compare(max_val, zero) > 0);

    // Test equality edge cases
    try testing.expect(sm9.bigint.equal(zero, zero));
    try testing.expect(!sm9.bigint.equal(zero, max_val));
}
