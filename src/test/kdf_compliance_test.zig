const std = @import("std");
const testing = std.testing;
const allocator = testing.allocator;
const sm9 = @import("../sm9.zig");

test "GM/T 0044-2016 Compliant KDF Implementation" {
    // Test basic functionality with standard test vector
    const input = "GM/T 0044-2016 KDF Test Vector";
    const result32 = try sm9.encrypt.EncryptionUtils.kdf(input, 32, allocator);
    defer allocator.free(result32);

    // Verify output length
    try testing.expect(result32.len == 32);

    // Verify output is not all zeros (security requirement)
    var all_zero = true;
    for (result32) |byte| {
        if (byte != 0) {
            all_zero = false;
            break;
        }
    }
    try testing.expect(!all_zero);

    // Test deterministic behavior (same input should produce same output)
    const result32_2 = try sm9.encrypt.EncryptionUtils.kdf(input, 32, allocator);
    defer allocator.free(result32_2);
    try testing.expectEqualSlices(u8, result32, result32_2);

    // Test different output lengths
    const result16 = try sm9.encrypt.EncryptionUtils.kdf(input, 16, allocator);
    defer allocator.free(result16);
    try testing.expect(result16.len == 16);

    const result64 = try sm9.encrypt.EncryptionUtils.kdf(input, 64, allocator);
    defer allocator.free(result64);
    try testing.expect(result64.len == 64);

    // First 32 bytes should match result32 (KDF consistency check)
    try testing.expectEqualSlices(u8, result32, result64[0..32]);

    // Test edge cases - empty input should fail per GM/T 0044-2016
    try testing.expectError(error.KDFComputationFailed, sm9.encrypt.EncryptionUtils.kdf("", 32, allocator));

    // Test zero length output should fail
    try testing.expectError(error.KDFComputationFailed, sm9.encrypt.EncryptionUtils.kdf(input, 0, allocator));

    // Test very large output should fail (security limit)
    try testing.expectError(error.KDFComputationFailed, sm9.encrypt.EncryptionUtils.kdf(input, 0x200000, allocator));
}

test "GM/T 0044-2016 KDF Security Properties" {
    // Test that different inputs produce different outputs
    const input1 = "Test Input 1";
    const input2 = "Test Input 2";

    const result1 = try sm9.encrypt.EncryptionUtils.kdf(input1, 32, allocator);
    defer allocator.free(result1);

    const result2 = try sm9.encrypt.EncryptionUtils.kdf(input2, 32, allocator);
    defer allocator.free(result2);

    // Results should be different (avalanche effect)
    try testing.expect(!std.mem.eql(u8, result1, result2));

    // Test that single bit change produces completely different output
    const input3 = "Test Input 3";
    const input4 = "Test Input 4"; // Only last character different

    const result3 = try sm9.encrypt.EncryptionUtils.kdf(input3, 32, allocator);
    defer allocator.free(result3);

    const result4 = try sm9.encrypt.EncryptionUtils.kdf(input4, 32, allocator);
    defer allocator.free(result4);

    // Results should be different
    try testing.expect(!std.mem.eql(u8, result3, result4));

    // Count different bytes (should be significantly different)
    var different_bytes: usize = 0;
    for (result3, result4) |b1, b2| {
        if (b1 != b2) different_bytes += 1;
    }
    // Should have significant difference (avalanche property)
    try testing.expect(different_bytes >= 16); // At least 50% different
}

test "GM/T 0044-2016 KDF Standard Compliance" {
    // Test with official test vectors pattern
    const test_vectors = [_]struct {
        input: []const u8,
        output_len: usize,
        expected_non_zero: bool,
    }{
        .{ .input = "a", .output_len = 16, .expected_non_zero = true },
        .{ .input = "abc", .output_len = 32, .expected_non_zero = true },
        .{ .input = "message digest", .output_len = 48, .expected_non_zero = true },
        .{ .input = "abcdefghijklmnopqrstuvwxyz", .output_len = 64, .expected_non_zero = true },
    };

    for (test_vectors) |tv| {
        const result = try sm9.encrypt.EncryptionUtils.kdf(tv.input, tv.output_len, allocator);
        defer allocator.free(result);

        try testing.expect(result.len == tv.output_len);

        var non_zero = false;
        for (result) |byte| {
            if (byte != 0) {
                non_zero = true;
                break;
            }
        }
        try testing.expect(non_zero == tv.expected_non_zero);
    }
}

// Vectors generated independently with the Python pysmx/snowland-smx SM9
// implementation (SM3-based H2 and KDF).
test "SM9 KDF and H2 match external reference vectors" {
    const kdf_expected = [_]u8{
        0xfe, 0x1e, 0xa8, 0x0d, 0xac, 0x6f, 0x10, 0x0c,
        0x33, 0x53, 0x7b, 0xd2, 0x46, 0x19, 0xec, 0x7c,
        0x72, 0xa1, 0xe8, 0xb1, 0xff, 0xea, 0xef, 0xb1,
        0xeb, 0x52, 0xa3, 0x77, 0x91, 0xfd, 0xaf, 0x61,
    };
    const kdf_out = try sm9.encrypt.EncryptionUtils.kdf("abc", 32, allocator);
    defer allocator.free(kdf_out);
    try testing.expectEqualSlices(u8, &kdf_expected, kdf_out);

    var w: [32]u8 = undefined;
    for (&w, 0..) |*b, i| b.* = @intCast(i);
    const order = [_]u8{
        0xb6, 0x40, 0x00, 0x00, 0x02, 0xa3, 0xa6, 0xf1,
        0xd6, 0x03, 0xab, 0x4f, 0xf5, 0x8e, 0xc7, 0x44,
        0x49, 0xf2, 0x93, 0x4b, 0x18, 0xea, 0x8b, 0xee,
        0xe5, 0x6e, 0xe1, 0x9c, 0xd6, 0x9e, 0xcf, 0x25,
    };
    const h2 = try sm9.hash.h2Hash("abc", &w, order, allocator);
    var h2_int: u256 = 0;
    for (h2) |b| h2_int = (h2_int << 8) | b;
    try testing.expectEqual(@as(u256, 0x1f38065a441763eb1fa47ad71046972ee65f8a8ba2ecbd2d2f2236561dfcfae9), h2_int);
}

// H1 first-block vector for ID = "Alice", hid = 0x01, computed with SM3.
test "SM9 H1 scalar follows the GM/T 0044-2016 H1 construction" {
    const order = [_]u8{
        0xb6, 0x40, 0x00, 0x00, 0x02, 0xa3, 0xa6, 0xf1,
        0xd6, 0x03, 0xab, 0x4f, 0xf5, 0x8e, 0xc7, 0x44,
        0x49, 0xf2, 0x93, 0x4b, 0x18, 0xea, 0x8b, 0xee,
        0xe5, 0x6e, 0xe1, 0x9c, 0xd6, 0x9e, 0xcf, 0x25,
    };
    const h1 = try sm9.hash.h1Hash("Alice", 0x01, order, allocator);
    var h1_int: u256 = 0;
    for (h1) |b| h1_int = (h1_int << 8) | b;
    try testing.expectEqual(@as(u256, 0x2acc468c3926b0bdb2767e99ff26e084de9ced8dbc7d5fbf418027b667862fab), h1_int);
}
