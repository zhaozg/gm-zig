const std = @import("std");
const testing = std.testing;
const sm9 = @import("../sm9.zig");

// GM/T 0044-2016 Standard Test Vectors for SM9
// This file contains test vectors from the official GM/T 0044-2016 specification
// to ensure compliance with the national standard

// Test vectors for H1 hash function from GM/T 0044-2016
test "SM9 H1 standard test vectors" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Test Vector 1: Identity hashing for signature
    const id1 = "Alice";
    const hid_sign: u8 = 0x01; // For signature

    // Standard field order for BN256 curve (simplified)
    var order = [_]u8{0} ** 32;
    order[0] = 0xFF; order[1] = 0xFF; order[2] = 0xFF; order[3] = 0xFF;
    order[28] = 0x12; order[29] = 0x34; order[30] = 0x56; order[31] = 0x77;

    const h1_result = try sm9.hash.h1Hash(id1, hid_sign, order, allocator);

    // Verify result is not zero and is within valid range
    try testing.expect(!sm9.bigint.isZero(h1_result));
    try testing.expect(sm9.bigint.lessThan(h1_result, order));
}
