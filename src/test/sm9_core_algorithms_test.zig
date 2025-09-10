const std = @import("std");
const testing = std.testing;
const sm9 = @import("../sm9.zig");

// Test core SM9 algorithms individually to ensure basic functionality
// This file contains focused tests for each key SM9 operation

test "SM9 basic key extraction validation" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Initialize SM9 system
    const system = sm9.params.SM9System.init();
    try testing.expect(system.params.validate());

    // Generate master keys
    const sign_master = sm9.params.SignMasterKeyPair.generate(system.params);
    const encrypt_master = sm9.params.EncryptMasterKeyPair.generate(system.params);

    // Create complete system with master keys
    const full_system = sm9.params.SM9System{
        .params = system.params,
        .sign_master = sign_master,
        .encrypt_master = encrypt_master,
    };

    // Create key extraction context
    const key_context = sm9.key_extract.KeyExtractionContext.init(
        full_system,
        allocator,
    );

    // Test user key extraction
    const user_id = "test@example.com";

    // Extract signature key
    const sign_key = try key_context.extractSignKey(user_id);

    // Validate signature key
    try testing.expect(sign_key.validate(system.params));
    try testing.expect(sign_key.hid == 0x01);
    try testing.expect(sign_key.key[0] == 0x02 or sign_key.key[0] == 0x03);

    // Extract encryption key
    const encrypt_key = try key_context.extractEncryptKey(user_id);

    // Validate encryption key
    try testing.expect(encrypt_key.validate(system.params));
    try testing.expect(encrypt_key.hid == 0x03);
    try testing.expect(encrypt_key.key[0] == 0x04);
}

test "SM9 basic hash functions H1 and H2" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const system = sm9.params.SM9System.init();
    const user_id = "test@example.com";

    // Test H1 hash function
    const h1_result = try sm9.key_extract.h1Hash(user_id, 0x01, system.params.N, allocator);

    // H1 result should not be zero
    var h1_zero = true;
    for (h1_result) |byte| {
        if (byte != 0) {
            h1_zero = false;
            break;
        }
    }
    try testing.expect(!h1_zero);

    // Test H2 hash function
    const message = "Hello, World!";
    const w = [_]u8{ 0x12, 0x34, 0x56, 0x78 } ++ [_]u8{0} ** 28;
    const h2_result = try sm9.key_extract.h2Hash(message, &w, system.params.N, allocator);

    // H2 result should not be zero
    var h2_zero = true;
    for (h2_result) |byte| {
        if (byte != 0) {
            h2_zero = false;
            break;
        }
    }
    try testing.expect(!h2_zero);
}

test "SM9 basic BN256 parameter compliance" {
    const system = sm9.params.SM9System.init();

    // Verify system parameters are valid
    try testing.expect(system.params.validate());
    try testing.expect(system.params.curve == .bn256);
    try testing.expect(system.params.v == 256);

    // Verify P1 format is correct
    try testing.expect(system.params.P1.len == 33);
    try testing.expect(system.params.P1[0] == 0x02 or system.params.P1[0] == 0x03);

    // Verify P2 format is correct
    try testing.expect(system.params.P2.len == 65);
    try testing.expect(system.params.P2[0] == 0x04);

    // Verify prime field order q and group order N are not zero
    var q_nonzero = false;
    var n_nonzero = false;

    for (system.params.q) |byte| {
        if (byte != 0) {
            q_nonzero = true;
            break;
        }
    }

    for (system.params.N) |byte| {
        if (byte != 0) {
            n_nonzero = true;
            break;
        }
    }

    try testing.expect(q_nonzero);
    try testing.expect(n_nonzero);
}
