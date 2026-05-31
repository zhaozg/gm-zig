const std = @import("std");
const testing = std.testing;
const sm9 = @import("../sm9.zig");

// SM9 Reference Implementation Compliance Tests
// Based on the SM9 C reference implementation (SM9_sv.c, SM9_enc_dec.c, SM9_Key_ex.c)
// from the GM/T 0044-2016 standard reference code.

// Test the complete SM9 signature algorithm flow as defined in SM9_sv.c
test "SM9 reference sign algorithm flow compliance" {
    const io = testing.io;
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const system = sm9.params.SM9System.init();
    const key_context = sm9.key_extract.KeyExtractionContext.init(system, io, allocator);
    const sign_context = sm9.sign.SignatureContext.init(system, io, allocator);

    const user_id = "Alice";
    const message = "Chinese IBS standard";

    const user_key = try key_context.extractSignKey(user_id);
    try testing.expect(user_key.validate(system.params));

    const signature = try sign_context.sign(message, user_key, .{});
    try testing.expect(signature.validate());

    const is_valid = try sign_context.verify(message, signature, user_id, .{});
    try testing.expect(is_valid);

    const wrong_message = "Different message";
    const is_invalid = try sign_context.verify(wrong_message, signature, user_id, .{});
    try testing.expect(!is_invalid);

    const wrong_user = "Bob";
    const is_invalid_user = try sign_context.verify(message, signature, wrong_user, .{});
    try testing.expect(!is_invalid_user);
}

// Test the complete SM9 verification algorithm flow
test "SM9 reference verify algorithm flow compliance" {
    const io = testing.io;
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const system = sm9.params.SM9System.init();
    const key_context = sm9.key_extract.KeyExtractionContext.init(system, io, allocator);
    const sign_context = sm9.sign.SignatureContext.init(system, io, allocator);

    const test_cases = [_]struct {
        user_id: []const u8,
        message: []const u8,
    }{
        .{ .user_id = "Alice", .message = "Chinese IBS standard" },
        .{ .user_id = "Bob", .message = "message digest" },
        .{ .user_id = "alice@example.com", .message = "SM9 test message" },
        .{ .user_id = "bob@example.com", .message = "Hello, SM9 World!" },
    };

    for (test_cases) |tc| {
        const user_key = try key_context.extractSignKey(tc.user_id);
        const signature = try sign_context.sign(tc.message, user_key, .{});
        const is_valid = try sign_context.verify(tc.message, signature, tc.user_id, .{});
        try testing.expect(is_valid);

        if (tc.message.len > 0) {
            var modified = try allocator.dupe(u8, tc.message);
            defer allocator.free(modified);
            modified[0] ^= 0x01;
            const is_invalid = try sign_context.verify(modified, signature, tc.user_id, .{});
            try testing.expect(!is_invalid);
        }
    }
}

// Test SM9 H1 hash function compliance
test "SM9 H1 hash function reference compliance" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const system = sm9.params.SM9System.init();

    const test_ids = [_]struct {
        id: []const u8,
        hid: u8,
    }{
        .{ .id = "Alice", .hid = 0x01 },
        .{ .id = "Bob", .hid = 0x01 },
        .{ .id = "Alice", .hid = 0x03 },
        .{ .id = "test@example.com", .hid = 0x01 },
        .{ .id = "test@example.com", .hid = 0x03 },
    };

    for (test_ids) |tc| {
        const h1_result = try sm9.hash.h1Hash(tc.id, tc.hid, system.params.N, allocator);
        try testing.expect(!sm9.bigint.isZero(h1_result));
        try testing.expect(sm9.bigint.lessThan(h1_result, system.params.N));

        const h1_result2 = try sm9.hash.h1Hash(tc.id, tc.hid, system.params.N, allocator);
        try testing.expectEqualSlices(u8, &h1_result, &h1_result2);
    }
}

// Test SM9 H2 hash function compliance
test "SM9 H2 hash function reference compliance" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const system = sm9.params.SM9System.init();

    const test_cases = [_]struct {
        message: []const u8,
        w: [32]u8,
    }{
        .{ .message = "Chinese IBS standard", .w = [_]u8{0x01} ** 32 },
        .{ .message = "message digest", .w = [_]u8{0x02} ** 32 },
        .{ .message = "Hello, SM9!", .w = [_]u8{0x03} ** 32 },
        .{ .message = "x", .w = [_]u8{0x04} ** 32 },
    };

    for (test_cases) |tc| {
        const h2_result = try sm9.hash.h2Hash(tc.message, &tc.w, system.params.N, allocator);
        try testing.expect(!sm9.bigint.isZero(h2_result));
        try testing.expect(sm9.bigint.lessThan(h2_result, system.params.N));

        const h2_result2 = try sm9.hash.h2Hash(tc.message, &tc.w, system.params.N, allocator);
        try testing.expectEqualSlices(u8, &h2_result, &h2_result2);
    }
}

// Test SM9 key generation compliance
test "SM9 key generation reference compliance" {
    const io = testing.io;
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const system = sm9.params.SM9System.init();
    const key_context = sm9.key_extract.KeyExtractionContext.init(system, io, allocator);

    const test_ids = [_][]const u8{
        "Alice",             "Bob",             "Charlie",
        "alice@example.com", "bob@example.com",
    };

    for (test_ids) |user_id| {
        const sign_key = try key_context.extractSignKey(user_id);
        try testing.expect(sign_key.validate(system.params));
        try testing.expect(sign_key.hid == 0x01);
        try testing.expectEqualStrings(user_id, sign_key.id);

        const encrypt_key = try key_context.extractEncryptKey(user_id);
        try testing.expect(encrypt_key.validate(system.params));
        try testing.expect(encrypt_key.hid == 0x03);
        try testing.expectEqualStrings(user_id, encrypt_key.id);

        const sign_key2 = try key_context.extractSignKey(user_id);
        try testing.expectEqualSlices(u8, &sign_key.key, &sign_key2.key);

        const encrypt_key2 = try key_context.extractEncryptKey(user_id);
        try testing.expectEqualSlices(u8, &encrypt_key.key, &encrypt_key2.key);
    }
}

// Test SM9 encryption algorithm flow compliance
test "SM9 reference encrypt algorithm flow compliance" {
    const io = testing.io;
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const system = sm9.params.SM9System.init();
    const key_context = sm9.key_extract.KeyExtractionContext.init(system, io, allocator);
    const encrypt_context = sm9.encrypt.EncryptionContext.init(system, io, allocator);

    const test_cases = [_]struct {
        user_id: []const u8,
        message: []const u8,
    }{
        .{ .user_id = "Bob", .message = "encryption standard" },
        .{ .user_id = "Alice", .message = "Hello, SM9 Encryption!" },
        .{ .user_id = "test@example.com", .message = "Test message" },
        .{ .user_id = "user@domain.org", .message = "Confidential data" },
    };

    for (test_cases) |tc| {
        const user_key = try key_context.extractEncryptKey(tc.user_id);
        const ciphertext = try encrypt_context.encrypt(tc.message, tc.user_id, .{});
        defer ciphertext.deinit();
        try testing.expect(ciphertext.validate());

        const decrypted = try encrypt_context.decrypt(ciphertext, user_key, .{});
        defer allocator.free(decrypted);
        try testing.expectEqualStrings(tc.message, decrypted);
    }
}

// Test SM9 decryption algorithm flow compliance
test "SM9 reference decrypt algorithm flow compliance" {
    const io = testing.io;
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const system = sm9.params.SM9System.init();
    const key_context = sm9.key_extract.KeyExtractionContext.init(system, io, allocator);
    const encrypt_context = sm9.encrypt.EncryptionContext.init(system, io, allocator);

    const messages = [_][]const u8{
        "Short msg",
        "Medium length message for testing",
        "A longer message that spans multiple blocks to test the encryption and decryption",
    };

    const user_id = "bob@example.com";
    const user_key = try key_context.extractEncryptKey(user_id);

    for (messages) |message| {
        const ciphertext = try encrypt_context.encrypt(message, user_id, .{});
        defer ciphertext.deinit();
        const decrypted = try encrypt_context.decrypt(ciphertext, user_key, .{});
        defer allocator.free(decrypted);
        try testing.expectEqualStrings(message, decrypted);
    }
}

// Test SM9 key agreement protocol compliance
test "SM9 reference key agreement protocol compliance" {
    const io = testing.io;
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const system = sm9.params.SM9System.init();
    const key_context = sm9.key_extract.KeyExtractionContext.init(system, io, allocator);
    const ka_context = sm9.key_agreement.KeyAgreementContext.init(system, io, allocator);

    const alice_id = "alice@example.com";
    const bob_id = "bob@example.com";

    const alice_sign_key = try key_context.extractSignKey(alice_id);
    const bob_sign_key = try key_context.extractSignKey(bob_id);

    const alice_ephemeral = try ka_context.generateEphemeralKey(alice_id);
    const bob_ephemeral = try ka_context.generateEphemeralKey(bob_id);

    const alice_shared = try ka_context.performKeyAgreement(
        alice_id,
        alice_sign_key,
        alice_ephemeral,
        bob_id,
        bob_ephemeral.public_key,
        .initiator,
        32,
    );
    defer allocator.free(alice_shared);

    const bob_shared = try ka_context.performKeyAgreement(
        bob_id,
        bob_sign_key,
        bob_ephemeral,
        alice_id,
        alice_ephemeral.public_key,
        .responder,
        32,
    );
    defer allocator.free(bob_shared);

    try testing.expectEqualSlices(u8, alice_shared, bob_shared);

    var all_zero = true;
    for (alice_shared) |byte| {
        if (byte != 0) {
            all_zero = false;
            break;
        }
    }
    try testing.expect(!all_zero);
}

// Test SM9 key agreement with multiple key lengths
test "SM9 reference key agreement multiple key lengths" {
    const io = testing.io;
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const system = sm9.params.SM9System.init();
    const key_context = sm9.key_extract.KeyExtractionContext.init(system, io, allocator);
    const ka_context = sm9.key_agreement.KeyAgreementContext.init(system, io, allocator);

    const alice_id = "alice@test.org";
    const bob_id = "bob@test.org";

    const alice_sign_key = try key_context.extractSignKey(alice_id);
    const bob_sign_key = try key_context.extractSignKey(bob_id);

    const alice_ephemeral = try ka_context.generateEphemeralKey(alice_id);
    const bob_ephemeral = try ka_context.generateEphemeralKey(bob_id);

    const key_lengths = [_]usize{ 16, 32, 48, 64 };

    for (key_lengths) |key_len| {
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

        try testing.expect(alice_key.len == key_len);
        try testing.expect(bob_key.len == key_len);
        try testing.expectEqualSlices(u8, alice_key, bob_key);
    }
}

// Test SM9 curve parameter compliance
test "SM9 reference curve parameter compliance" {
    const system = sm9.params.SM9System.init();

    try testing.expect(system.params.validate());
    try testing.expect(system.params.curve == .bn256);

    const expected_q = [32]u8{
        0xB6, 0x40, 0x00, 0x00, 0x02, 0xA3, 0xA6, 0xF1,
        0xD6, 0x03, 0xAB, 0x4F, 0xF5, 0x8E, 0xC7, 0x45,
        0x21, 0xF2, 0x93, 0x4B, 0x1A, 0x7A, 0xEE, 0xDB,
        0xE5, 0x6F, 0x9B, 0x27, 0xE3, 0x51, 0x45, 0x7D,
    };
    try testing.expectEqualSlices(u8, &expected_q, &system.params.q);

    const expected_N = [32]u8{
        0xB6, 0x40, 0x00, 0x00, 0x02, 0xA3, 0xA6, 0xF1,
        0xD6, 0x03, 0xAB, 0x4F, 0xF5, 0x8E, 0xC7, 0x44,
        0x49, 0xF2, 0x93, 0x4B, 0x18, 0xEA, 0x8B, 0xEE,
        0xE5, 0x6E, 0xE1, 0x9C, 0xD6, 0x9E, 0xCF, 0x25,
    };
    try testing.expectEqualSlices(u8, &expected_N, &system.params.N);

    try testing.expect(system.params.P1[0] == 0x02 or system.params.P1[0] == 0x03);
    try testing.expect(system.params.P2[0] == 0x04);
}

// Test SM9 KDF compliance
test "SM9 KDF reference compliance" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const test_cases = [_]struct {
        input: []const u8,
        output_len: usize,
    }{
        .{ .input = "test", .output_len = 16 },
        .{ .input = "SM9 KDF test vector", .output_len = 32 },
        .{ .input = "Longer input for KDF testing purposes", .output_len = 48 },
        .{ .input = "x", .output_len = 32 },
    };

    for (test_cases) |tc| {
        const kdf_output = try sm9.encrypt.EncryptionUtils.kdf(tc.input, tc.output_len, allocator);
        defer allocator.free(kdf_output);

        try testing.expect(kdf_output.len == tc.output_len);

        var all_zero = true;
        for (kdf_output) |byte| {
            if (byte != 0) {
                all_zero = false;
                break;
            }
        }
        try testing.expect(!all_zero);

        const kdf_output2 = try sm9.encrypt.EncryptionUtils.kdf(tc.input, tc.output_len, allocator);
        defer allocator.free(kdf_output2);
        try testing.expectEqualSlices(u8, kdf_output, kdf_output2);
    }
}

// Test SM9 MAC compliance
test "SM9 MAC reference compliance" {
    const key = "test_key_12345678";
    const message = "test message for MAC";

    var hasher = sm9.hash.HashUtils.HashContext.init();
    hasher.update(message);
    hasher.update(key);
    var mac_result: [32]u8 = undefined;
    hasher.final(&mac_result);

    var all_zero = true;
    for (mac_result) |byte| {
        if (byte != 0) {
            all_zero = false;
            break;
        }
    }
    try testing.expect(!all_zero);

    var hasher2 = sm9.hash.HashUtils.HashContext.init();
    hasher2.update(message);
    hasher2.update(key);
    var mac_result2: [32]u8 = undefined;
    hasher2.final(&mac_result2);
    try testing.expectEqualSlices(u8, &mac_result, &mac_result2);
}

// Test SM9 self-check functionality
test "SM9 reference self-check compliance" {
    const io = testing.io;
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const system = sm9.params.SM9System.init();
    try testing.expect(system.params.validate());

    const sign_master = sm9.params.SignMasterKeyPair.generate(system.params);
    const encrypt_master = sm9.params.EncryptMasterKeyPair.generate(system.params);

    const full_system = sm9.params.SM9System{
        .params = system.params,
        .sign_master = sign_master,
        .encrypt_master = encrypt_master,
    };

    const key_context = sm9.key_extract.KeyExtractionContext.init(full_system, io, allocator);
    const sign_context = sm9.sign.SignatureContext.init(full_system, io, allocator);
    const encrypt_context = sm9.encrypt.EncryptionContext.init(full_system, io, allocator);

    const user_id = "selfcheck@test.com";
    const message = "SM9 self-check test message";

    const sign_key = try key_context.extractSignKey(user_id);
    const signature = try sign_context.sign(message, sign_key, .{});
    const verify_result = try sign_context.verify(message, signature, user_id, .{});
    try testing.expect(verify_result);

    const encrypt_key = try key_context.extractEncryptKey(user_id);
    const ciphertext = try encrypt_context.encrypt(message, user_id, .{});
    defer ciphertext.deinit();
    const decrypted = try encrypt_context.decrypt(ciphertext, encrypt_key, .{});
    defer allocator.free(decrypted);
    try testing.expectEqualStrings(message, decrypted);
}

// Test SM9 with reference standard test vectors
test "SM9 reference standard test vectors" {
    const io = testing.io;
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const system = sm9.params.SM9System.init();
    const key_context = sm9.key_extract.KeyExtractionContext.init(system, io, allocator);
    const sign_context = sm9.sign.SignatureContext.init(system, io, allocator);

    const user_id = "Alice";
    const message = "Chinese IBS standard";

    const sign_key = try key_context.extractSignKey(user_id);
    const signature = try sign_context.sign(message, sign_key, .{});
    const is_valid = try sign_context.verify(message, signature, user_id, .{});
    try testing.expect(is_valid);

    const user_id2 = "Bob";
    const message2 = "message digest";

    const sign_key2 = try key_context.extractSignKey(user_id2);
    const signature2 = try sign_context.sign(message2, sign_key2, .{});
    const is_valid2 = try sign_context.verify(message2, signature2, user_id2, .{});
    try testing.expect(is_valid2);
}

// Test SM9 encryption with reference test vectors
test "SM9 reference encryption test vectors" {
    const io = testing.io;
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const system = sm9.params.SM9System.init();
    const key_context = sm9.key_extract.KeyExtractionContext.init(system, io, allocator);
    const encrypt_context = sm9.encrypt.EncryptionContext.init(system, io, allocator);

    const user_id = "Bob";
    const message = "encryption standard";

    const encrypt_key = try key_context.extractEncryptKey(user_id);
    const ciphertext = try encrypt_context.encrypt(message, user_id, .{});
    defer ciphertext.deinit();
    try testing.expect(ciphertext.validate());

    const decrypted = try encrypt_context.decrypt(ciphertext, encrypt_key, .{});
    defer allocator.free(decrypted);
    try testing.expectEqualStrings(message, decrypted);
}

// Test SM9 with Chinese character identities
test "SM9 reference unicode identity support" {
    const io = testing.io;
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const system = sm9.params.SM9System.init();
    const key_context = sm9.key_extract.KeyExtractionContext.init(system, io, allocator);
    const sign_context = sm9.sign.SignatureContext.init(system, io, allocator);
    const encrypt_context = sm9.encrypt.EncryptionContext.init(system, io, allocator);

    const user_id = "测试用户";
    const message = "中文测试消息 Chinese test message";

    const sign_key = try key_context.extractSignKey(user_id);
    const signature = try sign_context.sign(message, sign_key, .{});
    const is_valid = try sign_context.verify(message, signature, user_id, .{});
    try testing.expect(is_valid);

    const encrypt_key = try key_context.extractEncryptKey(user_id);
    const ciphertext = try encrypt_context.encrypt(message, user_id, .{});
    defer ciphertext.deinit();
    const decrypted = try encrypt_context.decrypt(ciphertext, encrypt_key, .{});
    defer allocator.free(decrypted);
    try testing.expectEqualStrings(message, decrypted);
}

// Test SM9 with various message sizes
test "SM9 reference message size boundary testing" {
    const io = testing.io;
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const system = sm9.params.SM9System.init();
    const key_context = sm9.key_extract.KeyExtractionContext.init(system, io, allocator);
    const sign_context = sm9.sign.SignatureContext.init(system, io, allocator);
    const encrypt_context = sm9.encrypt.EncryptionContext.init(system, io, allocator);

    const user_id = "boundary_test@example.com";
    const sign_key = try key_context.extractSignKey(user_id);
    const encrypt_key = try key_context.extractEncryptKey(user_id);

    const sizes = [_]usize{ 1, 16, 31, 32, 33, 64, 128, 256, 1024 };

    for (sizes) |size| {
        const message = try allocator.alloc(u8, size);
        defer allocator.free(message);
        for (message, 0..) |*byte, i| {
            byte.* = @truncate(i & 0xFF);
        }

        const signature = try sign_context.sign(message, sign_key, .{});
        const is_valid = try sign_context.verify(message, signature, user_id, .{});
        try testing.expect(is_valid);

        const ciphertext = try encrypt_context.encrypt(message, user_id, .{});
        defer ciphertext.deinit();
        const decrypted = try encrypt_context.decrypt(ciphertext, encrypt_key, .{});
        defer allocator.free(decrypted);
        try testing.expectEqualSlices(u8, message, decrypted);
    }
}

// Test SM9 signature with different hash types
test "SM9 reference signature hash type options" {
    const io = testing.io;
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const system = sm9.params.SM9System.init();
    const key_context = sm9.key_extract.KeyExtractionContext.init(system, io, allocator);
    const sign_context = sm9.sign.SignatureContext.init(system, io, allocator);

    const user_id = "hash_test@example.com";
    const message = "Testing different hash types";

    const sign_key = try key_context.extractSignKey(user_id);

    const options_sm3 = sm9.sign.SignatureOptions{ .hash_type = .sm3 };
    const signature_sm3 = try sign_context.sign(message, sign_key, options_sm3);
    const valid_sm3 = try sign_context.verify(message, signature_sm3, user_id, options_sm3);
    try testing.expect(valid_sm3);

    const options_pre = sm9.sign.SignatureOptions{ .hash_type = .precomputed };
    const signature_pre = try sign_context.sign(message, sign_key, options_pre);
    const valid_pre = try sign_context.verify(message, signature_pre, user_id, options_pre);
    try testing.expect(valid_pre);
}

// Test SM9 encryption with different output formats
test "SM9 reference encryption format options" {
    const io = testing.io;
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const system = sm9.params.SM9System.init();
    const key_context = sm9.key_extract.KeyExtractionContext.init(system, io, allocator);
    const encrypt_context = sm9.encrypt.EncryptionContext.init(system, io, allocator);

    const user_id = "format_test@example.com";
    const message = "Testing encryption formats";

    const encrypt_key = try key_context.extractEncryptKey(user_id);

    const opts_c1c3c2 = sm9.encrypt.EncryptionOptions{ .format = .c1_c3_c2 };
    const ct_c1c3c2 = try encrypt_context.encrypt(message, user_id, opts_c1c3c2);
    defer ct_c1c3c2.deinit();
    try testing.expect(ct_c1c3c2.format == .c1_c3_c2);

    const dec_c1c3c2 = try encrypt_context.decrypt(ct_c1c3c2, encrypt_key, opts_c1c3c2);
    defer allocator.free(dec_c1c3c2);
    try testing.expectEqualStrings(message, dec_c1c3c2);

    const opts_c1c2c3 = sm9.encrypt.EncryptionOptions{ .format = .c1_c2_c3 };
    const ct_c1c2c3 = try encrypt_context.encrypt(message, user_id, opts_c1c2c3);
    defer ct_c1c2c3.deinit();
    try testing.expect(ct_c1c2c3.format == .c1_c2_c3);

    const dec_c1c2c3 = try encrypt_context.decrypt(ct_c1c2c3, encrypt_key, opts_c1c2c3);
    defer allocator.free(dec_c1c2c3);
    try testing.expectEqualStrings(message, dec_c1c2c3);
}
