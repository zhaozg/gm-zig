const std = @import("std");
const testing = std.testing;
const sm9 = @import("../sm9.zig");

test "GM/T 0044-2016 - Basic parameter validation" {
    const system = sm9.params.SM9System.init();
    
    // Verify system parameters are valid
    try testing.expect(system.params.validate());
    
    // Check that curve order N is not zero
    try testing.expect(!sm9.bigint.isZero(system.params.N));
    
    // Check that field prime q is not zero  
    try testing.expect(!sm9.bigint.isZero(system.params.q));
    
    // Verify generator points P1 and P2 are not zero
    var p1_all_zero = true;
    for (system.params.P1) |byte| {
        if (byte != 0) {
            p1_all_zero = false;
            break;
        }
    }
    try testing.expect(!p1_all_zero);
    
    var p2_all_zero = true;
    for (system.params.P2) |byte| {
        if (byte != 0) {
            p2_all_zero = false;
            break;
        }
    }
    try testing.expect(!p2_all_zero);
}

test "GM/T 0044-2016 - Hash function H1 compliance" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    const system = sm9.params.SM9System.init();
    
    // Test H1 with standard user ID format
    const user_id = "Alice@bupt.edu.cn";
    
    // Test H1 for signature (hid = 0x01)
    const h1_sign = try sm9.hash.h1Hash(user_id, 0x01, system.params.N, allocator);
    try testing.expect(!sm9.bigint.isZero(h1_sign));
    try testing.expect(sm9.bigint.lessThan(h1_sign, system.params.N));
    
    // Test H1 for encryption (hid = 0x03)  
    const h1_encrypt = try sm9.hash.h1Hash(user_id, 0x03, system.params.N, allocator);
    try testing.expect(!sm9.bigint.isZero(h1_encrypt));
    try testing.expect(sm9.bigint.lessThan(h1_encrypt, system.params.N));
    
    // Verify H1 produces different results for different HIDs
    try testing.expect(!sm9.bigint.equal(h1_sign, h1_encrypt));
    
    // Test determinism: same inputs produce same outputs
    const h1_sign_repeat = try sm9.hash.h1Hash(user_id, 0x01, system.params.N, allocator);
    try testing.expect(sm9.bigint.equal(h1_sign, h1_sign_repeat));
}

test "GM/T 0044-2016 - Hash function H2 compliance" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    const message = "Chinese IBE standard";
    const additional_data = "test_vector_data";
    
    // Test H2 hash function
    const h2_result = try sm9.hash.h2Hash(message, additional_data, allocator);
    try testing.expect(!sm9.bigint.isZero(h2_result));
    
    // Test with different messages
    const different_message = "Different test message";
    const h2_different = try sm9.hash.h2Hash(different_message, additional_data, allocator);
    try testing.expect(!sm9.bigint.equal(h2_result, h2_different));
    
    // Test determinism
    const h2_repeat = try sm9.hash.h2Hash(message, additional_data, allocator);
    try testing.expect(sm9.bigint.equal(h2_result, h2_repeat));
}

test "GM/T 0044-2016 - KDF compliance and security" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    const kdf_input = "SM9_KDF_test_vector";
    
    // Test various output lengths
    const lengths = [_]usize{ 16, 32, 64, 128, 256 };
    
    for (lengths) |len| {
        const kdf_output = try sm9.hash.kdf(kdf_input, len, allocator);
        defer allocator.free(kdf_output);
        
        try testing.expect(kdf_output.len == len);
        
        // Verify KDF output is not all zeros (security requirement)
        var all_zero = true;
        for (kdf_output) |byte| {
            if (byte != 0) {
                all_zero = false;
                break;
            }
        }
        try testing.expect(!all_zero);
    }
    
    // Test KDF determinism
    const kdf1 = try sm9.hash.kdf(kdf_input, 32, allocator);
    defer allocator.free(kdf1);
    const kdf2 = try sm9.hash.kdf(kdf_input, 32, allocator);
    defer allocator.free(kdf2);
    
    try testing.expectEqualSlices(u8, kdf1, kdf2);
}

test "GM/T 0044-2016 - Key extraction compliance" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    const system = sm9.params.SM9System.init();
    const key_context = sm9.key_extract.KeyExtractionContext.init(system, allocator);
    
    // Test with standard user ID formats from GM/T 0044-2016
    const test_users = [_][]const u8{
        "Alice@bupt.edu.cn",
        "Bob@bupt.edu.cn", 
        "charlie@example.com",
        "测试用户@测试.cn", // Unicode support
    };
    
    for (test_users) |user_id| {
        // Test signature key extraction
        const sign_key = try key_context.extractSignKey(user_id);
        try testing.expect(sign_key.validate(system.params));
        try testing.expect(sign_key.hid == 0x01);
        
        // Test encryption key extraction
        const encrypt_key = try key_context.extractEncryptKey(user_id);
        try testing.expect(encrypt_key.validate(system.params));
        try testing.expect(encrypt_key.hid == 0x03);
        
        // Verify keys are properly formatted
        try testing.expect(sign_key.key[0] == 0x02 or sign_key.key[0] == 0x03);
        try testing.expect(encrypt_key.key[0] == 0x04);
    }
}

test "GM/T 0044-2016 - Digital signature compliance" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    const system = sm9.params.SM9System.init();
    const key_context = sm9.key_extract.KeyExtractionContext.init(system, allocator);
    const sign_context = sm9.sign.SignatureContext.init(system, allocator);
    
    const user_id = "Alice@bupt.edu.cn";
    const message = "Chinese IBS standard";
    
    // Extract signing key
    const sign_key = try key_context.extractSignKey(user_id);
    
    // Test signature generation
    const signature = try sign_context.sign(message, sign_key, .{});
    try testing.expect(signature.validate());
    
    // Test signature verification
    const is_valid = try sign_context.verify(message, signature, user_id, .{});
    try testing.expect(is_valid);
    
    // Test signature format compliance
    try testing.expect(!sm9.bigint.isZero(signature.h));
    try testing.expect(signature.S[0] == 0x02 or signature.S[0] == 0x03);
    
    // Test signature rejection with wrong message
    const wrong_message = "Wrong message";
    const wrong_valid = try sign_context.verify(wrong_message, signature, user_id, .{});
    try testing.expect(!wrong_valid);
    
    // Test signature rejection with wrong user ID
    const wrong_user = "Bob@bupt.edu.cn";
    const wrong_user_valid = try sign_context.verify(message, signature, wrong_user, .{});
    try testing.expect(!wrong_user_valid);
}

test "GM/T 0044-2016 - Public key encryption compliance" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    const system = sm9.params.SM9System.init();
    const key_context = sm9.key_extract.KeyExtractionContext.init(system, allocator);
    const encrypt_context = sm9.encrypt.EncryptionContext.init(system, allocator);
    
    const user_id = "Bob@bupt.edu.cn";
    const message = "encryption standard";
    
    // Extract encryption key
    const encrypt_key = try key_context.extractEncryptKey(user_id);
    
    // Test encryption
    const ciphertext = try encrypt_context.encrypt(message, user_id, .{});
    defer ciphertext.deinit();
    try testing.expect(ciphertext.validate());
    
    // Test decryption
    const decrypted = try encrypt_context.decrypt(ciphertext, encrypt_key, .{});
    defer allocator.free(decrypted);
    
    // Verify decryption correctness
    try testing.expectEqualSlices(u8, message, decrypted);
    
    // Test ciphertext format compliance
    try testing.expect(ciphertext.c1[0] == 0x02 or ciphertext.c1[0] == 0x03);
    try testing.expect(ciphertext.c2.len == message.len);
    try testing.expect(!sm9.bigint.isZero(ciphertext.c3));
    
    // Test different ciphertext formats
    const ciphertext_alt = try encrypt_context.encrypt(message, user_id, .{ .format = .c1_c2_c3 });
    defer ciphertext_alt.deinit();
    try testing.expect(ciphertext_alt.validate());
    
    const decrypted_alt = try encrypt_context.decrypt(ciphertext_alt, encrypt_key, .{});
    defer allocator.free(decrypted_alt);
    try testing.expectEqualSlices(u8, message, decrypted_alt);
}

test "GM/T 0044-2016 - Cross-user interoperability" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    const system = sm9.params.SM9System.init();
    const key_context = sm9.key_extract.KeyExtractionContext.init(system, allocator);
    const sign_context = sm9.sign.SignatureContext.init(system, allocator);
    const encrypt_context = sm9.encrypt.EncryptionContext.init(system, allocator);
    
    // Test multiple users
    const alice_id = "Alice@bupt.edu.cn";
    const bob_id = "Bob@bupt.edu.cn";
    const charlie_id = "Charlie@bupt.edu.cn";
    
    const message = "Multi-user interoperability test";
    
    // Extract keys for all users
    const alice_sign_key = try key_context.extractSignKey(alice_id);
    const bob_encrypt_key = try key_context.extractEncryptKey(bob_id);
    const charlie_sign_key = try key_context.extractSignKey(charlie_id);
    
    // Alice signs for Bob and Charlie to verify
    const alice_signature = try sign_context.sign(message, alice_sign_key, .{});
    
    const bob_verifies_alice = try sign_context.verify(message, alice_signature, alice_id, .{});
    const charlie_verifies_alice = try sign_context.verify(message, alice_signature, alice_id, .{});
    
    try testing.expect(bob_verifies_alice);
    try testing.expect(charlie_verifies_alice);
    
    // Alice encrypts for Bob
    const alice_to_bob = try encrypt_context.encrypt(message, bob_id, .{});
    defer alice_to_bob.deinit();
    
    const bob_decrypts = try encrypt_context.decrypt(alice_to_bob, bob_encrypt_key, .{});
    defer allocator.free(bob_decrypts);
    
    try testing.expectEqualSlices(u8, message, bob_decrypts);
    
    // Charlie signs for Alice and Bob to verify
    const charlie_signature = try sign_context.sign(message, charlie_sign_key, .{});
    
    const alice_verifies_charlie = try sign_context.verify(message, charlie_signature, charlie_id, .{});
    const bob_verifies_charlie = try sign_context.verify(message, charlie_signature, charlie_id, .{});
    
    try testing.expect(alice_verifies_charlie);
    try testing.expect(bob_verifies_charlie);
}

test "GM/T 0044-2016 - Performance and security validation" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    const system = sm9.params.SM9System.init();
    const key_context = sm9.key_extract.KeyExtractionContext.init(system, allocator);
    const sign_context = sm9.sign.SignatureContext.init(system, allocator);
    
    const user_id = "performance_test@bupt.edu.cn";
    
    // Test batch key extraction (should be efficient)
    const batch_size = 10;
    var sign_keys: [batch_size]sm9.key_extract.SignUserPrivateKey = undefined;
    
    for (0..batch_size) |i| {
        const test_user = try std.fmt.allocPrint(allocator, "user{}@test.com", .{i});
        defer allocator.free(test_user);
        
        sign_keys[i] = try key_context.extractSignKey(test_user);
        try testing.expect(sign_keys[i].validate(system.params));
    }
    
    // Test batch signature generation and verification
    const sign_key = try key_context.extractSignKey(user_id);
    
    for (0..5) |i| {
        const test_message = try std.fmt.allocPrint(allocator, "Message {}", .{i});
        defer allocator.free(test_message);
        
        const signature = try sign_context.sign(test_message, sign_key, .{});
        const is_valid = try sign_context.verify(test_message, signature, user_id, .{});
        
        try testing.expect(signature.validate());
        try testing.expect(is_valid);
    }
    
    // Security validation: signatures should be different for different messages
    const sig1 = try sign_context.sign("message1", sign_key, .{});
    const sig2 = try sign_context.sign("message2", sign_key, .{});
    
    try testing.expect(!std.mem.eql(u8, &sig1.h, &sig2.h));
    try testing.expect(!std.mem.eql(u8, &sig1.S, &sig2.S));
}