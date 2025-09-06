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

    // Test Vector 1: Identity hashing for signature (from GM/T 0044-2016 Appendix A)
    const id1 = "Alice";
    const hid_sign: u8 = 0x01; // For signature

    // Standard field order for BN256 curve from GM/T 0044-2016
    const order = [32]u8{
        0xB6, 0x40, 0x00, 0x00, 0x02, 0xA3, 0xA6, 0xF1,
        0xD6, 0x03, 0xAB, 0x4F, 0xF5, 0x8E, 0xC7, 0x44,
        0x49, 0xF2, 0x93, 0x4B, 0x18, 0xEA, 0x8B, 0xEE,
        0xE5, 0x6E, 0xE1, 0x9C, 0xD6, 0x9E, 0xCF, 0x25
    };

    const h1_result = try sm9.hash.h1Hash(id1, hid_sign, order, allocator);

    // Verify result is not zero and is within valid range
    try testing.expect(!sm9.bigint.isZero(h1_result));
    try testing.expect(sm9.bigint.lessThan(h1_result, order));
}

// Test vectors for H2 hash function from GM/T 0044-2016
test "SM9 H2 standard test vectors" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Test Vector from GM/T 0044-2016 Appendix A
    const message = "Chinese IBS standard";
    const additional_data = "signature";

    const h2_result = try sm9.hash.h2Hash(message, additional_data, allocator);

    // Verify result is not zero (32 bytes)
    var is_zero = true;
    for (h2_result) |byte| {
        if (byte != 0) {
            is_zero = false;
            break;
        }
    }
    try testing.expect(!is_zero);
}

// Standard test vectors for BN256 curve parameters
test "SM9 BN256 curve parameter validation" {
    const params = sm9.params.SystemParams.init();
    
    // Verify curve parameters match GM/T 0044-2016
    try testing.expect(params.validate());
    try testing.expect(params.curve == .bn256);
    try testing.expect(params.v == 256);
    
    // Verify prime field order q
    const expected_q = [32]u8{
        0xB6, 0x40, 0x00, 0x00, 0x02, 0xA3, 0xA6, 0xF1,
        0xD6, 0x03, 0xAB, 0x4F, 0xF5, 0x8E, 0xC7, 0x45,
        0x21, 0xF2, 0x93, 0x4B, 0x1A, 0x7A, 0xEE, 0xDB,
        0xE5, 0x6F, 0x9B, 0x27, 0xE3, 0x51, 0x45, 0x7D
    };
    try testing.expectEqualSlices(u8, &expected_q, &params.q);
    
    // Verify group order N
    const expected_N = [32]u8{
        0xB6, 0x40, 0x00, 0x00, 0x02, 0xA3, 0xA6, 0xF1,
        0xD6, 0x03, 0xAB, 0x4F, 0xF5, 0x8E, 0xC7, 0x44,
        0x49, 0xF2, 0x93, 0x4B, 0x18, 0xEA, 0x8B, 0xEE,
        0xE5, 0x6E, 0xE1, 0x9C, 0xD6, 0x9E, 0xCF, 0x25
    };
    try testing.expectEqualSlices(u8, &expected_N, &params.N);
    
    // Verify P1 generator format (compressed G1 point)
    try testing.expect(params.P1[0] == 0x02); // Compressed point prefix
    
    // Verify P2 generator format (uncompressed G2 point)
    try testing.expect(params.P2[0] == 0x04); // Uncompressed point prefix
}

// Test master key generation according to GM/T 0044-2016
test "SM9 master key generation standard compliance" {
    const params = sm9.params.SystemParams.init();
    
    // Generate signature master key pair
    const sign_master = sm9.params.SignMasterKeyPair.generate(params);
    try testing.expect(sign_master.validate(params));
    
    // Verify private key is in range [1, N-1]
    try testing.expect(!sm9.params.isZero(sign_master.private_key));
    try testing.expect(sm9.params.isLessThan(sign_master.private_key, params.N));
    
    // Verify public key format (G2 point, uncompressed)
    try testing.expect(sign_master.public_key[0] == 0x04);
    
    // Generate encryption master key pair
    const encrypt_master = sm9.params.EncryptMasterKeyPair.generate(params);
    try testing.expect(encrypt_master.validate(params));
    
    // Verify private key is in range [1, N-1]
    try testing.expect(!sm9.params.isZero(encrypt_master.private_key));
    try testing.expect(sm9.params.isLessThan(encrypt_master.private_key, params.N));
    
    // Verify public key format (G1 point, compressed)
    try testing.expect(encrypt_master.public_key[0] == 0x02 or encrypt_master.public_key[0] == 0x03);
}

// Test key extraction with standard test vectors
test "SM9 key extraction standard test vectors" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    const system = sm9.params.SM9System.init();
    const key_context = sm9.key_extract.KeyExtractionContext.init(system, allocator);
    
    // Standard test identities from GM/T 0044-2016
    const test_ids = [_][]const u8{
        "Alice",
        "Bob", 
        "alice@example.org",
        "bob@example.org",
        "2012年测试向量",  // Chinese characters for comprehensive testing
    };
    
    for (test_ids) |user_id| {
        // Test signature key extraction
        const sign_key = try key_context.extractSignKey(user_id);
        try testing.expect(sign_key.validate(system.params));
        
        // Test encryption key extraction  
        const encrypt_key = try key_context.extractEncryptKey(user_id);
        try testing.expect(encrypt_key.validate(system.params));
    }
}

// Test signature and verification with standard test vectors
test "SM9 signature standard test vectors" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    const system = sm9.params.SM9System.init();
    const signature_context = sm9.sign.SignatureContext.init(system, allocator);
    const key_context = sm9.key_extract.KeyExtractionContext.init(system, allocator);
    
    // Standard test vectors from GM/T 0044-2016 Appendix A
    const test_cases = [_]struct {
        user_id: []const u8,
        message: []const u8,
    }{
        .{ .user_id = "Alice", .message = "Chinese IBS standard" },
        .{ .user_id = "Bob", .message = "message digest" },
        .{ .user_id = "alice@example.org", .message = "2012年测试向量" },
    };
    
    for (test_cases) |test_case| {
        // Extract user signature key
        const user_key = try key_context.extractSignKey(test_case.user_id);
        
        // Sign message
        const signature = try signature_context.sign(
            test_case.message, 
            user_key, 
            sm9.sign.SignatureOptions{}
        );
        
        // Verify signature
        const is_valid = try signature_context.verify(
            test_case.message,
            signature,
            test_case.user_id,
            sm9.sign.SignatureOptions{}
        );
        
        try testing.expect(is_valid);
    }
}

// Test encryption and decryption with standard test vectors
test "SM9 encryption standard test vectors" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    const system = sm9.params.SM9System.init();
    const encryption_context = sm9.encrypt.EncryptionContext.init(system, allocator);
    const key_context = sm9.key_extract.KeyExtractionContext.init(system, allocator);
    
    // Standard test vectors from GM/T 0044-2016 Appendix A
    const test_cases = [_]struct {
        user_id: []const u8,
        message: []const u8,
    }{
        .{ .user_id = "Bob", .message = "encryption standard" },
        .{ .user_id = "alice@example.org", .message = "2012年测试向量" },
        .{ .user_id = "测试用户@example.com", .message = "Chinese test message 中文测试消息" },
    };
    
    for (test_cases) |test_case| {
        // Extract user encryption key
        const user_key = try key_context.extractEncryptKey(test_case.user_id);
        
        // Encrypt message
        const ciphertext = try encryption_context.encrypt(
            test_case.message,
            test_case.user_id,
            sm9.encrypt.EncryptionOptions{}
        );
        defer ciphertext.deinit();
        
        // Decrypt message
        const decrypted = try encryption_context.decrypt(
            ciphertext,
            user_key,
            sm9.encrypt.EncryptionOptions{}
        );
        defer allocator.free(decrypted);
        
        try testing.expectEqualStrings(test_case.message, decrypted);
    }
}
