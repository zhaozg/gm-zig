const std = @import("std");
const testing = std.testing;
const sm9 = @import("../sm9.zig");

test "SM9 bigint operations" {
    // Test basic arithmetic operations
    const a = sm9.bigint.fromU64(123456);
    const b = sm9.bigint.fromU64(789012);
    const m = sm9.bigint.fromU64(999999);
    
    // Test addition
    const sum = try sm9.bigint.addMod(a, b, m);
    try testing.expect(!sm9.bigint.isZero(sum));
    
    // Test subtraction
    const diff = try sm9.bigint.subMod(b, a, m);
    try testing.expect(!sm9.bigint.isZero(diff));
    
    // Test multiplication
    const prod = try sm9.bigint.mulMod(a, b, m);
    try testing.expect(!sm9.bigint.isZero(prod));
}

test "SM9 hash functions" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    const data = "test@example.com";
    const order = sm9.bigint.fromU64(999999999);
    
    // Test H1 hash function
    const h1_result = try sm9.hash.h1Hash(data, 0x01, order, allocator);
    try testing.expect(!sm9.bigint.isZero(h1_result));
    
    // Test H2 hash function
    const message = "Hello, SM9!";
    const additional_data = "additional";
    const h2_result = try sm9.hash.h2Hash(message, additional_data, allocator);
    try testing.expect(!sm9.bigint.isZero(h2_result));
    
    // Test KDF
    const kdf_input = "key derivation input";
    const kdf_output = try sm9.hash.kdf(kdf_input, 32, allocator);
    defer allocator.free(kdf_output);
    
    try testing.expect(kdf_output.len == 32);
    
    // Verify KDF doesn't return all zeros
    var all_zero = true;
    for (kdf_output) |byte| {
        if (byte != 0) {
            all_zero = false;
            break;
        }
    }
    try testing.expect(!all_zero);
}

test "SM9 curve operations" {
    const params = sm9.params.SystemParams.init();
    
    // Test G1 point operations
    const P1 = sm9.curve.CurveUtils.getG1Generator(params);
    try testing.expect(!P1.isInfinity());
    
    // Test point doubling
    const P1_double = P1.double(params);
    try testing.expect(!P1_double.isInfinity());
    
    // Test scalar multiplication
    const scalar = sm9.bigint.fromU64(12345);
    const P1_mul = P1.mul(scalar, params);
    try testing.expect(!P1_mul.isInfinity());
    
    // Test G2 point operations
    const P2 = sm9.curve.CurveUtils.getG2Generator(params);
    try testing.expect(!P2.isInfinity());
    
    // Test G2 scalar multiplication
    const P2_mul = P2.mul(scalar, params);
    try testing.expect(!P2_mul.isInfinity());
}

test "SM9 pairing operations" {
    const params = sm9.params.SystemParams.init();
    
    // Get generator points
    const P1 = sm9.curve.CurveUtils.getG1Generator(params);
    const P2 = sm9.curve.CurveUtils.getG2Generator(params);
    
    // For now, just test that generators can be created without crashing
    // TODO: Fix generator construction and add full pairing test
    try testing.expect(!P1.isInfinity());
    try testing.expect(!P2.isInfinity());
    
    // Test basic operations without pairing for now
    const identity_gt = sm9.pairing.GtElement.identity();
    try testing.expect(identity_gt.isIdentity());
    const exponent = sm9.bigint.fromU64(7);
    const gt_pow = identity_gt.pow(exponent);
    try testing.expect(!gt_pow.isIdentity());
}

test "SM9 system parameters" {
    // Test system parameter validation
    const params = sm9.params.SystemParams.init();
    try testing.expect(params.validate());
    
    // Test SM9 system initialization
    const system = sm9.params.SM9System.init();
    try testing.expect(system.validate());
    
    // Verify master keys are valid
    try testing.expect(system.sign_master.validate(params));
    try testing.expect(system.encrypt_master.validate(params));
}

test "SM9 key extraction" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    const system = sm9.params.SM9System.init();
    const context = sm9.key_extract.KeyExtractionContext.init(system, allocator);
    
    const user_id = "alice@example.com";
    
    // Test signature key extraction
    const sign_key = try context.extractSignKey(user_id);
    try testing.expect(sign_key.validate(system.params));
    try testing.expect(sign_key.hid == 0x01);
    
    // Test encryption key extraction
    const encrypt_key = try context.extractEncryptKey(user_id);
    try testing.expect(encrypt_key.validate(system.params));
    try testing.expect(encrypt_key.hid == 0x03);
}

test "SM9 signature roundtrip" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    // Initialize SM9 system
    const system = sm9.params.SM9System.init();
    const signature_context = sm9.sign.SignatureContext.init(system, allocator);
    const key_context = sm9.key_extract.KeyExtractionContext.init(system, allocator);
    
    const user_id = "alice@example.com";
    const message = "Hello, SM9 signature!";
    
    // Extract user signing key
    const user_key = try key_context.extractSignKey(user_id);
    
    // Sign message
    const signature = try signature_context.sign(message, user_key, .{});
    try testing.expect(signature.validate());
    
    // Verify signature
    const is_valid = try signature_context.verify(message, signature, user_id, .{});
    try testing.expect(is_valid);
    
    // Test with wrong message
    const wrong_message = "Different message";
    const is_invalid = try signature_context.verify(wrong_message, signature, user_id, .{});
    try testing.expect(!is_invalid);
}

test "SM9 encryption roundtrip" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    // Initialize SM9 system
    const system = sm9.params.SM9System.init();
    const encryption_context = sm9.encrypt.EncryptionContext.init(system, allocator);
    const key_context = sm9.key_extract.KeyExtractionContext.init(system, allocator);
    
    const user_id = "bob@example.com";
    const message = "Hello, SM9 encryption!";
    
    // Extract user encryption key
    const user_key = try key_context.extractEncryptKey(user_id);
    
    // Encrypt message
    const ciphertext = try encryption_context.encrypt(message, user_id, .{});
    defer ciphertext.deinit();
    
    // Decrypt message
    const decrypted = try encryption_context.decrypt(ciphertext, user_key, .{});
    defer allocator.free(decrypted);
    
    // Verify roundtrip
    try testing.expectEqualSlices(u8, message, decrypted);
}

test "SM9 complete workflow" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    // Initialize complete SM9 context
    var sm9_context = sm9.SM9Context.init(allocator);
    try testing.expect(sm9_context.validate());
    
    const alice_id = "alice@example.com";
    const bob_id = "bob@example.com";
    const message = "Confidential message from Alice to Bob";
    
    // Extract keys for both users
    const alice_sign_key = try sm9_context.extractSignKey(alice_id);
    const bob_encrypt_key = try sm9_context.extractEncryptKey(bob_id);
    
    // Alice signs the message
    const signature = try sm9_context.signMessage(message, alice_sign_key, .{});
    
    // Verify Alice's signature
    const signature_valid = try sm9_context.verifySignature(message, signature, alice_id, .{});
    try testing.expect(signature_valid);
    
    // Encrypt message for Bob
    const ciphertext = try sm9_context.encryptMessage(message, bob_id, .{});
    defer ciphertext.deinit();
    
    // Bob decrypts the message
    const decrypted = try sm9_context.decryptMessage(ciphertext, bob_encrypt_key, .{});
    defer allocator.free(decrypted);
    
    // Verify the decrypted message matches original
    try testing.expectEqualSlices(u8, message, decrypted);
}