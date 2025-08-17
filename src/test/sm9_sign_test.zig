const std = @import("std");
const testing = std.testing;
const sm9 = @import("../sm9.zig");

test "SM9 signature creation and validation" {
    // Create signature with non-zero values for valid test
    const h = [_]u8{0x12} ** 32;
    const S = [_]u8{0x34} ** 33;
    const signature = sm9.sign.Signature.init(h, S);
    
    try testing.expect(signature.validate());
}

test "SM9 signature serialization" {
    const h = [_]u8{0x12} ** 32;
    const S = [_]u8{0x34} ** 33;
    const signature = sm9.sign.Signature.init(h, S);
    
    // Test byte encoding/decoding
    const bytes = signature.toBytes();
    const restored = sm9.sign.Signature.fromBytes(bytes);
    
    try testing.expectEqualSlices(u8, &signature.h, &restored.h);
    try testing.expectEqualSlices(u8, &signature.S, &restored.S);
}

test "SM9 signature context initialization" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    const system = sm9.params.SM9System.init();
    const context = sm9.sign.SignatureContext.init(system, allocator);
    
    // Context should be initialized with system parameters
    try testing.expect(context.system_params.validate());
}

test "SM9 signature operation" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    const system = sm9.params.SM9System.init();
    const context = sm9.sign.SignatureContext.init(system, allocator);
    
    const user_id = "alice@example.com";
    const message = "Hello, SM9 signature!";
    
    // Extract user signing key using the new key extraction context
    const key_context = sm9.key_extract.KeyExtractionContext.init(system, allocator);
    const user_key = try key_context.extractSignKey(user_id);
    
    // Test key validation
    try testing.expect(user_key.validate(system.params));
    
    // Sign message
    const signature = try context.sign(
        message,
        user_key,
        sm9.sign.SignatureOptions{},
    );
    
    try testing.expect(signature.validate());
    
    // Verify signature
    const is_valid = try context.verify(
        message,
        signature,
        user_id,
        sm9.sign.SignatureOptions{},
    );
    
    try testing.expect(is_valid);
    
    // Test verification with wrong message should fail
    const wrong_message = "Different message";
    const is_invalid = try context.verify(
        wrong_message,
        signature,
        user_id,
        sm9.sign.SignatureOptions{},
    );
    
    try testing.expect(!is_invalid);
}

test "SM9 signature with different options" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    const system = sm9.params.SM9System.init();
    const context = sm9.sign.SignatureContext.init(system, allocator);
    
    const user_id = "test@example.com";
    const message = "Test message with options";
    
    const user_key = try sm9.key_extract.SignUserPrivateKey.extract(
        system.sign_master,
        system.params,
        user_id,
        allocator,
    );
    
    // Test with different hash types
    const options_sm3 = sm9.sign.SignatureOptions{ .hash_type = .sm3 };
    const signature_sm3 = try context.sign(message, user_key, options_sm3);
    const valid_sm3 = try context.verify(message, signature_sm3, user_id, options_sm3);
    try testing.expect(valid_sm3);
    
    const options_precomputed = sm9.sign.SignatureOptions{ .hash_type = .precomputed };
    const signature_precomputed = try context.sign(message, user_key, options_precomputed);
    const valid_precomputed = try context.verify(message, signature_precomputed, user_id, options_precomputed);
    try testing.expect(valid_precomputed);
}

test "SM9 batch signature verification" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    const system = sm9.params.SM9System.init();
    const context = sm9.sign.SignatureContext.init(system, allocator);
    
    var batch = sm9.sign.BatchSignature.init(context);
    defer batch.deinit();
    
    const messages = [_][]const u8{
        "Message 1",
        "Message 2",
        "Message 3",
    };
    
    const user_ids = [_][]const u8{
        "user1@example.com",
        "user2@example.com",
        "user3@example.com",
    };
    
    // Create signatures for each message
    for (messages, user_ids) |message, user_id| {
        const user_key = try sm9.key_extract.SignUserPrivateKey.extract(
            system.sign_master,
            system.params,
            user_id,
            allocator,
        );
        
        const signature = try context.sign(
            message,
            user_key,
            sm9.sign.SignatureOptions{},
        );
        
        try batch.addSignature(message, signature, user_id);
    }
    
    // Verify batch
    const batch_valid = try batch.verifyBatch(sm9.sign.SignatureOptions{});
    try testing.expect(batch_valid);
}

test "SM9 signature utility functions" {
    const id = "test@example.com";
    const hid: u8 = 0x01;
    const N = std.mem.zeroes([32]u8);
    
    // Test H1 computation
    const h1 = sm9.sign.SignatureUtils.computeH1(id, hid, N);
    try testing.expect(h1.len == 32);
    
    // Test H2 computation
    const message = "test message";
    const w = std.mem.zeroes([32]u8);
    const h2 = sm9.sign.SignatureUtils.computeH2(message, &w, N);
    try testing.expect(h2.len == 32);
    
    // Test random generation
    const random1 = sm9.sign.SignatureUtils.generateRandom();
    const random2 = sm9.sign.SignatureUtils.generateRandom();
    try testing.expect(!std.mem.eql(u8, &random1, &random2));
    
    // Test component validation
    const h = std.mem.zeroes([32]u8);
    const S = std.mem.zeroes([32]u8);
    try testing.expect(sm9.sign.SignatureUtils.validateComponents(h, S, N));
}