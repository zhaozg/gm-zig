const std = @import("std");
const testing = std.testing;
const sm9 = @import("../sm9.zig");

test "SM9 ciphertext creation and validation" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Create valid test data for ciphertext validation
    var c1 = [_]u8{0x02} ++ [_]u8{0x01} ** 32; // Valid compressed G1 point format
    const c2 = "test message";
    var c3 = [_]u8{0x33} ** 32; // Non-zero MAC value

    const ciphertext = try sm9.encrypt.Ciphertext.init(
        allocator,
        c1,
        c2,
        c3,
        .c1_c3_c2,
    );
    defer ciphertext.deinit();

    try testing.expect(ciphertext.validate());
    try testing.expect(ciphertext.format == .c1_c3_c2);
    try testing.expectEqualStrings(c2, ciphertext.c2);
}

test "SM9 ciphertext serialization" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const c1 = [_]u8{0x11} ** 33;
    const c2 = "Hello, SM9!";
    const c3 = [_]u8{0x33} ** 32;

    const ciphertext = try sm9.encrypt.Ciphertext.init(
        allocator,
        c1,
        c2,
        c3,
        .c1_c3_c2,
    );
    defer ciphertext.deinit();

    // Test serialization
    const bytes = try ciphertext.toBytes(allocator);
    defer allocator.free(bytes);

    // Test deserialization
    const restored = try sm9.encrypt.Ciphertext.fromBytes(
        bytes,
        c2.len,
        .c1_c3_c2,
        allocator,
    );
    defer restored.deinit();

    try testing.expectEqualSlices(u8, &ciphertext.c1, &restored.c1);
    try testing.expectEqualSlices(u8, ciphertext.c2, restored.c2);
    try testing.expectEqualSlices(u8, &ciphertext.c3, &restored.c3);
}

test "SM9 encryption context initialization" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const system = sm9.params.SM9System.init();
    const context = sm9.encrypt.EncryptionContext.init(system, allocator);

    try testing.expect(context.system_params.validate());
}

test "SM9 encryption and decryption" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const system = sm9.params.SM9System.init();
    const context = sm9.encrypt.EncryptionContext.init(system, allocator);

    const user_id = "bob@example.com";
    const message = "Confidential message for SM9 encryption!";

    // Extract user encryption key
    const user_key = try sm9.key_extract.EncryptUserPrivateKey.extract(
        system.encrypt_master,
        system.params,
        user_id,
        allocator,
    );

    // Encrypt message
    const ciphertext = try context.encrypt(
        message,
        user_id,
        sm9.encrypt.EncryptionOptions{},
    );
    defer ciphertext.deinit();

    try testing.expect(ciphertext.validate());

    // Decrypt message
    const decrypted = try context.decrypt(
        ciphertext,
        user_key,
        sm9.encrypt.EncryptionOptions{},
    );
    defer allocator.free(decrypted);

    try testing.expectEqualStrings(message, decrypted);
}

test "SM9 encryption with different formats" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const system = sm9.params.SM9System.init();
    const context = sm9.encrypt.EncryptionContext.init(system, allocator);

    const user_id = "test@example.com";
    const message = "Test message with different formats";

    const user_key = try sm9.key_extract.EncryptUserPrivateKey.extract(
        system.encrypt_master,
        system.params,
        user_id,
        allocator,
    );

    // Test C1||C3||C2 format
    const options_c1c3c2 = sm9.encrypt.EncryptionOptions{ .format = .c1_c3_c2 };
    const ciphertext_c1c3c2 = try context.encrypt(message, user_id, options_c1c3c2);
    defer ciphertext_c1c3c2.deinit();

    const decrypted_c1c3c2 = try context.decrypt(ciphertext_c1c3c2, user_key, options_c1c3c2);
    defer allocator.free(decrypted_c1c3c2);
    try testing.expectEqualStrings(message, decrypted_c1c3c2);

    // Test C1||C2||C3 format
    const options_c1c2c3 = sm9.encrypt.EncryptionOptions{ .format = .c1_c2_c3 };
    const ciphertext_c1c2c3 = try context.encrypt(message, user_id, options_c1c2c3);
    defer ciphertext_c1c2c3.deinit();

    const decrypted_c1c2c3 = try context.decrypt(ciphertext_c1c2c3, user_key, options_c1c2c3);
    defer allocator.free(decrypted_c1c2c3);
    try testing.expectEqualStrings(message, decrypted_c1c2c3);
}

test "SM9 key encapsulation mechanism" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const system = sm9.params.SM9System.init();
    const encryption_context = sm9.encrypt.EncryptionContext.init(system, allocator);
    const kem_context = sm9.encrypt.KEMContext.init(encryption_context);

    const user_id = "test@example.com";
    const key_length = 32;

    const user_key = try sm9.key_extract.EncryptUserPrivateKey.extract(
        system.encrypt_master,
        system.params,
        user_id,
        allocator,
    );

    // Encapsulate key
    const encapsulation = try kem_context.encapsulate(user_id, key_length);
    defer encapsulation.deinit();

    try testing.expect(encapsulation.key.len == key_length);

    // Decapsulate key
    const decapsulated_key = try kem_context.decapsulate(
        encapsulation.encapsulation,
        user_key,
    );
    defer allocator.free(decapsulated_key);

    try testing.expect(decapsulated_key.len == key_length);
}

test "SM9 encryption utility functions" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    // Initialize system parameters for tests
    const system_params = sm9.params.SystemParams.init();

    // Test KDF
    const input = "test input for KDF";
    const output_len = 64;
    const kdf_output = try sm9.encrypt.EncryptionUtils.kdf(input, output_len, allocator);
    defer allocator.free(kdf_output);

    try testing.expect(kdf_output.len == output_len);

    // Test H2 computation
    const c1 = std.mem.zeroes([32]u8);
    const message = "test message";
    const user_id = "test@example.com";
    const h2 = sm9.encrypt.EncryptionUtils.computeH2(&c1, message, user_id);
    try testing.expect(h2.len == 32);

    // Test point validation
    var g1_point = [_]u8{0x02} ++ [_]u8{0} ** 32; // Proper compressed G1 point format
    g1_point[1] = 1; // Make x-coordinate non-zero
    
    var g2_point = [_]u8{0x04} ++ [_]u8{0} ** 64; // Proper uncompressed G2 point format  
    g2_point[1] = 1; // Make x-coordinate non-zero

    try testing.expect(sm9.encrypt.EncryptionUtils.validateG1Point(g1_point, system_params));
    try testing.expect(sm9.encrypt.EncryptionUtils.validateG2Point(g2_point, system_params));
}

test "SM9 encryption with large messages" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const system = sm9.params.SM9System.init();
    const context = sm9.encrypt.EncryptionContext.init(system, allocator);

    const user_id = "test@example.com";

    // Create large message
    const large_message = try allocator.alloc(u8, 4096);
    defer allocator.free(large_message);
    for (large_message, 0..) |*byte, i| {
        byte.* = @truncate(i);
    }

    const user_key = try sm9.key_extract.EncryptUserPrivateKey.extract(
        system.encrypt_master,
        system.params,
        user_id,
        allocator,
    );

    // Encrypt large message
    const ciphertext = try context.encrypt(
        large_message,
        user_id,
        sm9.encrypt.EncryptionOptions{},
    );
    defer ciphertext.deinit();

    // Decrypt large message
    const decrypted = try context.decrypt(
        ciphertext,
        user_key,
        sm9.encrypt.EncryptionOptions{},
    );
    defer allocator.free(decrypted);

    try testing.expectEqualSlices(u8, large_message, decrypted);
}
