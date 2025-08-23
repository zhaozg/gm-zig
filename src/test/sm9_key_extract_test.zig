const std = @import("std");
const testing = std.testing;
const sm9 = @import("../sm9.zig");

test "SM9 signature user key extraction" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const system = sm9.params.SM9System.init();
    const user_id = "alice@example.com";

    const user_key = try sm9.key_extract.SignUserPrivateKey.extract(
        system.sign_master,
        system.params,
        user_id,
        allocator,
    );

    // Test key validation
    try testing.expect(user_key.validate(system.params));
    try testing.expect(user_key.hid == 0x01);
    try testing.expectEqualStrings(user_id, user_key.id);
}

test "SM9 encryption user key extraction" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const system = sm9.params.SM9System.init();
    const user_id = "bob@example.com";

    const user_key = try sm9.key_extract.EncryptUserPrivateKey.extract(
        system.encrypt_master,
        system.params,
        user_id,
        allocator,
    );

    // Test key validation
    try testing.expect(user_key.validate(system.params));
    try testing.expect(user_key.hid == 0x03);
    try testing.expectEqualStrings(user_id, user_key.id);
}

test "SM9 user public key derivation for signature" {
    const system = sm9.params.SM9System.init();
    const user_id = "alice@example.com";

    const public_key = sm9.key_extract.UserPublicKey.deriveForSignature(
        user_id,
        system.params,
        system.sign_master,
    );

    try testing.expect(public_key.validate(system.params));
    try testing.expect(public_key.hid == 0x01);
    try testing.expectEqualStrings(user_id, public_key.id);
}

test "SM9 user public key derivation for encryption" {
    const system = sm9.params.SM9System.init();
    const user_id = "bob@example.com";

    const public_key = sm9.key_extract.UserPublicKey.deriveForEncryption(
        user_id,
        system.params,
        system.encrypt_master,
    );

    try testing.expect(public_key.validate(system.params));
    try testing.expect(public_key.hid == 0x03);
    try testing.expectEqualStrings(user_id, public_key.id);
}

test "SM9 key extraction context" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const system = sm9.params.SM9System.init();
    const context = sm9.key_extract.KeyExtractionContext.init(system, allocator);

    const user_id = "test@example.com";

    // Test sign key extraction
    const sign_key = try context.extractSignKey(user_id);
    try testing.expect(sign_key.validate(system.params));

    // Test encrypt key extraction
    const encrypt_key = try context.extractEncryptKey(user_id);
    try testing.expect(encrypt_key.validate(system.params));

    // Test public key derivation
    const sign_public = context.deriveSignPublicKey(user_id);
    try testing.expect(sign_public.validate(system.params));

    const encrypt_public = context.deriveEncryptPublicKey(user_id);
    try testing.expect(encrypt_public.validate(system.params));
}

test "SM9 user key serialization" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const system = sm9.params.SM9System.init();
    const user_id = "test@example.com";

    // Test signature key serialization
    const sign_key = try sm9.key_extract.SignUserPrivateKey.extract(
        system.sign_master,
        system.params,
        user_id,
        allocator,
    );

    const sign_bytes = try sign_key.toBytes(allocator);
    defer allocator.free(sign_bytes);

    const restored_sign_key = try sm9.key_extract.SignUserPrivateKey.fromBytes(sign_bytes, user_id);
    try testing.expectEqualStrings(sign_key.id, restored_sign_key.id);
    try testing.expect(sign_key.hid == restored_sign_key.hid);

    // Test encryption key serialization
    const encrypt_key = try sm9.key_extract.EncryptUserPrivateKey.extract(
        system.encrypt_master,
        system.params,
        user_id,
        allocator,
    );

    const encrypt_bytes = try encrypt_key.toBytes(allocator);
    defer allocator.free(encrypt_bytes);

    const restored_encrypt_key = try sm9.key_extract.EncryptUserPrivateKey.fromBytes(encrypt_bytes, user_id);
    try testing.expectEqualStrings(encrypt_key.id, restored_encrypt_key.id);
    try testing.expect(encrypt_key.hid == restored_encrypt_key.hid);
}
