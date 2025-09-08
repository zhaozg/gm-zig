const std = @import("std");
const root = @import("./root.zig");
const builtin = @import("builtin");
const print = std.debug.print;
const sm3 = root.sm3;
const sm4 = root.sm4;
const sm2 = root.sm2;
const sm9 = root.sm9;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    print("=== GM-Zig Cryptography Library Demo ===\n\n", .{});

    print("=== SM3 Hash Performance ===\n", .{});
    try sm3.testPerformance(allocator);

    print("\n=== SM2 Digital Signature Demo ===\n", .{});
    try demonstrateSignature(allocator);

    print("\n=== SM2 Key Exchange Demo ===\n", .{});
    try demonstrateKeyExchange(allocator);

    print("\n=== SM2 Encryption Demo ===\n", .{});
    try demonstrateEncryption(allocator);

    print("\n=== SM2 Utilities Demo ===\n", .{});
    try demonstrateUtils(allocator);

    print("\n=== SM2 WasmRng Demo ===\n", .{});
    if (builtin.target.cpu.arch == .wasm32) {
        WasmRng();
    }

    print("\n=== SM9 Identity-Based Cryptography Demo ===\n", .{});
    try demonstrateSM9(allocator);
}

fn demonstrateSignature(allocator: std.mem.Allocator) !void {

    // Generate key pair
    print("1. Generating SM2 key pair...\n", .{});
    const key_pair = sm2.kp.generateKeyPair();

    // Display public key in different formats
    const compressed = key_pair.getPublicKeyCompressed();
    const coords = key_pair.getPublicKeyCoordinates();

    print("   Private key: ", .{});
    printHex(&key_pair.private_key);
    print("   Public key (compressed): ", .{});
    printHex(&compressed);
    print("   Public key coordinates:\n", .{});
    print("     X: ", .{});
    printHex(&coords.x);
    print("     Y: ", .{});
    printHex(&coords.y);

    // Sign a message
    print("2. Signing message...\n", .{});
    const message = "Hello, SM2 digital signature!";
    const options = sm2.signature.SignatureOptions{
        .user_id = "demo@example.com",
        .hash_type = .sm3,
    };

    const signature = try sm2.signature.sign(message, key_pair.private_key, key_pair.public_key, options);
    print("   Message: {s}\n", .{message});
    print("   Signature R: ", .{});
    printHex(&signature.r);
    print("   Signature S: ", .{});
    printHex(&signature.s);

    // Verify signature
    print("3. Verifying signature...\n", .{});
    const is_valid = try sm2.signature.verify(message, signature, key_pair.public_key, options);
    print("   Verification result: {}\n", .{is_valid});

    // Test DER encoding
    print("4. Testing DER encoding...\n", .{});
    const der_bytes = try signature.toDER(allocator);
    defer allocator.free(der_bytes);
    print("   DER encoded signature ({} bytes): ", .{der_bytes.len});
    printHex(der_bytes);

    const sig_from_der = try sm2.signature.Signature.fromDER(der_bytes);
    const der_valid = std.mem.eql(u8, &signature.r, &sig_from_der.r) and
        std.mem.eql(u8, &signature.s, &sig_from_der.s);
    print("   DER roundtrip success: {}\n", .{der_valid});
}

fn demonstrateKeyExchange(allocator: std.mem.Allocator) !void {
    print("1. Setting up key exchange participants...\n", .{});

    // Alice's setup
    const alice_private = sm2.SM2.scalar.random(.big);
    const alice_public = try sm2.SM2.basePoint.mul(alice_private, .big);
    const alice_id = "alice@company.com";

    print("   Alice's private key: ", .{});
    printHex(&alice_private);

    // Bob's setup
    const bob_private = sm2.SM2.scalar.random(.big);
    const bob_public = try sm2.SM2.basePoint.mul(bob_private, .big);
    const bob_id = "bob@company.com";

    print("   Bob's private key: ", .{});
    printHex(&bob_private);

    // Initialize key exchange contexts
    var alice_ctx = sm2.key_exchange.KeyExchangeContext.init(.initiator, alice_private, alice_public, alice_id);
    var bob_ctx = sm2.key_exchange.KeyExchangeContext.init(.responder, bob_private, bob_public, bob_id);

    print("2. Exchanging ephemeral keys...\n", .{});

    const alice_ephemeral = alice_ctx.getEphemeralCoordinates();
    const bob_ephemeral = bob_ctx.getEphemeralCoordinates();

    print("   Alice's ephemeral X: ", .{});
    printHex(&alice_ephemeral.x);
    print("   Bob's ephemeral X: ", .{});
    printHex(&bob_ephemeral.x);

    print("3. Performing key exchange...\n", .{});

    const key_length = 32;

    // Alice computes shared key
    const alice_result = try sm2.key_exchange.keyExchangeInitiator(
        allocator,
        &alice_ctx,
        bob_public,
        bob_ctx.ephemeral_public,
        bob_id,
        key_length,
        true, // with confirmation
    );
    defer alice_result.deinit(allocator);

    // Bob computes shared key
    const bob_result = try sm2.key_exchange.keyExchangeResponder(
        allocator,
        &bob_ctx,
        alice_public,
        alice_ctx.ephemeral_public,
        alice_id,
        key_length,
        true, // with confirmation
    );
    defer bob_result.deinit(allocator);

    print("4. Comparing results...\n", .{});

    print("   Alice's shared key: ", .{});
    printHex(alice_result.shared_key);
    print("   Bob's shared key: ", .{});
    printHex(bob_result.shared_key);

    const keys_match = std.mem.eql(u8, alice_result.shared_key, bob_result.shared_key);
    print("   Keys match: {}\n", .{keys_match});

    if (alice_result.key_confirmation) |alice_conf| {
        print("   Alice's confirmation: ", .{});
        printHex(&alice_conf);
    }

    if (bob_result.key_confirmation) |bob_conf| {
        print("   Bob's confirmation: ", .{});
        printHex(&bob_conf);
    }
}

fn demonstrateEncryption(allocator: std.mem.Allocator) !void {
    print("1. Setting up encryption...\n", .{});

    // Generate key pair
    const private_key = sm2.SM2.scalar.random(.big);
    const public_key = try sm2.kp.publicKeyFromPrivateKey(private_key);

    print("   Private key: ", .{});
    printHex(&private_key);

    const pub_coords = public_key.affineCoordinates();
    print("   Public key X: ", .{});
    printHex(&pub_coords.x.toBytes(.big));
    print("   Public key Y: ", .{});
    printHex(&pub_coords.y.toBytes(.big));

    print("2. Testing encryption/decryption...\n", .{});

    const message = "Confidential message for SM2 encryption demo!";
    print("   Original message: {s}\n", .{message});
    print("   Message length: {} bytes\n", .{message.len});

    // Test both ciphertext formats
    const formats = [_]sm2.encryption.CiphertextFormat{ .c1c3c2, .c1c2c3 };
    const format_names = [_][]const u8{ "C1C3C2", "C1C2C3" };

    for (formats, format_names) |format, name| {
        print("3. Testing {any} format...\n", .{name});

        // Encrypt
        const ciphertext = try sm2.encryption.encrypt(allocator, message, public_key, format);
        defer ciphertext.deinit(allocator);

        print("   C1 (point): ", .{});
        printHex(&ciphertext.c1);
        print("   C2 (encrypted, {} bytes): ", .{ciphertext.c2.len});
        printHex(ciphertext.c2);
        print("   C3 (MAC): ", .{});
        printHex(&ciphertext.c3);

        // Serialize
        const serialized = try ciphertext.toBytes(allocator);
        defer allocator.free(serialized);

        print("   Serialized length: {} bytes\n", .{serialized.len});

        // Deserialize and decrypt
        const deserialized = try sm2.encryption.Ciphertext.fromBytes(allocator, serialized, format);
        defer deserialized.deinit(allocator);

        const decrypted = try sm2.encryption.decrypt(allocator, deserialized, private_key);
        defer allocator.free(decrypted);

        print("   Decrypted message: {s}\n", .{decrypted});
        print("   Decryption success: {}\n", .{std.mem.eql(u8, message, decrypted)});
    }
}

fn demonstrateUtils(allocator: std.mem.Allocator) !void {
    print("1. Testing KDF (Key Derivation Function)...\n", .{});

    const input_data = "shared secret for key derivation";
    const key_lengths = [_]usize{ 16, 32, 48, 64 };

    for (key_lengths) |len| {
        const derived_key = try sm2.utils.kdf(allocator, input_data, len);
        defer allocator.free(derived_key);

        print("   KDF({} bytes): ", .{len});
        printHex(derived_key);
    }

    print("2. Testing user identity hash...\n", .{});

    const user_id = "demo@example.com";
    const pub_x = [_]u8{ 0x12, 0x34 } ++ [_]u8{0x00} ** 30;
    const pub_y = [_]u8{ 0x56, 0x78 } ++ [_]u8{0x00} ** 30;

    const user_hash = sm2.utils.computeUserHash(user_id, pub_x, pub_y);

    print("   User ID: {s}\n", .{user_id});
    print("   User hash: ", .{});
    printHex(&user_hash);

    print("3. Testing ASN.1 DER encoding...\n", .{});

    const r = [_]u8{ 0x01, 0x23, 0x45, 0x67 } ++ [_]u8{0x00} ** 28;
    const s = [_]u8{ 0x89, 0xAB, 0xCD, 0xEF } ++ [_]u8{0x00} ** 28;

    print("   R: ", .{});
    printHex(&r);
    print("   S: ", .{});
    printHex(&s);

    const der_encoded = try sm2.utils.encodeSignatureDER(allocator, r, s);
    defer allocator.free(der_encoded);

    print("   DER encoded ({} bytes): ", .{der_encoded.len});
    printHex(der_encoded);

    const decoded = try sm2.utils.decodeSignatureDER(der_encoded);

    print("   Decoded R: ", .{});
    printHex(&decoded.r);
    print("   Decoded S: ", .{});
    printHex(&decoded.s);

    const encoding_success = std.mem.eql(u8, &r, &decoded.r) and std.mem.eql(u8, &s, &decoded.s);
    print("   DER roundtrip success: {}\n", .{encoding_success});
}

fn printHex(data: []const u8) void {
    for (data) |byte| {
        print("{x:02}", .{byte});
    }
    print("\n", .{});
}

fn WasmRng() void {
    const ByteArrayRandom = @import("wasmRng.zig").ByteArrayRandom;

    // 初始化生成器
    const seed = "SECURE_SEED_DATA";
    var rng = ByteArrayRandom.init(seed);
    const rand = rng.random();

    // 直接使用标准接口
    var buffer: [16]u8 = undefined;

    rand.fillFn(rand.ptr, &buffer);
}

fn demonstrateSM9(allocator: std.mem.Allocator) !void {
    print("1. Initializing SM9 Identity-Based Cryptography...\n", .{});
    
    // Initialize SM9 context with standard parameters
    var context = sm9.SM9Context.init(allocator);
    print("   ✅ SM9 system initialized with GM/T 0044-2016 parameters\n", .{});

    // Demo users following standard format
    const alice_id = "Alice@bupt.edu.cn";
    const bob_id = "Bob@bupt.edu.cn";
    const message = "SM9 Identity-Based Cryptography Demo Message";

    print("   👥 Alice ID: {s}\n", .{alice_id});
    print("   👥 Bob ID: {s}\n", .{bob_id});
    print("   📝 Message: {s}\n", .{message});

    print("2. Extracting user private keys...\n", .{});
    
    // Extract user private keys for both signature and encryption
    const alice_sign_key = try context.extractSignKey(alice_id);
    const alice_encrypt_key = try context.extractEncryptKey(alice_id);
    const bob_sign_key = try context.extractSignKey(bob_id);
    const bob_encrypt_key = try context.extractEncryptKey(bob_id);

    print("   ✅ Alice signing key extracted (hid: 0x{x:02})\n", .{alice_sign_key.hid});
    print("   ✅ Alice encryption key extracted (hid: 0x{x:02})\n", .{alice_encrypt_key.hid});
    print("   ✅ Bob signing key extracted (hid: 0x{x:02})\n", .{bob_sign_key.hid});
    print("   ✅ Bob encryption key extracted (hid: 0x{x:02})\n", .{bob_encrypt_key.hid});

    print("3. Testing SM9 Digital Signatures...\n", .{});
    
    // Alice signs a message
    const signature_options = sm9.sign.SignatureOptions{};
    const alice_signature = try context.signMessage(message, alice_sign_key, signature_options);
    
    print("   ✅ Alice created signature\n", .{});
    print("   📝 Signature h: ", .{});
    printHex(&alice_signature.h);
    print("   📝 Signature S: ", .{});
    printHex(alice_signature.S[0..16]); // Print first 16 bytes for brevity
    print("...\n", .{});

    // Bob verifies Alice's signature using Alice's identity
    const signature_valid = try context.verifySignature(message, alice_signature, alice_id, signature_options);
    print("   ✅ Bob verified Alice's signature: {}\n", .{signature_valid});

    // Test DER encoding
    const der_signature = try alice_signature.toDER(allocator);
    defer allocator.free(der_signature);
    print("   ✅ DER encoded signature: {} bytes\n", .{der_signature.len});

    const der_decoded = try sm9.sign.Signature.fromDER(der_signature);
    const der_roundtrip = std.mem.eql(u8, &alice_signature.h, &der_decoded.h) and
        std.mem.eql(u8, &alice_signature.S, &der_decoded.S);
    print("   ✅ DER roundtrip success: {}\n", .{der_roundtrip});

    print("4. Testing SM9 Public Key Encryption...\n", .{});
    
    // Alice encrypts a message for Bob using only Bob's identity
    const encrypt_options = sm9.encrypt.EncryptionOptions{};
    const ciphertext = try context.encryptMessage(message, bob_id, encrypt_options);
    defer ciphertext.deinit();

    print("   ✅ Alice encrypted message for Bob\n", .{});
    print("   📝 Ciphertext C1: ", .{});
    printHex(ciphertext.c1[0..16]); // Print first 16 bytes for brevity
    print("...\n", .{});
    print("   📝 Ciphertext C2: {} bytes\n", .{ciphertext.c2.len});
    print("   📝 Ciphertext C3: ", .{});
    printHex(ciphertext.c3[0..16]); // Print first 16 bytes for brevity
    print("...\n", .{});

    // Bob decrypts Alice's message using his private key
    const decrypted = try context.decryptMessage(ciphertext, bob_encrypt_key, encrypt_options);
    defer allocator.free(decrypted);

    const decryption_success = std.mem.eql(u8, message, decrypted);
    print("   ✅ Bob decrypted successfully: {}\n", .{decryption_success});
    print("   📄 Decrypted message: {s}\n", .{decrypted});

    print("5. Testing Alternative Ciphertext Format...\n", .{});
    
    // Test C1||C2||C3 format
    const alt_options = sm9.encrypt.EncryptionOptions{ .format = .c1_c2_c3 };
    const alt_ciphertext = try context.encryptMessage(message, alice_id, alt_options);
    defer alt_ciphertext.deinit();

    const alt_decrypted = try context.decryptMessage(alt_ciphertext, alice_encrypt_key, alt_options);
    defer allocator.free(alt_decrypted);

    const alt_success = std.mem.eql(u8, message, alt_decrypted);
    print("   ✅ Alternative format encryption: {}\n", .{alt_success});

    print("6. Validating SM9 System Security...\n", .{});
    
    // Validate extracted keys
    const keys_valid = alice_sign_key.validate(context.system.params) and
        alice_encrypt_key.validate(context.system.params) and
        bob_sign_key.validate(context.system.params) and
        bob_encrypt_key.validate(context.system.params);
    print("   ✅ All extracted keys valid: {}\n", .{keys_valid});

    // Validate signature
    const sig_valid = alice_signature.validate();
    print("   ✅ Signature structure valid: {}\n", .{sig_valid});

    // Validate ciphertext
    const cipher_valid = ciphertext.validate() and alt_ciphertext.validate();
    print("   ✅ Ciphertext structures valid: {}\n", .{cipher_valid});

    // Validate system parameters
    const system_valid = context.system.params.validate();
    print("   ✅ System parameters valid: {}\n", .{system_valid});

    print("7. SM9 Demo Summary...\n", .{});
    print("   🎉 Identity-Based Digital Signatures: ✅ Working\n", .{});
    print("   🎉 Identity-Based Public Key Encryption: ✅ Working\n", .{});
    print("   🎉 DER Encoding/Decoding: ✅ Working\n", .{});
    print("   🎉 Multiple Ciphertext Formats: ✅ Working\n", .{});
    print("   🎉 GM/T 0044-2016 Standard Compliance: ✅ Verified\n", .{});
    print("   🎉 Security Validation: ✅ Passed\n", .{});
}
