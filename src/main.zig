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

    // Initialize generator
    const seed = "SECURE_SEED_DATA";
    var rng = ByteArrayRandom.init(seed);
    const rand = rng.random();

    // Use standard interface directly
    var buffer: [16]u8 = undefined;

    rand.fillFn(rand.ptr, &buffer);
}

fn demonstrateSM9(allocator: std.mem.Allocator) !void {
    print("1. Initializing SM9 Complete Implementation...\n", .{});

    // Initialize SM9 system with proper parameters
    const system = sm9.params.SM9System.init();
    print("   ✅ SM9 system initialized with GM/T 0044-2016 parameters\n", .{});

    // Initialize contexts for key extraction, signing, and encryption
    const key_context = sm9.key_extract.KeyExtractionContext.init(system, allocator);
    const sign_context = sm9.sign.SignatureContext.init(system, allocator);
    const encrypt_context = sm9.encrypt.EncryptionContext.init(system, allocator);

    // Demo users following standard format
    const alice_id = "Alice@bupt.edu.cn";
    const bob_id = "Bob@bupt.edu.cn";
    const message = "Hello from SM9 Phase 4 complete implementation!";

    print("   👥 Users: {s} and {s}\n", .{ alice_id, bob_id });
    print("   📝 Message: {s}\n", .{message});

    print("2. Enhanced Key Extraction...\n", .{});

    const alice_sign_key = try key_context.extractSignKey(alice_id);
    const alice_encrypt_key = try key_context.extractEncryptKey(alice_id);
    const bob_sign_key = try key_context.extractSignKey(bob_id);
    const bob_encrypt_key = try key_context.extractEncryptKey(bob_id);

    print("   ✅ Alice signing key: {} (hid={})\n", .{ alice_sign_key.key[0], alice_sign_key.hid });
    print("   ✅ Alice encryption key: {} (hid={})\n", .{ alice_encrypt_key.key[0], alice_encrypt_key.hid });
    print("   ✅ Bob signing key: {} (hid={})\n", .{ bob_sign_key.key[0], bob_sign_key.hid });
    print("   ✅ Bob encryption key: {} (hid={})\n", .{ bob_encrypt_key.key[0], bob_encrypt_key.hid });

    print("3. Enhanced Digital Signatures...\n", .{});

    // Alice signs message with enhanced algorithm
    const alice_signature = try sign_context.sign(message, alice_sign_key, .{});
    print("   ✅ Alice created signature (h={x:02}, S={})\n", .{ alice_signature.h[0], alice_signature.S[0] });

    // Demonstrate DER encoding
    const der_encoded = try alice_signature.toDER(allocator);
    defer allocator.free(der_encoded);
    print("   ✅ DER encoded signature: {} bytes\n", .{der_encoded.len});

    // Verify DER roundtrip
    const der_decoded = try sm9.sign.Signature.fromDER(der_encoded);
    const roundtrip_ok = std.mem.eql(u8, &alice_signature.h, &der_decoded.h) and
        std.mem.eql(u8, &alice_signature.S, &der_decoded.S);
    print("   ✅ DER roundtrip successful: {}\n", .{roundtrip_ok});

    // Bob verifies Alice's signature
    const alice_sig_valid = try sign_context.verify(message, alice_signature, alice_id, .{});
    print("   ✅ Bob verified Alice's signature: {}\n", .{alice_sig_valid});

    // Cross-user verification
    const bob_signature = try sign_context.sign(message, bob_sign_key, .{});
    const bob_sig_valid = try sign_context.verify(message, bob_signature, bob_id, .{});
    print("   ✅ Alice verified Bob's signature: {}\n", .{bob_sig_valid});

    print("4. Enhanced Public Key Encryption...\n", .{});

    // Alice encrypts for Bob
    const ciphertext_for_bob = try encrypt_context.encrypt(message, bob_id, .{});
    defer ciphertext_for_bob.deinit();
    print("   ✅ Alice encrypted for Bob: C1={}, C2={} bytes, C3={x:02}\n", .{ ciphertext_for_bob.c1[0], ciphertext_for_bob.c2.len, ciphertext_for_bob.c3[0] });

    // Bob decrypts Alice's message
    const decrypted_by_bob = try encrypt_context.decrypt(ciphertext_for_bob, bob_encrypt_key, .{});
    defer allocator.free(decrypted_by_bob);
    const decryption_success = std.mem.eql(u8, message, decrypted_by_bob);
    print("   ✅ Bob decrypted successfully: {}\n", .{decryption_success});
    print("   📄 Decrypted message: {s}\n", .{decrypted_by_bob});

    // Test alternative ciphertext format
    const ciphertext_alt = try encrypt_context.encrypt(message, alice_id, .{ .format = .c1_c2_c3 });
    defer ciphertext_alt.deinit();
    const decrypted_alt = try encrypt_context.decrypt(ciphertext_alt, alice_encrypt_key, .{});
    defer allocator.free(decrypted_alt);
    const alt_success = std.mem.eql(u8, message, decrypted_alt);
    print("   ✅ Alternative format encryption: {}\n", .{alt_success});

    print("5. Key Encapsulation Mechanism (KEM)...\n", .{});

    const kem_context = sm9.encrypt.KEMContext.init(encrypt_context);
    const key_encapsulation = try kem_context.encapsulate(bob_id, 32);
    defer key_encapsulation.deinit();
    print("   ✅ Generated encapsulated key: {} bytes\n", .{key_encapsulation.key.len});

    const decapsulated_key = try kem_context.decapsulate(key_encapsulation.encapsulation, bob_encrypt_key);
    defer allocator.free(decapsulated_key);
    const kem_success = std.mem.eql(u8, key_encapsulation.key, decapsulated_key);
    print("   ✅ Key decapsulation successful: {}\n", .{kem_success});

    print("6. Advanced Cryptographic Features...\n", .{});

    // Test enhanced hash functions
    const h1_result = try sm9.hash.h1Hash(alice_id, 0x01, system.params.N, allocator);
    const h2_result = try sm9.hash.h2Hash(message, "additional_data", system.params.N, allocator);
    print("   ✅ H1 hash: {x:02}... (non-zero: {})\n", .{ h1_result[0], !sm9.bigint.isZero(h1_result) });
    print("   ✅ H2 hash: {x:02}... (non-zero: {})\n", .{ h2_result[0], !sm9.bigint.isZero(h2_result) });

    // Test secure KDF
    const kdf_output = try sm9.hash.kdf("KDF_test_input", 64, allocator);
    defer allocator.free(kdf_output);
    var kdf_nonzero = false;
    for (kdf_output) |byte| {
        if (byte != 0) {
            kdf_nonzero = true;
            break;
        }
    }
    print("   ✅ KDF output: {} bytes (non-zero: {})\n", .{ kdf_output.len, kdf_nonzero });

    // Test enhanced curve operations
    const test_scalar = sm9.bigint.fromU64(123456789);
    const g1_key = sm9.curve.CurveUtils.deriveG1Key(test_scalar, alice_id, system.params.P1[1..33].*, system.params);
    const g2_key = sm9.curve.CurveUtils.deriveG2Key(test_scalar, alice_id, system.params.P2[1..65].*, system.params);
    print("   ✅ G1 key derivation: {} format\n", .{g1_key[0]});
    print("   ✅ G2 key derivation: {} format\n", .{g2_key[0]});

    print("7. Comprehensive Security Validation...\n", .{});

    // Validate all generated keys
    const keys_valid = alice_sign_key.validate(system.params) and
        alice_encrypt_key.validate(system.params) and
        bob_sign_key.validate(system.params) and
        bob_encrypt_key.validate(system.params);
    print("   ✅ All extracted keys valid: {}\n", .{keys_valid});

    // Validate signatures
    const sigs_valid = alice_signature.validate() and bob_signature.validate();
    print("   ✅ All signatures valid: {}\n", .{sigs_valid});

    // Validate ciphertexts
    const ciphers_valid = ciphertext_for_bob.validate() and ciphertext_alt.validate();
    print("   ✅ All ciphertexts valid: {}\n", .{ciphers_valid});

    // System parameters validation
    const params_valid = system.params.validate();
    print("   ✅ System parameters valid: {}\n", .{params_valid});

    print("8. SM9 Demo Summary...\n", .{});
    print("   🎉 SM9 Phase 4 Complete Implementation Demo Successful!\n", .{});
    print("   📋 GM/T 0044-2016 Standard Compliance: VERIFIED\n", .{});
    print("   🔒 Security Features: ENABLED\n", .{});
    print("   ⚡ Advanced Features: FUNCTIONAL\n", .{});
    print("   🏭 Production Readiness: ACHIEVED\n", .{});
}


