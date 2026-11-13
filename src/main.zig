const std = @import("std");
const root = @import("./root.zig");
const builtin = @import("builtin");
const print = std.debug.print;
const sm3 = root.sm3;
const sm4 = root.sm4;
const sm2 = root.sm2;
const zuc = root.zuc;
const sm9 = root.sm9;

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const allocator = init.gpa;

    print("=== GM-Zig Cryptography Library Demo ===\n\n", .{});
    print("\n=== SM2 Digital Signature Demo ===\n", .{});
    try demonstrateSignature(io, allocator);

    print("\n=== SM2 Key Exchange Demo ===\n", .{});
    try demonstrateKeyExchange(io, allocator);

    print("\n=== SM2 Encryption Demo ===\n", .{});
    try demonstrateEncryption(io, allocator);

    print("\n=== SM2 Utilities Demo ===\n", .{});
    try demonstrateUtils(io, allocator);

    print("\n=== SM2 WasmRng Demo ===\n", .{});
    if (builtin.target.cpu.arch == .wasm32) {
        WasmRng();
    }

    print("\n=== SM9 Identity-Based Cryptography Demo ===\n", .{});
    try demonstrateSM9(io, allocator);
}

fn demonstrateSignature(io: std.Io, allocator: std.mem.Allocator) !void {
    // Generate key pair
    print("1. Generating SM2 key pair...\n", .{});
    const key_pair = sm2.kp.generateKeyPair(io);

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

    const signature = try sm2.signature.sign(io, message, key_pair.private_key, key_pair.public_key, options);
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

fn demonstrateKeyExchange(io: std.Io, allocator: std.mem.Allocator) !void {
    print("1. Setting up key exchange participants...\n", .{});

    // Alice's setup
    const alice_private = sm2.SM2.scalar.random(io, .big);
    const alice_public = try sm2.SM2.basePoint.mul(alice_private, .big);
    const alice_id = "alice@company.com";

    print("   Alice's private key: ", .{});
    printHex(&alice_private);

    // Bob's setup
    const bob_private = sm2.SM2.scalar.random(io, .big);
    const bob_public = try sm2.SM2.basePoint.mul(bob_private, .big);
    const bob_id = "bob@company.com";

    print("   Bob's private key: ", .{});
    printHex(&bob_private);

    // Initialize key exchange contexts
    var alice_ctx = sm2.key_exchange.KeyExchangeContext.init(io, .initiator, alice_private, alice_public, alice_id);
    var bob_ctx = sm2.key_exchange.KeyExchangeContext.init(io, .responder, bob_private, bob_public, bob_id);

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

fn demonstrateEncryption(io: std.Io, allocator: std.mem.Allocator) !void {
    print("1. Setting up encryption...\n", .{});

    // Generate key pair
    const private_key = sm2.SM2.scalar.random(io, .big);
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
        const ciphertext = try sm2.encryption.encrypt(io, allocator, message, public_key, format);
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

fn demonstrateUtils(io: std.Io, allocator: std.mem.Allocator) !void {
    _ = io;
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
    const pub_x = [_]u8{ 0x12, 0x34 } ++ @as([30]u8, @splat(0x00));
    const pub_y = [_]u8{ 0x56, 0x78 } ++ @as([30]u8, @splat(0x00));

    const user_hash = sm2.utils.computeUserHash(user_id, pub_x, pub_y);

    print("   User ID: {s}\n", .{user_id});
    print("   User hash: ", .{});
    printHex(&user_hash);

    print("3. Testing ASN.1 DER encoding...\n", .{});

    const r = [_]u8{ 0x01, 0x23, 0x45, 0x67 } ++ @as([28]u8, @splat(0x00));
    const s = [_]u8{ 0x89, 0xAB, 0xCD, 0xEF } ++ @as([28]u8, @splat(0x00));

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

fn demonstrateSM9(io: std.Io, allocator: std.mem.Allocator) !void {
    _ = io;
    const std_sm9 = sm9.standard;
    const bn = sm9.bn;

    print("=== SM9 (GM/T 0044-2016) Standard Demo ===\n", .{});

    const sign_master = std_sm9.signMaster(1);
    const encrypt_master = std_sm9.encryptMaster(2);
    print("SM9 master keys initialized\n", .{});

    const alice_id = "Alice@example.com";
    const bob_id = "Bob@example.com";
    const message = "Hello from the standard SM9 implementation!";
    const nonce: bn.Fp = 0x123456789abcdef;

    const alice_sign_key = try std_sm9.signUserKey(allocator, sign_master, alice_id);
    const bob_encrypt_key = try std_sm9.encryptUserKey(allocator, encrypt_master, bob_id);
    print("Extracted Alice signing key and Bob decryption key\n", .{});

    const signature = try std_sm9.sign(allocator, message, alice_sign_key, sign_master.public_key, nonce);
    const verified = try std_sm9.verify(allocator, message, signature, alice_id, sign_master.public_key);
    print("SM9 signature verified: {}\n", .{verified});

    const ciphertext = try std_sm9.encrypt(allocator, message, bob_id, encrypt_master.public_key, nonce);
    defer allocator.free(ciphertext.C2);
    const decrypted = try std_sm9.decrypt(allocator, ciphertext, bob_id, bob_encrypt_key);
    defer allocator.free(decrypted);
    print("SM9 encryption/decryption: {s}\n", .{decrypted});

    const r_a: bn.Fp = 0x1111111111111111;
    const r_b: bn.Fp = 0x2222222222222222;
    const sk_a = try std_sm9.encryptUserKey(allocator, encrypt_master, alice_id);
    const sk_b = try std_sm9.encryptUserKey(allocator, encrypt_master, bob_id);
    const ra = try std_sm9.keyExchangeBegin(allocator, encrypt_master.public_key, bob_id, r_a);
    const rb = try std_sm9.keyExchangeBegin(allocator, encrypt_master.public_key, alice_id, r_b);
    const ka = try std_sm9.keyExchangeShared(allocator, encrypt_master.public_key, sk_a, alice_id, bob_id, r_a, ra, rb, .initiator, 32);
    defer allocator.free(ka);
    const kb = try std_sm9.keyExchangeShared(allocator, encrypt_master.public_key, sk_b, bob_id, alice_id, r_b, rb, ra, .responder, 32);
    defer allocator.free(kb);
    print("SM9 key agreement matched: {}\n", .{std.mem.eql(u8, ka, kb)});
}
