const std = @import("std");
const kp = @import("../sm2/keypair.zig");
const KeyPair = kp.KeyPair;
const testing = std.testing;

test "SM2 key pair generation" {

    const key_pair = kp.generateKeyPair();

    // Verify public key is valid (not identity element)
    try key_pair.public_key.rejectIdentity();

    // Test serialization
    const uncompressed = key_pair.getPublicKeyUncompressed();
    try testing.expect(uncompressed[0] == 0x04); // Uncompressed marker

    const compressed = key_pair.getPublicKeyCompressed();
    try testing.expect(compressed[0] == 0x02 or compressed[0] == 0x03); // Compressed marker
}

