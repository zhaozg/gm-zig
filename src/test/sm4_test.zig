const std = @import("std");
const sm4 = @import("../sm4.zig");
const SM4 = sm4.SM4;

// Test vectors (GB/T 32907-2016)
test "SM4 Known Answer Test" {
    const key = [16]u8{
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
    };
    const plaintext = [16]u8{
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
    };
    const expected_ciphertext = [16]u8{
        0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e,
        0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46,
    };

    const ctx = SM4.init(&key);

    // Test single block encryption
    var ciphertext: [16]u8 = undefined;
    ctx.encryptBlock(&plaintext, &ciphertext);
    try std.testing.expectEqualSlices(u8, &expected_ciphertext, &ciphertext);

    // Test single block decryption
    var decrypted: [16]u8 = undefined;
    ctx.decryptBlock(&ciphertext, &decrypted);
    try std.testing.expectEqualSlices(u8, &plaintext, &decrypted);
}
