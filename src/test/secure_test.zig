const std = @import("std");
const testing = std.testing;

const secure = @import("../secure.zig");
const sm4 = @import("../sm4.zig");
const zuc = @import("../zuc.zig");
const kp = @import("../sm2/keypair.zig");
const key_exchange = @import("../sm2/key_exchange.zig");
const key_extract = @import("../sm9/key_extract.zig");
const key_agreement = @import("../sm9/key_agreement.zig");

const test_key = [_]u8{
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
};
const test_iv = [_]u8{
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
};

fn scalarOne() [32]u8 {
    var scalar: [32]u8 = @splat(0);
    scalar[31] = 1;
    return scalar;
}

test "secure.zero overwrites secret bytes" {
    var data = @as([64]u8, @splat(0xaa));
    secure.zero(&data);
    try testing.expect(std.mem.allEqual(u8, &data, 0));
}

test "SM2 KeyPair.zeroize clears the private key" {
    var pair = try kp.KeyPair.fromPrivateKey(scalarOne());
    try testing.expect(!std.mem.allEqual(u8, &pair.private_key, 0));

    pair.zeroize();
    try testing.expect(std.mem.allEqual(u8, &pair.private_key, 0));

    // The public key is not secret and must remain usable.
    try pair.public_key.rejectIdentity();
}

test "SM2 KeyExchangeContext.deinit clears private and ephemeral keys" {
    const private_key = scalarOne();
    const public_key = try kp.publicKeyFromPrivateKey(private_key);
    var context = key_exchange.KeyExchangeContext.init(
        testing.io,
        .initiator,
        private_key,
        public_key,
        "secure-test",
    );

    context.deinit();
    try testing.expect(std.mem.allEqual(u8, &context.private_key, 0));
    try testing.expect(std.mem.allEqual(u8, &context.ephemeral_private, 0));
}

test "SM4.zeroize clears the expanded round keys" {
    var ctx = sm4.SM4.init(&test_key);
    ctx.zeroize();
    try testing.expect(std.mem.allEqual(u32, &ctx.rk, 0));
}

test "ZUC.zeroize clears the LFSR and registers" {
    var ctx = zuc.ZUC.init(&test_key, &test_iv);
    ctx.zeroize();
    try testing.expect(std.mem.allEqual(u32, &ctx.lfsr, 0));
    try testing.expectEqual(@as(u32, 0), ctx.r1);
    try testing.expectEqual(@as(u32, 0), ctx.r2);
}

test "ZUC_AEAD.zeroize clears the stored key and IV" {
    var ctx = zuc.ZUC_AEAD.init(&test_key, &test_iv);
    ctx.zeroize();
    try testing.expect(std.mem.allEqual(u8, &ctx.key, 0));
    try testing.expect(std.mem.allEqual(u8, &ctx.iv, 0));
}

test "SM9 private key structures zeroize their key material" {
    var sign_key = key_extract.SignUserPrivateKey{
        .id = "secure-test",
        .key = @as([33]u8, @splat(0x11)),
        .hid = 0x01,
    };
    sign_key.zeroize();
    try testing.expect(std.mem.allEqual(u8, &sign_key.key, 0));

    var encrypt_key = key_extract.EncryptUserPrivateKey{
        .id = "secure-test",
        .key = @as([65]u8, @splat(0x22)),
        .hid = 0x03,
    };
    encrypt_key.zeroize();
    try testing.expect(std.mem.allEqual(u8, &encrypt_key.key, 0));
}

test "SM9 ephemeral key zeroize clears the private scalar" {
    var pair = key_agreement.EphemeralKeyPair{
        .private_key = @as([32]u8, @splat(0x33)),
        .public_key = @as([33]u8, @splat(0x44)),
    };
    pair.zeroize();
    try testing.expect(std.mem.allEqual(u8, &pair.private_key, 0));
}
