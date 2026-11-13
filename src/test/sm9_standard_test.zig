const std = @import("std");
const testing = std.testing;
const sm9 = @import("../sm9.zig");
const bn = sm9.bn;
const standard = @import("../sm9/standard.zig");

const r_nonce: bn.Fp = 0x123456789ABCDEF;

test "SM9 standard signature matches external reference vector" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const master = standard.signMaster(1);
    const user_key = try standard.signUserKey(allocator, master, "Alice");

    // d_A from gmalg (msk_s = 1, ID = "Alice", hid = 0x01)
    try testing.expectEqual(
        @as(bn.Fp, 5281124970184827857761543561107713554947239663857812632049811761887376134857),
        user_key.x,
    );
    try testing.expectEqual(
        @as(bn.Fp, 50446581981349233830476507340966129261966540333806232410509392100624451032708),
        user_key.y,
    );

    const sig = try standard.sign(allocator, "Chinese IBS standard", user_key, master.public_key, r_nonce);
    try testing.expectEqualSlices(
        u8,
        &[_]u8{
            0x14, 0x1f, 0xea, 0x06, 0x63, 0x6e, 0x3b, 0x57,
            0xa1, 0x50, 0xc9, 0xb1, 0x65, 0xd9, 0xf6, 0xc5,
            0x9a, 0x41, 0x9c, 0xd4, 0xc9, 0x84, 0x7e, 0x04,
            0x5e, 0x58, 0xc8, 0x72, 0x6c, 0x31, 0xdd, 0x6f,
        },
        &sig.h,
    );
    try testing.expectEqual(
        @as(bn.Fp, 36812131534756599695824852606961915146673560296697190542871001018848183541836),
        sig.S.x,
    );
    try testing.expectEqual(
        @as(bn.Fp, 15711748974257581206312019923332311469962828360296440307208774986305148004432),
        sig.S.y,
    );
    try testing.expect(try standard.verify(allocator, "Chinese IBS standard", sig, "Alice", master.public_key));
    try testing.expect(!try standard.verify(allocator, "wrong message", sig, "Alice", master.public_key));
}

test "SM9 standard encryption matches external reference vector" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const master = standard.encryptMaster(2);
    const user_key = try standard.encryptUserKey(allocator, master, "Bob");

    const ct = try standard.encrypt(allocator, "encryption standard", "Bob", master.public_key, r_nonce);
    defer allocator.free(ct.C2);

    try testing.expectEqual(
        @as(bn.Fp, 77476847869340676893655444856732531291107454174375372116907725761662265029922),
        ct.C1.x,
    );
    try testing.expectEqual(
        @as(bn.Fp, 8665180888814968582730944085875862475903320071744462134013789069617927986803),
        ct.C1.y,
    );
    try testing.expectEqualSlices(
        u8,
        &[_]u8{ 0x9e, 0x57, 0x4e, 0x07, 0x46, 0x60, 0x89, 0x3b, 0x59, 0x47, 0x0d, 0xcf, 0x2f, 0xc4, 0xa5, 0x1d, 0xd1, 0x3c, 0xad },
        ct.C2,
    );
    try testing.expectEqualSlices(
        u8,
        &[_]u8{
            0x69, 0x7a, 0x0e, 0x7d, 0x1c, 0x24, 0xca, 0x12,
            0x14, 0x1f, 0x64, 0xd8, 0x99, 0xe8, 0x8c, 0x16,
            0x2e, 0x0f, 0xc7, 0x10, 0x28, 0x46, 0x64, 0xc1,
            0x2a, 0xf2, 0x9b, 0x35, 0xb6, 0x03, 0x8d, 0xc5,
        },
        &ct.C3,
    );

    const plain = try standard.decrypt(allocator, ct, "Bob", user_key);
    defer allocator.free(plain);
    try testing.expectEqualStrings("encryption standard", plain);
}

test "SM9 standard key agreement derives the same key" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const master = standard.encryptMaster(2);
    const sk_a = try standard.encryptUserKey(allocator, master, "Alice");
    const sk_b = try standard.encryptUserKey(allocator, master, "Bob");

    const r_a: bn.Fp = 0x1111111111111111;
    const r_b: bn.Fp = 0x2222222222222222;
    const ra = try standard.keyExchangeBegin(allocator, master.public_key, "Bob", r_a);
    const rb = try standard.keyExchangeBegin(allocator, master.public_key, "Alice", r_b);

    const ka = try standard.keyExchangeShared(allocator, master.public_key, sk_a, "Alice", "Bob", r_a, ra, rb, .initiator, 32);
    defer allocator.free(ka);
    const kb = try standard.keyExchangeShared(allocator, master.public_key, sk_b, "Bob", "Alice", r_b, rb, ra, .responder, 32);
    defer allocator.free(kb);
    try testing.expectEqualSlices(u8, ka, kb);
}
