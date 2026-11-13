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

fn hex32(s: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

test "SM9 standard signature boundary vectors" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const Case = struct {
        id: []const u8,
        message: []const u8,
        nonce: bn.Fp,
        h: [32]u8,
        sx: bn.Fp,
        sy: bn.Fp,
    };

    var long_msg: [257]u8 = undefined;
    for (&long_msg, 0..) |*b, i| b.* = @intCast(i % 256);
    const long_id: [100]u8 = @splat('x');
    const msg64: [64]u8 = @splat(0x42);

    const cases = [_]Case{
        .{
            .id = "a",
            .message = "",
            .nonce = 1,
            .h = hex32("b13b1dd2dfbaa2ab0b36588f73914969d3d4418803b3c6c0afc6ad2f4b361a9a"),
            .sx = 0x804e53865ac0f689935bafb0fbea4f0c825c6a4b9949209efabc1cee4359bd27,
            .sy = 0x6330d7636d8efb85e9a68f6ad0e3291da34cf04696b6192d441d018aa8f13255,
        },
        .{
            .id = "用户@example.com",
            .message = &[_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31 },
            .nonce = bn.N - 1,
            .h = hex32("a57a8e84f40dd833606ab9abeda2721788b6b95df650c4a29c82995bb851a732"),
            .sx = 0x6b3723b87115041fc8d9db474d203996da189928b7ac32738e27a215900ef18a,
            .sy = 0x32f1667b19bc119267c6a9475553f53c965fd425ed9bcd2c7123e63be688876,
        },
        .{
            .id = &long_id,
            .message = &long_msg,
            .nonce = 0xdeadbeefcafebabe,
            .h = hex32("45ca0a092c56e5d0018efd40502d76178b053b2e5579fed09784a0f9462575ba"),
            .sx = 0x8b00e89dd92139ca81278b3966d1d585f4c0fb2e998f7ebfe5b2c730edf24857,
            .sy = 0x8928f7e2d11227dd1d4a4f9836d4a51f679f985fd5f7f897b459c21a813617fb,
        },
        .{
            .id = "Alice",
            .message = &msg64,
            .nonce = 0x123456789abcdef,
            .h = hex32("3df602ae8fcb9c9de4fbb234d017cb6132a9aa1bdc83fd808c316590d25ecdcc"),
            .sx = 0x124da721e0cde4d41751ba919f96fb93533d9a5a2fc03857ffd8b407712e63f7,
            .sy = 0x34ce265ae34f054b8e26dd15be8afc0dea4a4cfc7af45fa11a052190a8038010,
        },
    };

    const master = standard.signMaster(1);
    for (cases) |c| {
        const key = try standard.signUserKey(allocator, master, c.id);
        const sig = try standard.sign(allocator, c.message, key, master.public_key, c.nonce);
        try testing.expectEqualSlices(u8, &c.h, &sig.h);
        try testing.expectEqual(c.sx, sig.S.x);
        try testing.expectEqual(c.sy, sig.S.y);
        try testing.expect(try standard.verify(allocator, c.message, sig, c.id, master.public_key));
        if (c.message.len > 0) {
            var tampered = try allocator.dupe(u8, c.message);
            defer allocator.free(tampered);
            tampered[0] ^= 1;
            try testing.expect(!try standard.verify(allocator, tampered, sig, c.id, master.public_key));
        }
    }
}

test "SM9 nonce and signature boundary rejection" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const master = standard.signMaster(1);
    const key = try standard.signUserKey(allocator, master, "boundary");
    try testing.expectError(error.InvalidPrivateKey, standard.sign(allocator, "m", key, master.public_key, 0));
    try testing.expectError(error.InvalidPrivateKey, standard.sign(allocator, "m", key, master.public_key, bn.N));

    const zero = standard.Signature{ .h = @splat(0), .S = key };
    try testing.expect(!try standard.verify(allocator, "m", zero, "boundary", master.public_key));
    const too_big = standard.Signature{ .h = bytesOfN(), .S = key };
    try testing.expect(!try standard.verify(allocator, "m", too_big, "boundary", master.public_key));
}

fn bytesOfN() [32]u8 {
    var out: [32]u8 = undefined;
    std.mem.writeInt(bn.Fp, &out, bn.N, .big);
    return out;
}

test "SM9 encryption message length boundaries" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const master = standard.encryptMaster(2);
    const id = "长度测试@example.com";
    const key = try standard.encryptUserKey(allocator, master, id);

    for ([_]usize{ 1, 15, 16, 31, 32, 33, 255 }) |len| {
        const msg = try allocator.alloc(u8, len);
        defer allocator.free(msg);
        for (msg, 0..) |*b, i| b.* = @intCast((i * 7 + 3) % 256);

        const ct = try standard.encrypt(allocator, msg, id, master.public_key, 0xabcdef);
        defer allocator.free(ct.C2);
        const out = try standard.decrypt(allocator, ct, id, key);
        defer allocator.free(out);
        try testing.expectEqualSlices(u8, msg, out);
    }

    try testing.expectError(error.EmptyMessage, standard.encrypt(allocator, "", id, master.public_key, 1));
    try testing.expectError(error.InvalidPrivateKey, standard.encrypt(allocator, "x", id, master.public_key, 0));
    try testing.expectError(error.InvalidPrivateKey, standard.encrypt(allocator, "x", id, master.public_key, bn.N));
}
