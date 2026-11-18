const std = @import("std");
const testing = std.testing;
const zuc = @import("../zuc.zig");

test "ZUC-256 draft keystream vectors" {
    const keys = [_][32]u8{
        @splat(0x00),
        @splat(0xff),
    };
    const ivs = [_][23]u8{
        @splat(0x00),
        @splat(0xff),
    };
    const expected = [_][20]u32{
        .{
            0x58d03ad6, 0x2e032ce2, 0xdafc683a, 0x39bdcb03, 0x52a2bc67,
            0xf1b7de74, 0x163ce3a1, 0x01ef5558, 0x9639d75b, 0x95fa681b,
            0x7f090df7, 0x56391ccc, 0x903b7612, 0x744d544c, 0x17bc3fad,
            0x8b163b08, 0x21787c0b, 0x97775bb8, 0x4943c6bb, 0xe8ad8afd,
        },
        .{
            0x3356cbae, 0xd1a1c18b, 0x6baa4ffe, 0x343f777c, 0x9e15128f,
            0x251ab65b, 0x949f7b26, 0xef7157f2, 0x96dd2fa9, 0xdf95e3ee,
            0x7a5be02e, 0xc32ba585, 0x505af316, 0xc2f9ded2, 0x7cdbd935,
            0xe441ce11, 0x15fd0a80, 0xbb7aef67, 0x68989416, 0xb8fac8c2,
        },
    };

    for (keys, ivs, expected) |key, iv, want| {
        var cipher = zuc.ZUC256.init(&key, &iv);
        var got: [20]u32 = undefined;
        cipher.generateKeystream(&got);
        try testing.expectEqualSlices(u32, &want, &got);
    }
}

test "ZUC-256 MAC 32/64/128-bit vectors" {
    const key0 = @as([32]u8, @splat(0x00));
    const keyf = @as([32]u8, @splat(0xff));
    const iv0 = @as([23]u8, @splat(0x00));
    const ivf = @as([23]u8, @splat(0xff));
    const zeros = @as([50]u8, @splat(0x00));
    const ones = @as([50]u8, @splat(0x11));

    const Case = struct {
        key: [32]u8,
        iv: [23]u8,
        msg: [50]u8,
        repeats: usize,
        tag32: u32,
        tag64: [2]u32,
        tag128: [4]u32,
    };
    const cases = [_]Case{
        .{ .key = key0, .iv = iv0, .msg = zeros, .repeats = 1, .tag32 = 0x9b972a74, .tag64 = .{ 0x673e5499, 0x0034d38c }, .tag128 = .{ 0xd85e54bb, 0xcb960096, 0x7084c952, 0xa1654b26 } },
        .{ .key = key0, .iv = iv0, .msg = ones, .repeats = 10, .tag32 = 0x8754f5cf, .tag64 = .{ 0x130dc225, 0xe72240cc }, .tag128 = .{ 0xdf1e8307, 0xb31cc62b, 0xeca1ac6f, 0x8190c22f } },
        .{ .key = keyf, .iv = ivf, .msg = zeros, .repeats = 1, .tag32 = 0x1f3079b4, .tag64 = .{ 0x8c71394d, 0x39957725 }, .tag128 = .{ 0xa35bb274, 0xb567c48b, 0x28319f11, 0x1af34fbd } },
        .{ .key = keyf, .iv = ivf, .msg = ones, .repeats = 10, .tag32 = 0x5c7c8b88, .tag64 = .{ 0xea1dee54, 0x4bb6223b }, .tag128 = .{ 0x3a83b554, 0xbe408ca5, 0x494124ed, 0x9d473205 } },
    };

    for (cases) |c| {
        var mac32: [16]u8 = undefined;
        var ctx = zuc.ZUC256MAC.init(&c.key, &c.iv, 32);
        for (0..c.repeats) |_| ctx.update(&c.msg);
        ctx.finish(&[_]u8{}, 0, &mac32);
        var want: [4]u8 = undefined;
        std.mem.writeInt(u32, &want, c.tag32, .big);
        try testing.expectEqualSlices(u8, &want, mac32[0..4]);

        var mac64: [16]u8 = undefined;
        ctx = zuc.ZUC256MAC.init(&c.key, &c.iv, 64);
        for (0..c.repeats) |_| ctx.update(&c.msg);
        ctx.finish(&[_]u8{}, 0, &mac64);
        for (c.tag64, 0..) |word, i| {
            var w: [4]u8 = undefined;
            std.mem.writeInt(u32, &w, word, .big);
            try testing.expectEqualSlices(u8, &w, mac64[i * 4 ..][0..4]);
        }

        var mac128: [16]u8 = undefined;
        ctx = zuc.ZUC256MAC.init(&c.key, &c.iv, 128);
        for (0..c.repeats) |_| ctx.update(&c.msg);
        ctx.finish(&[_]u8{}, 0, &mac128);
        for (c.tag128, 0..) |word, i| {
            var w: [4]u8 = undefined;
            std.mem.writeInt(u32, &w, word, .big);
            try testing.expectEqualSlices(u8, &w, mac128[i * 4 ..][0..4]);
        }
    }
}

test "ZUC-256 crypt roundtrip" {
    const key = @as([32]u8, @splat(0x42));
    const iv = @as([23]u8, @splat(0x24));
    const message = "ZUC-256 stream cipher roundtrip";
    var ciphertext: [message.len]u8 = undefined;
    var plaintext: [message.len]u8 = undefined;

    var enc = zuc.ZUC256.init(&key, &iv);
    enc.crypt(message, &ciphertext);
    var dec = zuc.ZUC256.init(&key, &iv);
    dec.crypt(&ciphertext, &plaintext);
    try testing.expectEqualSlices(u8, message, &plaintext);
}

test "ZUC-256 MAC incremental updates match one-shot" {
    const key = @as([32]u8, @splat(0x5a));
    const iv = @as([23]u8, @splat(0xa5));
    const msg = @as([50]u8, @splat(0x3c));

    for ([_]u32{ 32, 64, 128 }) |bits| {
        var a: [16]u8 = undefined;
        var ctx = zuc.ZUC256MAC.init(&key, &iv, bits);
        ctx.update(&msg);
        ctx.finish(&[_]u8{}, 0, &a);

        var b: [16]u8 = undefined;
        ctx = zuc.ZUC256MAC.init(&key, &iv, bits);
        var off: usize = 0;
        var step: usize = 1;
        while (off < msg.len) : (step += 1) {
            const n = @min(step, msg.len - off);
            ctx.update(msg[off .. off + n]);
            off += n;
        }
        ctx.finish(&[_]u8{}, 0, &b);
        try testing.expectEqualSlices(u8, a[0 .. bits / 8], b[0 .. bits / 8]);
    }
}

test "ZUC-256 MAC partial-bit finish" {
    const key = @as([32]u8, @splat(0x00));
    const iv = @as([23]u8, @splat(0x00));
    const msg = @as([50]u8, @splat(0x11));
    const bits = [_]u8{0xe0};
    const expected = [_]struct { bits: u32, tag: [16]u8 }{
        .{ .bits = 32, .tag = .{ 0xea, 0xc0, 0x37, 0x65, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 } },
        .{ .bits = 64, .tag = .{ 0xd3, 0x5d, 0x79, 0x59, 0xe5, 0xd5, 0x8b, 0x69, 0, 0, 0, 0, 0, 0, 0, 0 } },
        .{ .bits = 128, .tag = .{ 0x91, 0xce, 0xfb, 0x03, 0x6c, 0xbb, 0x3a, 0xac, 0x03, 0x1d, 0xdb, 0x83, 0x7f, 0x51, 0x6d, 0xc5 } },
    };
    for (expected) |e| {
        var mac: [16]u8 = undefined;
        var ctx = zuc.ZUC256MAC.init(&key, &iv, e.bits);
        ctx.update(&msg);
        ctx.finish(&bits, 3, &mac);
        try testing.expectEqualSlices(u8, e.tag[0 .. e.bits / 8], mac[0 .. e.bits / 8]);
    }
}
