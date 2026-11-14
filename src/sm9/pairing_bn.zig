//! SM9 R-ate pairing on the standard BN254 parameters.
//! The field/curve primitives live in `bn.zig`.

const std = @import("std");
const bn = @import("bn.zig");

const Fp = bn.Fp;
const Fp2 = bn.Fp2;
const Fp4 = bn.Fp4;
const Fp12 = bn.Fp12;
const G1 = bn.G1;
const G2 = bn.G2;

pub const PairingError = error{PairingFailed};

pub fn f12FromFp(a: Fp) Fp12 {
    return .{
        .c2 = bn.f4Zero(),
        .c1 = bn.f4Zero(),
        .c0 = .{ .c1 = bn.f2Zero(), .c0 = .{ .c1 = 0, .c0 = a } },
    };
}

pub fn f12PowSmall(a: Fp12, e: u64) Fp12 {
    var r = bn.f12One();
    var base = a;
    var exp = e;
    while (exp != 0) : (exp >>= 1) {
        if (exp & 1 != 0) r = bn.f12Mul(r, base);
        base = bn.f12Mul(base, base);
    }
    return r;
}

pub fn f12Pow(a: Fp12, e: Fp) Fp12 {
    var r = bn.f12One();
    var base = a;
    var exp = e;
    while (exp != 0) : (exp >>= 1) {
        if (exp & 1 != 0) r = bn.f12Mul(r, base);
        base = bn.f12Mul(base, base);
    }
    return r;
}

const FROB_FACTORS = [12]Fp{
    0x88ff5c730c0b73a064e54bb6a38b7f78ca1b1aa1217ba25198dafea840a7def7,
    0x2d40a38cf6983351711e5f99520347cc57d778a9f8ff4c8a4c949c7fa2a96686,
    0xb640000002a3a6f0e303ab4ff2eb2052a9f02115caef75e70f738991676af249,
    0xf300000002a3a6f2780272354f8b78f4d5fc11967be65334,
    0xb640000002a3a6f0e303ab4ff2eb2052a9f02115caef75e70f738991676af24a,
    0xf300000002a3a6f2780272354f8b78f4d5fc11967be65333,
    0x771c15a71d319b1651c73e5559865ffbda2ccadd0c9de9ee3c5217d3abd5dbf2,
    0x3f23ea58e5720bdb843c6cfA9c08674947c5c86e0ddd04eda91d8354377b698b,
    0x49db721a269967c4e0a8debc0783182f82555233139e9d63efbd7b54092c756c,
    0x6c648de5dc0a3f2cf55acc93ee0baf159f9d411806dc5177f5b21fd3da24d011,
    0xb640000002a3a6f1d603ab4ff58ec74521f2934b1a7aeedbe56f9b27e351457c,
    1,
};

pub fn frob1(x: Fp12) Fp12 {
    var out = bn.f12Zero();
    out.c2.c1.c1 = bn.mul(x.c2.c1.c1, FROB_FACTORS[0]);
    out.c2.c1.c0 = bn.mul(x.c2.c1.c0, FROB_FACTORS[1]);
    out.c2.c0.c1 = bn.mul(x.c2.c0.c1, FROB_FACTORS[2]);
    out.c2.c0.c0 = bn.mul(x.c2.c0.c0, FROB_FACTORS[3]);
    out.c1.c1.c1 = bn.mul(x.c1.c1.c1, FROB_FACTORS[4]);
    out.c1.c1.c0 = bn.mul(x.c1.c1.c0, FROB_FACTORS[5]);
    out.c1.c0.c1 = bn.mul(x.c1.c0.c1, FROB_FACTORS[6]);
    out.c1.c0.c0 = bn.mul(x.c1.c0.c0, FROB_FACTORS[7]);
    out.c0.c1.c1 = bn.mul(x.c0.c1.c1, FROB_FACTORS[8]);
    out.c0.c1.c0 = bn.mul(x.c0.c1.c0, FROB_FACTORS[9]);
    out.c0.c0.c1 = bn.mul(x.c0.c0.c1, FROB_FACTORS[10]);
    out.c0.c0.c0 = bn.mul(x.c0.c0.c0, FROB_FACTORS[11]);
    return out;
}

fn frob2(x: Fp12) Fp12 {
    return frob1(frob1(x));
}
fn frob3(x: Fp12) Fp12 {
    return frob1(frob2(x));
}
fn frob6(x: Fp12) Fp12 {
    return frob3(frob3(x));
}

fn finalExp(f: Fp12) Fp12 {
    var x = bn.f12Mul(frob6(f), bn.f12Inv(f));
    x = bn.f12Mul(frob2(x), x);

    const ft = f12PowSmall(x, bn.T);
    const ft2 = f12PowSmall(ft, bn.T);
    const ft3 = f12PowSmall(ft2, bn.T);

    const y6 = f12PowSmall(bn.f12Mul(ft3, frob1(ft3)), 36);
    const y5 = f12PowSmall(ft2, 30);
    const y4 = f12PowSmall(bn.f12Mul(frob1(ft2), ft), 18);
    const y3 = f12PowSmall(frob1(ft), 12);
    const y2 = f12PowSmall(frob2(ft2), 6);
    const y1 = bn.f12Mul(x, x);
    const y0 = bn.f12Mul(frob1(x), bn.f12Mul(frob2(x), frob3(x)));

    const num = bn.f12Mul(y2, y0);
    const den = bn.f12Mul(y6, bn.f12Mul(y5, bn.f12Mul(y4, bn.f12Mul(y3, y1))));
    return bn.f12Mul(num, bn.f12Inv(den));
}

const Fp12Point = struct { x: Fp12, y: Fp12 };

fn negF12(a: Fp12) Fp12 {
    return .{ .c2 = bn.f4Neg(a.c2), .c1 = bn.f4Neg(a.c1), .c0 = bn.f4Neg(a.c0) };
}
fn subF12(a: Fp12, b: Fp12) Fp12 {
    return .{ .c2 = bn.f4Sub(a.c2, b.c2), .c1 = bn.f4Sub(a.c1, b.c1), .c0 = bn.f4Sub(a.c0, b.c0) };
}
fn eqF12(a: Fp12, b: Fp12) bool {
    return bn.f12Eq(a, b);
}
fn isZeroF12(a: Fp12) bool {
    return bn.f4IsZero(a.c2) and bn.f4IsZero(a.c1) and bn.f4IsZero(a.c0);
}

fn phi(p: G2) Fp12Point {
    const inv_neg2: Fp = 0x5B2000000151D378EB01D5A7FAC763A290F949A58D3D776DF2B7CD93F1A8A2BE;
    const x = Fp12{
        .c2 = bn.f4Zero(),
        .c1 = .{
            .c1 = .{ .c1 = bn.mul(p.x.c0, inv_neg2), .c0 = p.x.c1 },
            .c0 = bn.f2Zero(),
        },
        .c0 = bn.f4Zero(),
    };
    const y = Fp12{
        .c2 = bn.f4Zero(),
        .c1 = bn.f4Zero(),
        .c0 = .{
            .c1 = .{ .c1 = bn.mul(p.y.c0, inv_neg2), .c0 = p.y.c1 },
            .c0 = bn.f2Zero(),
        },
    };
    return .{ .x = x, .y = y };
}

fn phiInv(p: Fp12Point) G2 {
    const neg2: Fp = bn.P - 2;
    const x = p.x.c1.c1;
    const y = p.y.c0.c1;
    return .{
        .x = .{ .c1 = x.c0, .c0 = bn.mul(x.c1, neg2) },
        .y = .{ .c1 = y.c0, .c0 = bn.mul(y.c1, neg2) },
    };
}

fn pointInf(p: Fp12Point) bool {
    return isZeroF12(p.x) and isZeroF12(p.y);
}

fn gFn(u: Fp12Point, v: Fp12Point, q: Fp12Point) Fp12 {
    if (pointInf(u) or pointInf(v) or pointInf(q)) return bn.f12One();

    var lam: Fp12 = undefined;
    if (eqF12(u.x, v.x)) {
        if (eqF12(u.y, negF12(v.y))) return subF12(q.x, v.x);
        lam = bn.f12Mul(
            bn.f12Mul(f12FromFp(3), bn.f12Mul(v.x, v.x)),
            bn.f12Inv(bn.f12Mul(f12FromFp(2), v.y)),
        );
    } else {
        lam = bn.f12Mul(subF12(u.y, v.y), bn.f12Inv(subF12(u.x, v.x)));
    }
    return subF12(bn.f12Mul(lam, subF12(q.x, v.x)), subF12(q.y, v.y));
}

fn g1ToFp12Point(p: G1) Fp12Point {
    return .{
        .x = f12FromFp(p.x),
        .y = f12FromFp(p.y),
    };
}

const E_A_BITS = "00100000000000000000000000000000000000010000101011101100100111110";

pub fn pairingLoopOnly(p: G1, q: G2) Fp12 {
    const pp = g1ToFp12Point(p);
    const qq = phi(q);
    var f = bn.f12One();
    var t = q;
    var i: usize = 0;
    while (i < E_A_BITS.len) : (i += 1) {
        f = bn.f12Mul(bn.f12Mul(f, f), gFn(phi(t), phi(t), pp));
        t = bn.g2Add(t, t);
        if (E_A_BITS[i] == '1') {
            f = bn.f12Mul(f, gFn(phi(t), qq, pp));
            t = bn.g2Add(t, q);
        }
    }
    return f;
}

pub fn pairing(p: G1, q: G2) Fp12 {
    if (p.x == 0 and p.y == 0) return bn.f12One();
    if (q.x.c1 == 0 and q.x.c0 == 0 and q.y.c1 == 0 and q.y.c0 == 0) return bn.f12One();

    const pp = g1ToFp12Point(p);
    const qq = phi(q);

    var f = bn.f12One();
    var t = q;
    var i: usize = 0;
    while (i < E_A_BITS.len) : (i += 1) {
        f = bn.f12Mul(bn.f12Mul(f, f), gFn(phi(t), phi(t), pp));
        t = bn.g2Add(t, t);
        if (E_A_BITS[i] == '1') {
            f = bn.f12Mul(f, gFn(phi(t), qq, pp));
            t = bn.g2Add(t, q);
        }
    }

    const q1 = Fp12Point{ .x = frob1(qq.x), .y = frob1(qq.y) };
    const q2 = Fp12Point{ .x = frob2(qq.x), .y = negF12(frob2(qq.y)) };

    f = bn.f12Mul(f, gFn(phi(t), q1, pp));
    t = bn.g2Add(t, phiInv(q1));
    f = bn.f12Mul(f, gFn(phi(t), q2, pp));

    return finalExp(f);
}

pub fn toBytes(a: Fp12) [384]u8 {
    var out: [384]u8 = undefined;
    var o: usize = 0;
    for ([_]Fp4{ a.c2, a.c1, a.c0 }) |p4| {
        for ([_]Fp2{ p4.c1, p4.c0 }) |p2| {
            std.mem.writeInt(Fp, out[o..][0..32], p2.c1, .big);
            o += 32;
            std.mem.writeInt(Fp, out[o..][0..32], p2.c0, .big);
            o += 32;
        }
    }
    return out;
}

test "pairing is non-degenerate and bilinear" {
    const g = pairing(bn.P1, bn.P2);
    try std.testing.expect(!eqF12(g, bn.f12One()));
    const bytes = toBytes(g);
    // Prefix of the external gmalg reference value for e(P1, P2).
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x25, 0x69, 0x43, 0xfb, 0xdb, 0x2b, 0xf8, 0x7a }, bytes[0..8]);
    try std.testing.expect(eqF12(bn.f12Mul(g, g), pairing(bn.g1Mul(2, bn.P1), bn.P2)));
}
