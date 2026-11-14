//! BN254 field/curve primitives for SM9, using Zig's native wide integers.
//! Reference: gmalg SM9 (1-2-4-12 tower, R-ate pairing).

const std = @import("std");

pub const Fp = u256;
pub const Fp2 = struct { c1: Fp, c0: Fp }; // c1*u + c0, u^2 = -2
pub const Fp4 = struct { c1: Fp2, c0: Fp2 }; // c1*v + c0, v^2 = u
pub const Fp12 = struct { c2: Fp4, c1: Fp4, c0: Fp4 }; // c2*w^2+c1*w+c0, w^3=v

pub const P: Fp = 0xB640000002A3A6F1D603AB4FF58EC74521F2934B1A7AEEDBE56F9B27E351457D;
pub const N: Fp = 0xB640000002A3A6F1D603AB4FF58EC74449F2934B18EA8BEEE56EE19CD69ECF25;
pub const T: u64 = 0x600000000058F98A;

pub const G1 = struct { x: Fp, y: Fp };
pub const G2 = struct { x: Fp2, y: Fp2 };

pub const P1 = G1{
    .x = 0x93DE051D62BF718FF5ED0704487D01D6E1E4086909DC3280E8C4E4817C66DDDD,
    .y = 0x21FE8DDA4F21E607631065125C395BBC1C1C00CBFA6024350C464CD70A3EA616,
};
pub const P2 = G2{
    .x = .{
        .c1 = 0x85AEF3D078640C98597B6027B441A01FF1DD2C190F5E93C454806C11D8806141,
        .c0 = 0x3722755292130B08D2AAB97FD34EC120EE265948D19C17ABF9B7213BAF82D65B,
    },
    .y = .{
        .c1 = 0x17509B092E845C1266BA0D262CBEE6ED0736A96FA347C8BD856DC76B84EBEB96,
        .c0 = 0xA7CF28D519BE3DA65F3170153D278FF247EFBA98A71A08116215BBA5C999A7C7,
    },
};
pub const B_TWIST = Fp2{ .c1 = 5, .c0 = 0 };

pub fn add(a: Fp, b: Fp) Fp {
    const s = a +% b;
    return if (s < a or s >= P) s -% P else s;
}
pub fn sub(a: Fp, b: Fp) Fp {
    const d = a -% b;
    return if (a < b) d +% P else d;
}
const P_LIMBS = [4]u64{
    0xe56f9b27e351457d,
    0x21f2934b1a7aeedb,
    0xd603ab4ff58ec745,
    0xb640000002a3a6f1,
};
const MONT_N0: u64 = 0x892bc42c2f2ee42b; // -P^-1 mod 2^64
const MONT_R2 = [4]u64{
    0x27dea312b417e2d2,
    0x88f8105fae1a5d3f,
    0xe479b522d6706e7b,
    0x2ea795a656f62fbd,
};

fn toLimbs(a: Fp) [4]u64 {
    return .{
        @truncate(a),
        @truncate(a >> 64),
        @truncate(a >> 128),
        @truncate(a >> 192),
    };
}

fn fromLimbs(l: [4]u64) Fp {
    return @as(Fp, l[0]) |
        (@as(Fp, l[1]) << 64) |
        (@as(Fp, l[2]) << 128) |
        (@as(Fp, l[3]) << 192);
}

fn montMul(a: Fp, b: Fp) Fp {
    const x = toLimbs(a);
    const y = toLimbs(b);
    var t: [9]u64 = @splat(0);

    // 4x4 schoolbook product into t[0..8].
    for (0..4) |i| {
        var carry: u64 = 0;
        for (0..4) |j| {
            const idx = i + j;
            const prod = @as(u128, x[i]) * y[j] + t[idx] + carry;
            t[idx] = @truncate(prod);
            carry = @truncate(prod >> 64);
        }
        t[i + 4] +%= carry;
    }

    // Montgomery reduction.
    var i: usize = 0;
    while (i < 4) : (i += 1) {
        const m = t[i] *% MONT_N0;
        var carry: u64 = 0;
        for (0..4) |j| {
            const idx = i + j;
            const sum = @as(u128, m) * P_LIMBS[j] + t[idx] + carry;
            t[idx] = @truncate(sum);
            carry = @truncate(sum >> 64);
        }
        var k = i + 4;
        while (carry != 0 and k < 9) : (k += 1) {
            const sum = @as(u128, t[k]) + carry;
            t[k] = @truncate(sum);
            carry = @truncate(sum >> 64);
        }
    }

    var r = [5]u64{ t[4], t[5], t[6], t[7], t[8] };
    // Conditional subtraction if the 5-limb value is >= P.
    if (r[4] != 0 or r[3] > P_LIMBS[3] or
        (r[3] == P_LIMBS[3] and r[2] > P_LIMBS[2]) or
        (r[3] == P_LIMBS[3] and r[2] == P_LIMBS[2] and r[1] > P_LIMBS[1]) or
        (r[3] == P_LIMBS[3] and r[2] == P_LIMBS[2] and r[1] == P_LIMBS[1] and r[0] >= P_LIMBS[0]))
    {
        var borrow: u64 = 0;
        for (0..5) |j| {
            const pj: u64 = if (j < 4) P_LIMBS[j] else 0;
            const diff = @as(u128, r[j]) -% pj -% borrow;
            r[j] = @truncate(diff);
            borrow = @as(u64, @truncate(diff >> 64)) & 1;
        }
    }
    return fromLimbs(r[0..4].*);
}

pub fn mul(a: Fp, b: Fp) Fp {
    // a*b*R^-1 then *R^2*R^-1 = a*b.
    return montMul(montMul(a, b), fromLimbs(MONT_R2));
}
pub fn neg(a: Fp) Fp {
    return if (a == 0) 0 else P - a;
}
pub fn pow(a: Fp, e: Fp) Fp {
    var r: Fp = 1;
    var base = a;
    var exp = e;
    while (exp != 0) : (exp >>= 1) {
        if (exp & 1 != 0) r = mul(r, base);
        base = mul(base, base);
    }
    return r;
}
pub fn inv(a: Fp) Fp {
    if (a == 0) return 0;
    // Binary extended Euclidean inverse for an odd modulus.
    var u: Fp = a;
    var v: Fp = P;
    var x1: Fp = 1;
    var x2: Fp = 0;

    while (u != 1 and v != 1) {
        while ((u & 1) == 0) {
            u >>= 1;
            if ((x1 & 1) == 0) {
                x1 >>= 1;
            } else {
                x1 = (x1 >> 1) + (P >> 1) + 1;
            }
        }
        while ((v & 1) == 0) {
            v >>= 1;
            if ((x2 & 1) == 0) {
                x2 >>= 1;
            } else {
                x2 = (x2 >> 1) + (P >> 1) + 1;
            }
        }
        if (u >= v) {
            u -= v;
            x1 = sub(x1, x2);
        } else {
            v -= u;
            x2 = sub(x2, x1);
        }
    }
    return if (u == 1) x1 else x2;
}

pub fn f2Zero() Fp2 {
    return .{ .c1 = 0, .c0 = 0 };
}
pub fn f2One() Fp2 {
    return .{ .c1 = 0, .c0 = 1 };
}
pub fn f2Add(a: Fp2, b: Fp2) Fp2 {
    return .{ .c1 = add(a.c1, b.c1), .c0 = add(a.c0, b.c0) };
}
pub fn f2Sub(a: Fp2, b: Fp2) Fp2 {
    return .{ .c1 = sub(a.c1, b.c1), .c0 = sub(a.c0, b.c0) };
}
pub fn f2Neg(a: Fp2) Fp2 {
    return .{ .c1 = neg(a.c1), .c0 = neg(a.c0) };
}
pub fn f2Mul(a: Fp2, b: Fp2) Fp2 {
    const t0 = mul(a.c1, b.c1);
    const t1 = mul(a.c0, b.c0);
    return .{
        .c1 = sub(sub(mul(add(a.c1, a.c0), add(b.c1, b.c0)), t0), t1),
        .c0 = sub(t1, mul(2, t0)),
    };
}
pub fn f2Inv(a: Fp2) Fp2 {
    const den = sub(neg(mul(2, mul(a.c1, a.c1))), mul(a.c0, a.c0));
    const d = inv(den);
    return .{ .c1 = mul(a.c1, d), .c0 = neg(mul(a.c0, d)) };
}
pub fn f2IsZero(a: Fp2) bool {
    return a.c1 == 0 and a.c0 == 0;
}
pub fn f2Eq(a: Fp2, b: Fp2) bool {
    return a.c1 == b.c1 and a.c0 == b.c0;
}

pub fn f2Sqrt(a: Fp2) ?Fp2 {
    const t = sub(mul(a.c0, a.c0), mul(2, mul(a.c1, a.c1)));
    const w = fpSqrt(t) orelse return null;
    var w2 = neg(w);
    if (w2 == 0) w2 = w;
    const inv2 = inv(2);
    for ([_]Fp{ w, w2 }) |candidate| {
        const v = mul(add(a.c0, candidate), inv2);
        if (fpSqrt(v)) |y| {
            const denom = mul(2, y);
            if (denom == 0) return null;
            return .{ .c1 = mul(a.c1, inv(denom)), .c0 = y };
        }
    }
    return null;
}

pub fn fpSqrt(a: Fp) ?Fp {
    if (a == 0) return 0;
    const q = P;
    const exp = (q + 3) / 8;
    var y = pow(a, exp);
    if (mul(y, y) == a) return y;
    const sqrt_m1 = pow(2, (q - 1) / 4);
    y = mul(y, sqrt_m1);
    if (mul(y, y) == a) return y;
    return null;
}

pub fn g2Add(p: G2, q: G2) G2 {
    // Infinity is (0, 0).
    if (p.x.c1 == 0 and p.x.c0 == 0 and p.y.c1 == 0 and p.y.c0 == 0) return q;
    if (q.x.c1 == 0 and q.x.c0 == 0 and q.y.c1 == 0 and q.y.c0 == 0) return p;

    if (f2Eq(p.x, q.x)) {
        if (!f2Eq(p.y, q.y)) return .{ .x = f2Zero(), .y = f2Zero() };
        const num = f2Mul(f2Mul(.{ .c1 = 0, .c0 = 3 }, p.x), p.x);
        const lam = f2Mul(num, f2Inv(f2Mul(.{ .c1 = 0, .c0 = 2 }, p.y)));
        const x3 = f2Sub(f2Mul(lam, lam), f2Mul(.{ .c1 = 0, .c0 = 2 }, p.x));
        return .{ .x = x3, .y = f2Sub(f2Mul(lam, f2Sub(p.x, x3)), p.y) };
    }
    const lam = f2Mul(f2Sub(q.y, p.y), f2Inv(f2Sub(q.x, p.x)));
    const x3 = f2Sub(f2Sub(f2Mul(lam, lam), p.x), q.x);
    return .{ .x = x3, .y = f2Sub(f2Mul(lam, f2Sub(p.x, x3)), p.y) };
}

pub fn g2Mul(k: Fp, p: G2) G2 {
    var r = G2{ .x = f2Zero(), .y = f2Zero() };
    var base = p;
    var e = k;
    while (e != 0) : (e >>= 1) {
        if (e & 1 != 0) r = g2Add(r, base);
        base = g2Add(base, base);
    }
    return r;
}

pub fn g1Add(p: G1, q: G1) G1 {
    if (p.x == 0 and p.y == 0) return q;
    if (q.x == 0 and q.y == 0) return p;
    if (p.x == q.x) {
        if (p.y != q.y) return .{ .x = 0, .y = 0 };
        const lam = mul(mul(3, mul(p.x, p.x)), inv(mul(2, p.y)));
        const x3 = sub(mul(lam, lam), mul(2, p.x));
        return .{ .x = x3, .y = sub(mul(lam, sub(p.x, x3)), p.y) };
    }
    const lam = mul(sub(q.y, p.y), inv(sub(q.x, p.x)));
    const x3 = sub(sub(mul(lam, lam), p.x), q.x);
    return .{ .x = x3, .y = sub(mul(lam, sub(p.x, x3)), p.y) };
}

const G1Jac = struct { x: Fp, y: Fp, z: Fp };
const G2Jac = struct { x: Fp2, y: Fp2, z: Fp2 };

fn g1JacDouble(p: G1Jac) G1Jac {
    if (p.z == 0 or p.y == 0) return .{ .x = 0, .y = 0, .z = 0 };
    const a = mul(p.x, p.x);
    const b = mul(p.y, p.y);
    const c = mul(b, b);
    const xb = add(p.x, b);
    const d = mul(2, sub(sub(mul(xb, xb), a), c));
    const e = mul(3, a);
    const f = mul(e, e);
    const x3 = sub(f, mul(2, d));
    const y3 = sub(mul(e, sub(d, x3)), mul(8, c));
    const z3 = mul(2, mul(p.y, p.z));
    return .{ .x = x3, .y = y3, .z = z3 };
}

fn g1JacAddAffine(p: G1Jac, q: G1) G1Jac {
    if (p.z == 0) return .{ .x = q.x, .y = q.y, .z = 1 };
    const z1z1 = mul(p.z, p.z);
    const uu2 = mul(q.x, z1z1);
    const s2 = mul(q.y, mul(p.z, z1z1));
    const h = sub(uu2, p.x);
    const hh = mul(h, h);
    if (hh == 0) {
        if (s2 == p.y) return g1JacDouble(p);
        return .{ .x = 0, .y = 0, .z = 0 };
    }
    const i = mul(4, hh);
    const j = mul(h, i);
    const r = mul(2, sub(s2, p.y));
    const v = mul(p.x, i);
    const x3 = sub(sub(mul(r, r), j), mul(2, v));
    const y3 = sub(mul(r, sub(v, x3)), mul(2, mul(p.y, j)));
    const z3 = sub(sub(mul(add(p.z, h), add(p.z, h)), z1z1), hh);
    return .{ .x = x3, .y = y3, .z = z3 };
}

fn g1JacToAffine(p: G1Jac) G1 {
    if (p.z == 0) return .{ .x = 0, .y = 0 };
    const zinv = inv(p.z);
    const zinv2 = mul(zinv, zinv);
    return .{ .x = mul(p.x, zinv2), .y = mul(p.y, mul(zinv2, zinv)) };
}

pub fn g1Mul(k: Fp, p: G1) G1 {
    var r = G1Jac{ .x = 0, .y = 0, .z = 0 };
    const e = k;
    var i: usize = 256;
    while (i > 0) {
        i -= 1;
        r = g1JacDouble(r);
        if ((e >> @intCast(i)) & 1 != 0) r = g1JacAddAffine(r, p);
    }
    return g1JacToAffine(r);
}

fn f2Double(a: Fp2) Fp2 {
    return .{ .c1 = add(a.c1, a.c1), .c0 = add(a.c0, a.c0) };
}
fn f2Triple(a: Fp2) Fp2 {
    return f2Add(f2Double(a), a);
}
fn f2Eight(a: Fp2) Fp2 {
    return f2Double(f2Double(f2Double(a)));
}

fn g2JacDouble(p: G2Jac) G2Jac {
    if (f2IsZero(p.z) or f2IsZero(p.y)) return .{ .x = f2Zero(), .y = f2Zero(), .z = f2Zero() };
    const a = f2Mul(p.x, p.x);
    const b = f2Mul(p.y, p.y);
    const c = f2Mul(b, b);
    const d = f2Double(f2Sub(f2Sub(f2Mul(f2Add(p.x, b), f2Add(p.x, b)), a), c));
    const e = f2Triple(a);
    const f = f2Mul(e, e);
    const x3 = f2Sub(f, f2Double(d));
    const y3 = f2Sub(f2Mul(e, f2Sub(d, x3)), f2Eight(c));
    const z3 = f2Mul(f2Double(p.y), p.z);
    return .{ .x = x3, .y = y3, .z = z3 };
}

fn g2JacAddAffine(p: G2Jac, q: G2) G2Jac {
    if (f2IsZero(p.z)) return .{ .x = q.x, .y = q.y, .z = f2One() };
    const z1z1 = f2Mul(p.z, p.z);
    const uu2 = f2Mul(q.x, z1z1);
    const s2 = f2Mul(q.y, f2Mul(p.z, z1z1));
    const h = f2Sub(uu2, p.x);
    const hh = f2Mul(h, h);
    if (f2IsZero(hh)) {
        if (f2Eq(s2, p.y)) return g2JacDouble(p);
        return .{ .x = f2Zero(), .y = f2Zero(), .z = f2Zero() };
    }
    const i = f2Double(f2Double(hh));
    const j = f2Mul(h, i);
    const r = f2Double(f2Sub(s2, p.y));
    const v = f2Mul(p.x, i);
    const x3 = f2Sub(f2Sub(f2Mul(r, r), j), f2Double(v));
    const y3 = f2Sub(f2Mul(r, f2Sub(v, x3)), f2Double(f2Mul(p.y, j)));
    const z3 = f2Sub(f2Sub(f2Mul(f2Add(p.z, h), f2Add(p.z, h)), z1z1), hh);
    return .{ .x = x3, .y = y3, .z = z3 };
}

fn g2JacToAffine(p: G2Jac) G2 {
    if (f2IsZero(p.z)) return .{ .x = f2Zero(), .y = f2Zero() };
    const zinv = f2Inv(p.z);
    const zinv2 = f2Mul(zinv, zinv);
    return .{ .x = f2Mul(p.x, zinv2), .y = f2Mul(p.y, f2Mul(zinv2, zinv)) };
}

pub fn g2OnCurve(p: G2) bool {
    const y2 = f2Mul(p.y, p.y);
    const x3 = f2Mul(f2Mul(p.x, p.x), p.x);
    return f2Eq(y2, f2Add(x3, B_TWIST));
}

test "G2 generator and doubling match reference" {
    try std.testing.expect(g2OnCurve(P2));
    const d = g2Mul(2, P2);
    try std.testing.expectEqual(
        @as(Fp, 0x513F149AB53E94BB3A0367C61FF87670E025DB30C57F84594E4BA4D7B3C656CF),
        d.x.c1,
    );
    try std.testing.expectEqual(
        @as(Fp, 0x2A74F8561B91993205EB512576AD56221EA5963F3DA078240D55594FB051EA86),
        d.x.c0,
    );
    try std.testing.expectEqual(
        @as(Fp, 0x776DE41DB0511B8976D69C982DD4757D641487C68D13CBEE7069396C20CD3459),
        d.y.c1,
    );
    try std.testing.expectEqual(
        @as(Fp, 0x8E3D9EC4E63D5B9F83081FB97B715430C8BFC6F1A1321A89627B9A4E8961C7BD),
        d.y.c0,
    );
}

test "G1 scalar multiplication matches reference" {
    const p2 = g1Mul(2, P1);
    try std.testing.expectEqual(
        @as(Fp, 68837315291996743217041636622852396466818836882647819428664965029664991212722),
        p2.x,
    );
    try std.testing.expectEqual(
        @as(Fp, 41865216905745220189262372230466479811613031676539468004305532680884167287293),
        p2.y,
    );
}

test "Fp12 arithmetic is internally consistent" {
    const x = Fp12{
        .c2 = .{ .c1 = .{ .c1 = 3, .c0 = 5 }, .c0 = .{ .c1 = 7, .c0 = 11 } },
        .c1 = .{ .c1 = .{ .c1 = 13, .c0 = 17 }, .c0 = .{ .c1 = 19, .c0 = 23 } },
        .c0 = .{ .c1 = .{ .c1 = 29, .c0 = 31 }, .c0 = .{ .c1 = 37, .c0 = 41 } },
    };
    try std.testing.expect(f12Eq(f12Mul(x, f12One()), x));
    try std.testing.expect(f12Eq(f12Mul(x, f12Inv(x)), f12One()));
}

pub fn f4Zero() Fp4 {
    return .{ .c1 = f2Zero(), .c0 = f2Zero() };
}
pub fn f4One() Fp4 {
    return .{ .c1 = f2Zero(), .c0 = f2One() };
}
pub fn f4Add(a: Fp4, b: Fp4) Fp4 {
    return .{ .c1 = f2Add(a.c1, b.c1), .c0 = f2Add(a.c0, b.c0) };
}
pub fn f4Sub(a: Fp4, b: Fp4) Fp4 {
    return .{ .c1 = f2Sub(a.c1, b.c1), .c0 = f2Sub(a.c0, b.c0) };
}
pub fn f4Neg(a: Fp4) Fp4 {
    return .{ .c1 = f2Neg(a.c1), .c0 = f2Neg(a.c0) };
}
fn f4Alpha() Fp2 {
    return .{ .c1 = 1, .c0 = 0 };
}
pub fn f4Mul(a: Fp4, b: Fp4) Fp4 {
    const t0 = f2Mul(a.c1, b.c1);
    const t1 = f2Mul(a.c0, b.c0);
    return .{
        .c1 = f2Sub(f2Sub(f2Mul(f2Add(a.c1, a.c0), f2Add(b.c1, b.c0)), t0), t1),
        .c0 = f2Add(f2Mul(f4Alpha(), t0), t1),
    };
}
pub fn f4Inv(a: Fp4) Fp4 {
    const den = f2Sub(f2Mul(f4Alpha(), f2Mul(a.c1, a.c1)), f2Mul(a.c0, a.c0));
    const d = f2Inv(den);
    return .{ .c1 = f2Mul(a.c1, d), .c0 = f2Neg(f2Mul(a.c0, d)) };
}
fn f4ByV(a: Fp4) Fp4 {
    return f4Mul(a, .{ .c1 = f2One(), .c0 = f2Zero() });
}
pub fn f4Eq(a: Fp4, b: Fp4) bool {
    return f2Eq(a.c1, b.c1) and f2Eq(a.c0, b.c0);
}
pub fn f4IsZero(a: Fp4) bool {
    return a.c1.c1 == 0 and a.c1.c0 == 0 and a.c0.c1 == 0 and a.c0.c0 == 0;
}

pub fn f12Zero() Fp12 {
    return .{ .c2 = f4Zero(), .c1 = f4Zero(), .c0 = f4Zero() };
}
pub fn f12One() Fp12 {
    return .{ .c2 = f4Zero(), .c1 = f4Zero(), .c0 = f4One() };
}
pub fn f12Mul(a: Fp12, b: Fp12) Fp12 {
    const z2 = f4Mul(a.c2, b.c2);
    const z1 = f4Mul(a.c1, b.c1);
    const z0 = f4Mul(a.c0, b.c0);
    const a2a1 = f4Mul(f4Add(a.c2, a.c1), f4Add(b.c2, b.c1));
    const a2a0 = f4Mul(f4Add(a.c2, a.c0), f4Add(b.c2, b.c0));
    const a1a0 = f4Mul(f4Add(a.c1, a.c0), f4Add(b.c1, b.c0));
    const uz2 = f4ByV(z2);
    const cross2 = f4Sub(a2a1, f4Add(z2, z1));
    return .{
        .c2 = f4Sub(f4Add(a2a0, z1), f4Add(z2, z0)),
        .c1 = f4Sub(f4Add(uz2, a1a0), f4Add(z1, z0)),
        .c0 = f4Add(f4ByV(cross2), z0),
    };
}
pub fn f12Inv(a: Fp12) Fp12 {
    const uz2 = f4ByV(a.c2);
    const uz1 = f4ByV(a.c1);
    const t0 = f4Sub(f4Mul(a.c1, a.c1), f4Mul(a.c2, a.c0));
    const t1 = f4Sub(f4Mul(uz2, a.c2), f4Mul(a.c1, a.c0));
    const t2 = f4Sub(f4Mul(a.c0, a.c0), f4Mul(uz2, a.c1));
    const det = f4Add(f4Mul(uz2, t1), f4Add(f4Mul(uz1, t0), f4Mul(a.c0, t2)));
    const d = f4Inv(det);
    return .{ .c2 = f4Mul(t0, d), .c1 = f4Mul(t1, d), .c0 = f4Mul(t2, d) };
}
pub fn f12Eq(a: Fp12, b: Fp12) bool {
    return f4Eq(a.c2, b.c2) and f4Eq(a.c1, b.c1) and f4Eq(a.c0, b.c0);
}

pub fn g1OnCurve(p: G1) bool {
    return mul(p.y, p.y) == add(mul(mul(p.x, p.x), p.x), 5);
}
