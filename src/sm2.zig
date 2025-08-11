const std = @import("std");
const crypto = std.crypto;
const mem = std.mem;
const meta = std.meta;
const math = std.math;
const EncodingError = crypto.errors.EncodingError;
const IdentityElementError = crypto.errors.IdentityElementError;
const NonCanonicalError = crypto.errors.NonCanonicalError;
const NotSquareError = crypto.errors.NotSquareError;

/// Group operations over SM2.
pub const SM2 = struct {
    /// The underlying prime field.
    /// Field arithmetic mod the order of the main subgroup.
    pub const scalar = @import("sm2/scalar.zig");
    pub const Fe = @import("sm2/field.zig").Fe;

    x: Fe,
    y: Fe,
    z: Fe = Fe.one,
    is_base: bool = false,

    /// The SM2 base point.
    pub const basePoint = SM2{
        .x = Fe.fromInt(22963146547237050559479531362550074578802567295341616970375194840604139615431) catch unreachable,
        .y = Fe.fromInt(85132369209828568825618990617112496413088388631904505083283536607588877201568) catch unreachable,
        .z = Fe.one,
        .is_base = true,
    };

    /// The SM2 neutral element.
    pub const identityElement = SM2{ .x = Fe.zero, .y = Fe.one, .z = Fe.zero };

    // SM2 curve: y² = x³ + ax + b
    // a = -3 = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
    // B = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
    pub const A = Fe.fromInt(0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC) catch unreachable;
    pub const B = Fe.fromInt(0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93) catch unreachable;

    /// Reject the neutral element.
    pub fn rejectIdentity(p: SM2) IdentityElementError!void {
        if (p.z.isZero()) {
            return error.IdentityElement;
        }
    }

    /// Create a point from affine coordinates after checking that they match the curve equation.
    pub fn fromAffineCoordinates(p: AffineCoordinates) EncodingError!SM2 {
        const x = p.x;
        const y = p.y;
        if (x.isZero() and y.isZero()) {
            return SM2.identityElement;
        }

        // 验证曲线方程 y² = x³ + ax + b
        const x3 = x.sq().mul(x);
        const ax = A.mul(x);
        const x3axb = x3.add(ax).add(B);
        const yy = y.sq();
        if (!x3axb.equivalent(yy)) {
            return error.InvalidEncoding;
        }
        return SM2{ .x = x, .y = y, .z = Fe.one };
    }

    /// Create a point from serialized affine coordinates.
    pub fn fromSerializedAffineCoordinates(xs: [32]u8, ys: [32]u8, endian: std.builtin.Endian) (NonCanonicalError || EncodingError)!SM2 {
        const x = try Fe.fromBytes(xs, endian);
        const y = try Fe.fromBytes(ys, endian);
        return fromAffineCoordinates(.{ .x = x, .y = y });
    }

    /// Recover the Y coordinate from the X coordinate.
    pub fn recoverY(x: Fe, is_odd: bool) NotSquareError!Fe {
        const x3 = x.sq().mul(x);
        const ax = A.mul(x);
        const x3axb = x3.add(ax).add(B);
        var y = try x3axb.sqrt();
        const yn = y.neg();
        y.cMov(yn, @intFromBool(is_odd) ^ @intFromBool(y.isOdd()));
        return y;
    }

    /// Deserialize a SEC1-encoded point.
    pub fn fromSec1(s: []const u8) (EncodingError || NotSquareError || NonCanonicalError)!SM2 {
        if (s.len < 1) return error.InvalidEncoding;
        const encoding_type = s[0];
        const encoded = s[1..];
        switch (encoding_type) {
            0 => {
                if (encoded.len != 0) return error.InvalidEncoding;
                return SM2.identityElement;
            },
            2, 3 => {
                if (encoded.len != 32) return error.InvalidEncoding;
                const x = try Fe.fromBytes(encoded[0..32].*, .big);
                const y_is_odd = (encoding_type == 3);
                const y = try recoverY(x, y_is_odd);
                return SM2{ .x = x, .y = y };
            },
            4 => {
                if (encoded.len != 64) return error.InvalidEncoding;
                const x = try Fe.fromBytes(encoded[0..32].*, .big);
                const y = try Fe.fromBytes(encoded[32..64].*, .big);
                return SM2.fromAffineCoordinates(.{ .x = x, .y = y });
            },
            else => return error.InvalidEncoding,
        }
    }

    /// Serialize a point using the compressed SEC-1 format.
    pub fn toCompressedSec1(p: SM2) [33]u8 {
        if (p.z.isZero()) {
            var out = [1]u8{0} ** 33;
            out[0] = 0;
            return out;
        }
        var out: [33]u8 = undefined;
        const xy = p.affineCoordinates();
        out[0] = if (xy.y.isOdd()) 3 else 2;
        out[1..].* = xy.x.toBytes(.big);
        return out;
    }

    /// Serialize a point using the uncompressed SEC-1 format.
    pub fn toUncompressedSec1(p: SM2) [65]u8 {
        var out: [65]u8 = undefined;
        out[0] = 4;
        const xy = p.affineCoordinates();
        out[1..33].* = xy.x.toBytes(.big);
        out[33..65].* = xy.y.toBytes(.big);
        return out;
    }

    /// Return a random point.
    pub fn random() SM2 {
        const n = scalar.random(.little);
        return basePoint.mul(n, .little) catch unreachable;
    }

    /// Flip the sign of the X coordinate.
    pub fn neg(p: SM2) SM2 {
        return .{ .x = p.x, .y = p.y.neg(), .z = p.z };
    }

    /// Double a SM2 point.
    // Fixed doubling algorithm for SM2
    pub fn dbl(p: SM2) SM2 {
        if (p.z.isZero()) {
            return SM2.identityElement;
        }

        const xx = p.x.sq();
        const yy = p.y.sq();
        const zz = p.z.sq();
        const zzzz = zz.sq();
        const s = p.x.mul(yy).dbl().dbl(); // 4 * X * Y²
        const m = xx.mul(Fe.fromInt(3) catch unreachable).sub(zzzz.mul(Fe.fromInt(3) catch unreachable)); // 3X² - 3Z⁴
        const t = m.sq().sub(s.dbl()); // M² - 2S
        const x3 = t;
        const y3 = m.mul(s.sub(t)).sub(yy.sq().dbl().dbl().dbl()); // M*(S-T) - 8Y⁴
        const z3 = p.y.mul(p.z).dbl(); // 2*Y*Z

        return .{ .x = x3, .y = y3, .z = z3 };
    }

    /// Add SM2 points, the second being specified using affine coordinates.
    // Fixed mixed addition algorithm for SM2
    pub fn addMixed(p: SM2, q: AffineCoordinates) SM2 {
        if (p.z.isZero()) {
            return .{ .x = q.x, .y = q.y, .z = Fe.one };
        }
        if (q.x.isZero() and q.y.isZero()) {
            return p;
        }

        const z1z1 = p.z.sq();
        const n2 = q.x.mul(z1z1);
        const s2 = q.y.mul(p.z).mul(z1z1);

        if (p.x.equivalent(n2)) {
            return if (p.y.equivalent(s2)) p.dbl() else SM2.identityElement;
        }

        const h = n2.sub(p.x);
        const hh = h.sq();
        const i = hh.dbl().dbl(); // 4*HH
        const j = h.mul(i);
        const r = s2.sub(p.y).dbl();
        const v = p.x.mul(i);

        const x3 = r.sq().sub(j).sub(v.dbl());
        const y3 = r.mul(v.sub(x3)).sub(p.y.mul(j).dbl());
        const z3 = p.z.mul(h).dbl(); // 2*Z1*H

        return .{ .x = x3, .y = y3, .z = z3 };
    }

    /// Add SM2 points.
    // Fixed addition algorithm for SM2
    pub fn add(p: SM2, q: SM2) SM2 {
        if (p.z.isZero()) return q;
        if (q.z.isZero()) return p;

        const z1z1 = p.z.sq();
        const z2z2 = q.z.sq();
        const n1 = p.x.mul(z2z2);
        const n2 = q.x.mul(z1z1);
        const s1 = p.y.mul(q.z).mul(z2z2);
        const s2 = q.y.mul(p.z).mul(z1z1);

        if (n1.equivalent(n2)) {
            return if (s1.equivalent(s2)) p.dbl() else SM2.identityElement;
        }

        const h = n2.sub(n1);
        const hh = h.sq();
        const i = hh.dbl().dbl(); // 4*HH
        const j = h.mul(i);
        const r = s2.sub(s1).dbl();
        const v = n1.mul(i);

        const x3 = r.sq().sub(j).sub(v.dbl());
        const y3 = r.mul(v.sub(x3)).sub(s1.mul(j).dbl());
        const z3 = p.z.mul(q.z).mul(h).dbl().dbl(); // 4*Z1*Z2*H

        return .{ .x = x3, .y = y3, .z = z3 };
    }

    /// Subtract SM2 points.
    pub fn sub(p: SM2, q: SM2) SM2 {
        return p.add(q.neg());
    }

    /// Subtract SM2 points, the second being specified using affine coordinates.
    pub fn subMixed(p: SM2, q: AffineCoordinates) SM2 {
        return p.addMixed(q.neg());
    }

    /// Return affine coordinates.
    pub fn affineCoordinates(p: SM2) AffineCoordinates {
        if (p.z.isZero()) {
            return AffineCoordinates.identityElement;
        }
        const zinv = p.z.invert();
        const x = p.x.mul(zinv);
        const y = p.y.mul(zinv);
        return .{ .x = x, .y = y };
    }

    /// Return true if both coordinate sets represent the same point.
    pub fn equivalent(a: SM2, b: SM2) bool {
        if (a.sub(b).rejectIdentity()) {
            return false;
        } else |_| {
            return true;
        }
    }

    fn cMov(p: *SM2, a: SM2, c: u1) void {
        p.x.cMov(a.x, c);
        p.y.cMov(a.y, c);
        p.z.cMov(a.z, c);
    }

    fn slide(s: [32]u8) [2 * 32 + 1]i8 {
        var e: [2 * 32 + 1]i8 = undefined;
        for (s, 0..) |x, i| {
            e[i * 2 + 0] = @as(i8, @as(u4, @truncate(x)));
            e[i * 2 + 1] = @as(i8, @as(u4, @truncate(x >> 4)));
        }
        var carry: i8 = 0;
        for (e[0..64]) |*x| {
            x.* += carry;
            carry = (x.* + 8) >> 4;
            x.* -= carry * 16;
            std.debug.assert(x.* >= -8 and x.* <= 8);
        }
        e[64] = carry;
        std.debug.assert(carry >= -8 and carry <= 8);
        return e;
    }

    fn pcSelect(comptime n: usize, pc: *const [n]SM2, b: u8) SM2 {
        var t = SM2.identityElement;
        comptime var i: u8 = 1;
        inline while (i < pc.len) : (i += 1) {
            const select = @as(u1, @intFromBool(i == b));
            t.cMov(pc[i], select);
        }
        return t;
    }

    fn precompute(p: SM2, comptime count: usize) [1 + count]SM2 {
        var pc: [1 + count]SM2 = undefined;
        pc[0] = SM2.identityElement;
        pc[1] = p;
        var i: usize = 2;
        while (i <= count) : (i += 1) {
            pc[i] = if (i % 2 == 0) pc[i / 2].dbl() else pc[i - 1].add(p);
        }
        return pc;
    }

    const basePointPc = pc: {
        @setEvalBranchQuota(500000);
        break :pc precompute(SM2.basePoint, 15);
    };

    fn orderSwap(s: [32]u8) [32]u8 {
        var t = s;
        std.mem.reverse(u8, &t);
        return t;
    }

    /// Multiply an elliptic curve point by a scalar.
    /// Return error.IdentityElement if the result is the identity element.
    pub fn mul(p: SM2, s_: [32]u8, endian: std.builtin.Endian) IdentityElementError!SM2 {
        const s = if (endian == .little) s_ else orderSwap(s_);
        if (p.is_base) {
            return pcMul16(&basePointPc, s, false);
        }
        try p.rejectIdentity();
        const pc = precompute(p, 15);
        return pcMul16(&pc, s, false);
    }

    fn pcMul16(pc: *const [16]SM2, s: [32]u8, comptime vartime: bool) IdentityElementError!SM2 {
        var q = SM2.identityElement;
        var pos: usize = 252;
        while (true) : (pos -= 4) {
            const slot = @as(u4, @truncate((s[pos >> 3] >> @as(u3, @truncate(pos)))));

            if (vartime) {
                if (slot != 0) {
                    q = q.add(pc[slot]);
                }
            } else {
                q = q.add(pcSelect(16, pc, slot));
            }

            if (pos == 0) break;
            q = q.dbl().dbl().dbl().dbl();
        }
        try q.rejectIdentity();
        return q;
    }

    /// Multiply an elliptic curve point by a *PUBLIC* scalar *IN VARIABLE TIME*
    /// This can be used for signature verification.
    pub fn mulPublic(p: SM2, s_: [32]u8, endian: std.builtin.Endian) IdentityElementError!SM2 {
        const s = if (endian == .little) s_ else orderSwap(s_);
        if (p.is_base) {
            return pcMul16(&basePointPc, s, true);
        }
        try p.rejectIdentity();
        const pc = precompute(p, 8);
        return pcMul(&pc, s, true);
    }

    fn pcMul(pc: *const [9]SM2, s: [32]u8, comptime vartime: bool) IdentityElementError!SM2 {
        const e = slide(s);
        var q = SM2.identityElement;
        var pos: usize = 64;
        _ = vartime;

        while (true) : (pos -= 1) {
            const slot = e[pos];
            if (slot > 0) {
                q = q.add(pc[@as(usize, @intCast(slot))]);
            } else if (slot < 0) {
                q = q.sub(pc[@as(usize, @intCast(-slot))]);
            }
            if (pos == 0) break;
            q = q.dbl().dbl().dbl().dbl();
        }
        try q.rejectIdentity();
        return q;
    }

    /// Double-base multiplication of public parameters - Compute (p1*s1)+(p2*s2) *IN VARIABLE TIME*
    /// This can be used for signature verification.
    pub fn mulDoubleBasePublic(p1: SM2, s1_: [32]u8, p2: SM2, s2_: [32]u8, endian: std.builtin.Endian) IdentityElementError!SM2 {
        const s1 = if (endian == .little) s1_ else orderSwap(s1_);
        const s2 = if (endian == .little) s2_ else orderSwap(s2_);
        try p1.rejectIdentity();
        var pc1_array: [9]SM2 = undefined;
        const pc1 = if (p1.is_base) basePointPc[0..9] else pc: {
            pc1_array = precompute(p1, 8);
            break :pc &pc1_array;
        };
        try p2.rejectIdentity();
        var pc2_array: [9]SM2 = undefined;
        const pc2 = if (p2.is_base) basePointPc[0..9] else pc: {
            pc2_array = precompute(p2, 8);
            break :pc &pc2_array;
        };
        const e1 = slide(s1);
        const e2 = slide(s2);
        var q = SM2.identityElement;
        var pos: usize = 64;
        while (true) : (pos -= 1) {
            const slot1 = e1[pos];
            if (slot1 > 0) {
                q = q.add(pc1[@as(usize, @intCast(slot1))]);
            } else if (slot1 < 0) {
                q = q.sub(pc1[@as(usize, @intCast(-slot1))]);
            }
            const slot2 = e2[pos];
            if (slot2 > 0) {
                q = q.add(pc2[@as(usize, @intCast(slot2))]);
            } else if (slot2 < 0) {
                q = q.sub(pc2[@as(usize, @intCast(-slot2))]);
            }
            if (pos == 0) break;
            q = q.dbl().dbl().dbl().dbl();
        }
        try q.rejectIdentity();
        return q;
    }

    pub const AffineCoordinates = struct {
        x: SM2.Fe,
        y: SM2.Fe,

        /// Identity element in affine coordinates.
        pub const identityElement = AffineCoordinates{ .x = Fe.zero, .y = Fe.zero };

        pub fn neg(p: AffineCoordinates) AffineCoordinates {
            return .{ .x = p.x, .y = p.y.neg() };
        }

        fn cMov(p: *AffineCoordinates, a: AffineCoordinates, c: u1) void {
            p.x.cMov(a.x, c);
            p.y.cMov(a.y, c);
        }
    };
};
