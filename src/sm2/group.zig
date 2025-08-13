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
    pub const scalar = @import("scalar.zig");
    pub const Fe = @import("field.zig").Fe;

    x: Fe,
    y: Fe,
    z: Fe = Fe.one,
    is_base: bool = false,

    /// The SM2 base point.
    pub const basePoint = SM2{
        .x = Fe.fromInt(0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7) catch unreachable,
        .y = Fe.fromInt(0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0) catch unreachable,
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
                return SM2{ .x = x, .y = y, .z = Fe.one };
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
    // Corrected doubling algorithm for SM2 using Jacobian coordinates
    pub fn dbl(p: SM2) SM2 {
        if (p.z.isZero()) {
            return SM2.identityElement;
        }

        const THREE = Fe.fromInt(3) catch unreachable;

        const xx = p.x.sq(); // X1²
        const yy = p.y.sq(); // Y1²
        const yyyy = yy.sq(); // Y1⁴
        const zz = p.z.sq(); // Z1²
        const s = p.x.add(yy).sq().sub(xx).sub(yyyy).dbl(); // 2*(X1+Y1²)²-2*X1²-2*Y1⁴
        const m = xx.mul(THREE).add(A.mul(zz.sq())); // 3*X1² + a*Z1⁴
        const x3 = m.sq().sub(s.dbl()); // M² - 2*S
        const y3 = m.mul(s.sub(x3)).sub(yyyy.dbl().dbl().dbl()); // M*(S-X3) - 8*Y1⁴
        const z3 = p.y.mul(p.z).dbl(); // 2*Y1*Z1

        return .{ .x = x3, .y = y3, .z = z3 };
    }

    /// Add SM2 points, the second being specified using affine coordinates.
    /// 由于有限域运算的特性，缺少这个因子会导致后续计算不匹配。
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
    const h3 = h.mul(hh);
    // 修复1: 移除r的dbl()
    const r = s2.sub(p.y);
    const v = p.x.mul(hh);

    // 修复2: 移除h3的dbl()
    const x3 = r.sq().sub(h3).sub(v.dbl());
    // 修复3: 移除p.y.mul(h3)的dbl()
    const y3 = r.mul(v.sub(x3)).sub(p.y.mul(h3));
    // 修复4: 移除z3的dbl()
    const z3 = p.z.mul(h);

    return .{ .x = x3, .y = y3, .z = z3 };
    }

    /// Add SM2 points.
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
        const hh = h.sq(); // H²
        const h3 = h.mul(hh); // H³
        const r = s2.sub(s1);
        const v = n1.mul(hh); // U1 * H²

        const x3 = r.sq().sub(h3).sub(v.dbl());
        const y3 = r.mul(v.sub(x3)).sub(s1.mul(h3)); // 修正：移除多余的.dbl()
        const z3 = p.z.mul(q.z).mul(h); // 修正：Z3 = H * Z1 * Z2

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
        const zinv2 = zinv.sq(); // Z⁻²
        const zinv3 = zinv2.mul(zinv); // Z⁻³
        const x = p.x.mul(zinv2); // X / Z²
        const y = p.y.mul(zinv3); // Y / Z³
        return .{ .x = x, .y = y };
    }

    /// Return true if both coordinate sets represent the same point.
    pub fn equivalent(a: SM2, b: SM2) bool {
        // 都是无穷远点
        if (a.z.isZero() and b.z.isZero()) return true;
        // 一个无穷远点，一个不是
        if (a.z.isZero() or b.z.isZero()) return false;

        // 转换到仿射坐标进行比较
        const z1z1 = a.z.sq();
        const z2z2 = b.z.sq();
        const n1 = a.x.mul(z2z2); // X1 * Z2²
        const n2 = b.x.mul(z1z1); // X2 * Z1²
        const s1 = a.y.mul(b.z).mul(z2z2); // Y1 * Z2³
        const s2 = b.y.mul(a.z).mul(z1z1); // Y2 * Z1³

        return n1.equivalent(n2) and s1.equivalent(s2);
    }

    pub fn cMov(p: *SM2, a: SM2, c: u1) void {
        p.x.cMov(a.x, c);
        p.y.cMov(a.y, c);
        p.z.cMov(a.z, c);
    }

    /// Swap the endianness of a 32-byte array.
    fn orderSwap(s: [32]u8) [32]u8 {
        var t = s;
        for (0..16) |i| {
            const j = 31 - i;
            const tmp = t[i];
            t[i] = t[j];
            t[j] = tmp;
        }
        return t;
    }

    /// Multiply an elliptic curve point by a scalar.
    /// Return error.IdentityElement if the result is the identity element.
    pub fn mul(p: SM2, s_: [32]u8, endian: std.builtin.Endian) IdentityElementError!SM2 {
        const s = if (endian == .little) s_ else orderSwap(s_);

        var result = SM2.identityElement;
        var addend = p;

        // 从最低字节开始处理（小端序）
        for (0..32) |i| {
            const byte = s[i];
            var bit_mask: u8 = 1;

            while (bit_mask != 0) : (bit_mask <<= 1) {
                if ((byte & bit_mask) != 0) {
                    result = result.add(addend);
                }
                addend = addend.dbl();
            }
        }

        try result.rejectIdentity();
        return result;
    }

    /// Multiply an elliptic curve point by a *PUBLIC* scalar *IN VARIABLE TIME*
    /// This can be used for signature verification.
    pub fn mulPublic(p: SM2, s_: [32]u8, endian: std.builtin.Endian) IdentityElementError!SM2 {
        return p.mul(s_, endian);
    }

    /// Double-base multiplication of public parameters - Compute (p1*s1)+(p2*s2) *IN VARIABLE TIME*
    /// This can be used for signature verification.
    pub fn mulDoubleBasePublic(p1: SM2, s1: [32]u8, p2: SM2, s2: [32]u8, endian: std.builtin.Endian) IdentityElementError!SM2 {
        const r1 = try p1.mul(s1, endian);
        const r2 = try p2.mul(s2, endian);
        const result = r1.add(r2);
        try result.rejectIdentity();
        return result;
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
