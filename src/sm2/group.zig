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
    // Corrected doubling algorithm for SM2 using Jacobian coordinates
    pub fn dbl(p: SM2) SM2 {
        if (p.z.isZero()) {
            return SM2.identityElement;
        }

        // Algorithm for point doubling in Jacobian coordinates
        // Input: P = (X1, Y1, Z1)
        // Output: 2P = (X3, Y3, Z3)

        const Y1Y1 = p.y.sq();                      // Y1²
        const S = p.x.mul(Y1Y1).dbl().dbl();       // S = 4*X1*Y1²
        const M = p.x.sq().mul(Fe.fromInt(3) catch unreachable).add(A.mul(p.z.sq().sq())); // M = 3*X1² + a*Z1⁴
        const X3 = M.sq().sub(S.dbl());            // X3 = M² - 2*S
        const Y3 = M.mul(S.sub(X3)).sub(Y1Y1.sq().dbl().dbl().dbl()); // Y3 = M*(S-X3) - 8*Y1⁴
        const Z3 = p.y.mul(p.z).dbl();             // Z3 = 2*Y1*Z1

        return .{ .x = X3, .y = Y3, .z = Z3 };
    }

    /// Add SM2 points, the second being specified using affine coordinates.
    pub fn addMixed(p: SM2, q: AffineCoordinates) SM2 {
        if (p.z.isZero()) {
            return .{ .x = q.x, .y = q.y, .z = Fe.one };
        }
        if (q.x.isZero() and q.y.isZero()) {
            return p;
        }

        // Algorithm for mixed addition in Jacobian coordinates
        const Z1Z1 = p.z.sq();                      // Z1²
        const U2 = q.x.mul(Z1Z1);                  // U2 = X2*Z1²
        const S2 = q.y.mul(p.z).mul(Z1Z1);        // S2 = Y2*Z1³

        if (p.x.equivalent(U2)) {
            return if (p.y.equivalent(S2)) p.dbl() else SM2.identityElement;
        }

        const H = U2.sub(p.x);                      // H = U2 - X1
        const HH = H.sq();                          // HH = H²
        const I = HH.dbl().dbl();                   // I = 4*HH
        const J = H.mul(I);                         // J = H*I
        const r = S2.sub(p.y).dbl();               // r = 2*(S2 - Y1)
        const V = p.x.mul(I);                      // V = X1*I

        const X3 = r.sq().sub(J).sub(V.dbl());     // X3 = r² - J - 2*V
        const Y3 = r.mul(V.sub(X3)).sub(p.y.mul(J).dbl()); // Y3 = r*(V-X3) - 2*Y1*J
        const Z3 = p.z.mul(H).dbl();               // Z3 = 2*Z1*H

        return .{ .x = X3, .y = Y3, .z = Z3 };
    }

    /// Add SM2 points.
    pub fn add(p: SM2, q: SM2) SM2 {
        if (p.z.isZero()) return q;
        if (q.z.isZero()) return p;

        // Algorithm for point addition in Jacobian coordinates
        const Z1Z1 = p.z.sq();                      // Z1²
        const Z2Z2 = q.z.sq();                      // Z2²
        const U1 = p.x.mul(Z2Z2);                  // U1 = X1*Z2²
        const U2 = q.x.mul(Z1Z1);                  // U2 = X2*Z1²
        const S1 = p.y.mul(q.z).mul(Z2Z2);        // S1 = Y1*Z2³
        const S2 = q.y.mul(p.z).mul(Z1Z1);        // S2 = Y2*Z1³

        if (U1.equivalent(U2)) {
            return if (S1.equivalent(S2)) p.dbl() else SM2.identityElement;
        }

        const H = U2.sub(U1);                       // H = U2 - U1
        const I = H.dbl().sq();                     // I = (2*H)²
        const J = H.mul(I);                         // J = H*I
        const r = S2.sub(S1).dbl();                // r = 2*(S2 - S1)
        const V = U1.mul(I);                       // V = U1*I

        const X3 = r.sq().sub(J).sub(V.dbl());     // X3 = r² - J - 2*V
        const Y3 = r.mul(V.sub(X3)).sub(S1.mul(J).dbl()); // Y3 = r*(V-X3) - 2*S1*J
        const Z3 = p.z.mul(q.z).mul(H).dbl();      // Z3 = 2*Z1*Z2*H

        return .{ .x = X3, .y = Y3, .z = Z3 };
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
        const zinv2 = zinv.sq();           // Z⁻²
        const zinv3 = zinv2.mul(zinv);     // Z⁻³
        const x = p.x.mul(zinv2);          // X / Z²
        const y = p.y.mul(zinv3);          // Y / Z³
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

    pub fn cMov(p: *SM2, a: SM2, c: u1) void {
        p.x.cMov(a.x, c);
        p.y.cMov(a.y, c);
        p.z.cMov(a.z, c);
    }

    /// Swap the endianness of a 32-byte array.
    fn orderSwap(s: [32]u8) [32]u8 {
        var t = s;
        mem.reverse(u8, &t);
        return t;
    }

    /// Multiply an elliptic curve point by a scalar.
    /// Return error.IdentityElement if the result is the identity element.
    pub fn mul(p: SM2, s_: [32]u8, endian: std.builtin.Endian) IdentityElementError!SM2 {
        const s = if (endian == .little) s_ else orderSwap(s_);

        // 使用简单的二进制方法（从最高位开始）
        var result = SM2.identityElement;

        // 从最高字节开始处理
        var byte_idx: usize = 31;
        while (true) {
            const byte = s[byte_idx];
            var bit_mask: u8 = 0x80; // 从最高位开始

            while (bit_mask != 0) : (bit_mask >>= 1) {
                result = result.dbl();
                if (byte & bit_mask != 0) {
                    result = result.add(p);
                }
            }

            if (byte_idx == 0) break;
            byte_idx -= 1;
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
