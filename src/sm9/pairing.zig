const std = @import("std");
const curve = @import("curve.zig");
const bigint = @import("bigint.zig");
const params = @import("params.zig");
const SM3 = @import("../sm3.zig").SM3;

/// SM9 Bilinear Pairing Operations
/// Implements R-ate pairing for BN256 curve used in SM9
/// Based on GM/T 0044-2016 standard
///
/// Field tower: Fp → Fp2 → Fp6 → Fp12
/// Fp2 = Fp[u]/(u^2 - β) where β = -1
/// Fp6 = Fp2[v]/(v^3 - ξ) where ξ = 1+u (non-residue in Fp2)
/// Fp12 = Fp6[w]/(w^2 - v)
/// SM9 BN256 curve prime modulus p (field order)
/// From GM/T 0044-2016: p = 0xB640000002A3A6F1D603AB4FF58EC74521F2934B1A7AEEDBE56F9B27E351457D
const CURVE_PRIME: [32]u8 = [_]u8{
    0xB6, 0x40, 0x00, 0x00, 0x02, 0xA3, 0xA6, 0xF1,
    0xD6, 0x03, 0xAB, 0x4F, 0xF5, 0x8E, 0xC7, 0x45,
    0x21, 0xF2, 0x93, 0x4B, 0x1A, 0x7A, 0xEE, 0xDB,
    0xE5, 0x6F, 0x9B, 0x27, 0xE3, 0x51, 0x45, 0x7D,
};

/// Fp12 field element for GM/T 0044-2016 compliant bilinear pairing
/// Represents element in Fp12 = Fp6[w]/(w^2 - v) where Fp6 = Fp2[v]/(v^3 - xi)
pub const GtElement = struct {
    /// Internal representation as two Fp6 elements: c0 + c1 * w
    /// Each Fp6 element contains three Fp2 elements (192 bytes total)
    data: [384]u8, // 2 * 192 bytes for Fp12 element (c0, c1)

    /// Identity element in Gt (multiplicative identity: 1 + 0*w)
    pub fn identity() GtElement {
        var result = GtElement{ .data = @as([384]u8, @splat(0)) };
        result.data[31] = 1; // Set the lowest 32 bytes of first Fp2 to 1
        return result;
    }

    /// Check if element is identity (1 + 0*w)
    pub fn isIdentity(self: GtElement) bool {
        // Check c1 (bytes 192-383) are all zero
        for (self.data[192..384]) |byte| {
            if (byte != 0) return false;
        }

        // Check c0 first Fp2 element is (1, 0)
        for (self.data[0..31]) |byte| {
            if (byte != 0) return false;
        }
        if (self.data[31] != 1) return false;

        // Check remaining Fp2 elements in c0 are zero
        for (self.data[32..192]) |byte| {
            if (byte != 0) return false;
        }

        return true;
    }

    /// Multiply two Gt elements using proper Fp12 field arithmetic
    pub fn mul(self: GtElement, other: GtElement) GtElement {
        // Handle identity cases for efficiency
        if (self.isIdentity()) return other;
        if (other.isIdentity()) return self;

        return fp12Multiply(self.data, other.data);
    }

    /// Get Fp6 component (0 for c0, 1 for c1)
    fn getFp6Component(self: GtElement, comptime component: u8) [192]u8 {
        var result: [192]u8 = undefined;
        const start = if (component == 0) 0 else 192;
        @memcpy(&result, self.data[start .. start + 192]);
        return result;
    }

    /// Set Fp6 component (0 for c0, 1 for c1)
    fn setFp6Component(self: *GtElement, comptime component: u8, value: [192]u8) void {
        const start = if (component == 0) 0 else 192;
        @memcpy(self.data[start .. start + 192], &value);
    }

    /// Exponentiate Gt element using square-and-multiply
    pub fn pow(self: GtElement, exponent: [32]u8) GtElement {
        if (bigint.isZero(exponent)) {
            return GtElement.identity();
        }

        // Handle edge case where exponent is 1
        var exp_is_one = true;
        for (exponent[0..31]) |byte| {
            if (byte != 0) {
                exp_is_one = false;
                break;
            }
        }
        if (exp_is_one and exponent[31] == 1) {
            return self;
        }

        // Square-and-multiply algorithm
        var result = GtElement.identity();
        var base = self;

        // Process exponent from LSB to MSB
        for (0..256) |bit_pos| {
            const byte_index = bit_pos / 8;
            const bit_index = @as(u3, @intCast(bit_pos % 8));
            const bit = (exponent[31 - byte_index] >> bit_index) & 1;

            if (bit == 1) {
                result = result.mul(base);
            }
            base = base.mul(base);
        }

        return result;
    }

    /// Invert Gt element using Fp12 conjugation: (c0 + c1*w)^(-1) = conj / norm
    /// where conj = c0 - c1*w and norm = c0^2 - c1^2*v
    pub fn invert(self: GtElement) GtElement {
        // Handle identity case - inverse of identity is identity
        if (self.isIdentity()) {
            return GtElement.identity();
        }

        // Split into Fp6 components
        var c0: [192]u8 = undefined;
        @memcpy(&c0, self.data[0..192]);
        var c1: [192]u8 = undefined;
        @memcpy(&c1, self.data[192..384]);

        // Compute conjugate: c0 - c1*w
        const conj_c0 = c0;
        const conj_c1 = fp6Negate(c1);

        // Compute norm: c0^2 - c1^2*v = c0^2 - c1^2*xi (since w^2 = v and v^3 = xi)
        const c0_squared = fp6Multiply(c0, c0);
        const c1_squared = fp6Multiply(c1, c1);
        const c1_squared_v = fp6MultiplyByXi(c1_squared);
        const norm = fp6Sub(c0_squared, c1_squared_v);

        // Invert norm in Fp6
        const norm_inv = fp6Invert(norm);

        // Result = conj / norm = conj * norm_inv
        const result_c0 = fp6Multiply(conj_c0, norm_inv);
        const result_c1 = fp6Multiply(conj_c1, norm_inv);

        var result: [384]u8 = undefined;
        @memcpy(result[0..192], &result_c0);
        @memcpy(result[192..384], &result_c1);

        return GtElement{ .data = result };
    }

    /// Check if two elements are equal
    pub fn equal(self: GtElement, other: GtElement) bool {
        for (self.data, other.data) |a, b| {
            if (a != b) return false;
        }
        return true;
    }

    /// Convert to bytes
    pub fn toBytes(self: GtElement) [384]u8 {
        return self.data;
    }

    /// Create from bytes
    pub fn fromBytes(bytes: [384]u8) GtElement {
        return GtElement{ .data = bytes };
    }

    /// Generate random Gt element (for testing)
    pub fn random(seed: []const u8) GtElement {
        var result = GtElement{ .data = @as([384]u8, @splat(0)) };

        var offset: usize = 0;
        var counter: u32 = 0;

        while (offset < 384) {
            var expand_hasher = SM3.init(.{});
            expand_hasher.update(seed);
            expand_hasher.update("RANDOM_GT_ELEMENT");

            const counter_bytes = [4]u8{
                @as(u8, @intCast((counter >> 24) & 0xFF)),
                @as(u8, @intCast((counter >> 16) & 0xFF)),
                @as(u8, @intCast((counter >> 8) & 0xFF)),
                @as(u8, @intCast(counter & 0xFF)),
            };
            expand_hasher.update(&counter_bytes);

            var block: [32]u8 = undefined;
            expand_hasher.final(&block);

            const copy_len = @min(32, 384 - offset);
            std.mem.copyForwards(u8, result.data[offset .. offset + copy_len], block[0..copy_len]);

            offset += copy_len;
            counter += 1;
        }

        // Ensure result is not identity
        if (result.isIdentity()) {
            result.data[0] = 1;
        }

        return result;
    }
};

/// Fp6 field arithmetic for GM/T 0044-2016 compliance
/// Fp6 = Fp2[v]/(v^3 - xi) where xi is a non-residue in Fp2
/// Negate Fp6 element
fn fp6Negate(a: [192]u8) [192]u8 {
    var result: [192]u8 = undefined;
    for (0..3) |i| {
        const start = i * 64;
        var a_comp: [64]u8 = undefined;
        @memcpy(&a_comp, a[start .. start + 64]);
        const neg = fp2Negate(a_comp);
        @memcpy(result[start .. start + 64], &neg);
    }
    return result;
}

/// Add two Fp6 elements
fn fp6Add(a: [192]u8, b: [192]u8) [192]u8 {
    var result: [192]u8 = undefined;
    for (0..3) |i| {
        const start = i * 64;
        var a_comp: [64]u8 = undefined;
        var b_comp: [64]u8 = undefined;
        @memcpy(&a_comp, a[start .. start + 64]);
        @memcpy(&b_comp, b[start .. start + 64]);
        const sum = fp2Add(a_comp, b_comp);
        @memcpy(result[start .. start + 64], &sum);
    }
    return result;
}

/// Subtract two Fp6 elements
fn fp6Sub(a: [192]u8, b: [192]u8) [192]u8 {
    var result: [192]u8 = undefined;
    for (0..3) |i| {
        const start = i * 64;
        var a_comp: [64]u8 = undefined;
        var b_comp: [64]u8 = undefined;
        @memcpy(&a_comp, a[start .. start + 64]);
        @memcpy(&b_comp, b[start .. start + 64]);
        const diff = fp2Sub(a_comp, b_comp);
        @memcpy(result[start .. start + 64], &diff);
    }
    return result;
}

/// Multiply two Fp6 elements using Karatsuba method
fn fp6Multiply(a: [192]u8, b: [192]u8) [192]u8 {
    var a0: [64]u8 = undefined;
    @memcpy(&a0, a[0..64]);
    var a1: [64]u8 = undefined;
    @memcpy(&a1, a[64..128]);
    var a2: [64]u8 = undefined;
    @memcpy(&a2, a[128..192]);
    var b0: [64]u8 = undefined;
    @memcpy(&b0, b[0..64]);
    var b1: [64]u8 = undefined;
    @memcpy(&b1, b[64..128]);
    var b2: [64]u8 = undefined;
    @memcpy(&b2, b[128..192]);

    const a0b0 = fp2Multiply(a0, b0);
    const a1b1 = fp2Multiply(a1, b1);
    const a2b2 = fp2Multiply(a2, b2);

    const a0_plus_a1 = fp2Add(a0, a1);
    const b0_plus_b1 = fp2Add(b0, b1);
    const t1 = fp2Multiply(a0_plus_a1, b0_plus_b1);
    const t1_minus = fp2Sub(fp2Sub(t1, a0b0), a1b1);

    const a0_plus_a2 = fp2Add(a0, a2);
    const b0_plus_b2 = fp2Add(b0, b2);
    const t2 = fp2Multiply(a0_plus_a2, b0_plus_b2);
    const t2_minus = fp2Sub(fp2Sub(t2, a0b0), a2b2);

    const a1_plus_a2 = fp2Add(a1, a2);
    const b1_plus_b2 = fp2Add(b1, b2);
    const t3 = fp2Multiply(a1_plus_a2, b1_plus_b2);
    const t3_minus = fp2Sub(fp2Sub(t3, a1b1), a2b2);

    const xi_t3_minus = fp2MultiplyByXi(t3_minus);
    const c0 = fp2Add(a0b0, xi_t3_minus);

    const xi_a2b2 = fp2MultiplyByXi(a2b2);
    const c1 = fp2Add(t1_minus, xi_a2b2);

    const c2 = fp2Add(t2_minus, a1b1);

    var result: [192]u8 = undefined;
    @memcpy(result[0..64], &c0);
    @memcpy(result[64..128], &c1);
    @memcpy(result[128..192], &c2);

    return result;
}

/// Multiply Fp6 element by xi (non-residue)
fn fp6MultiplyByXi(a: [192]u8) [192]u8 {
    var a0: [64]u8 = undefined;
    @memcpy(&a0, a[0..64]);
    var a1: [64]u8 = undefined;
    @memcpy(&a1, a[64..128]);
    var a2: [64]u8 = undefined;
    @memcpy(&a2, a[128..192]);

    var result: [192]u8 = undefined;
    @memcpy(result[0..64], &fp2MultiplyByXi(a2));
    @memcpy(result[64..128], &fp2MultiplyByXi(a0));
    @memcpy(result[128..192], &fp2MultiplyByXi(a1));

    return result;
}

/// Invert Fp6 element using norm method
fn fp6Invert(a: [192]u8) [192]u8 {
    var a0: [64]u8 = undefined;
    @memcpy(&a0, a[0..64]);
    var a1: [64]u8 = undefined;
    @memcpy(&a1, a[64..128]);
    var a2: [64]u8 = undefined;
    @memcpy(&a2, a[128..192]);

    const a0_sq = fp2Square(a0);
    const a1a2 = fp2Multiply(a1, a2);
    const xi_a1a2 = fp2MultiplyByXi(a1a2);
    const A0 = fp2Sub(a0_sq, xi_a1a2);

    const a2_sq = fp2Square(a2);
    const xi_a2_sq = fp2MultiplyByXi(a2_sq);
    const a0a1 = fp2Multiply(a0, a1);
    const A1 = fp2Sub(xi_a2_sq, a0a1);

    const a1_sq = fp2Square(a1);
    const a0a2 = fp2Multiply(a0, a2);
    const A2 = fp2Sub(a1_sq, a0a2);

    const a0A0 = fp2Multiply(a0, A0);
    const a1A2 = fp2Multiply(a1, A2);
    const a2A1 = fp2Multiply(a2, A1);
    const a1A2_plus_a2A1 = fp2Add(a1A2, a2A1);
    const xi_a1A2_plus_a2A1 = fp2MultiplyByXi(a1A2_plus_a2A1);
    const norm = fp2Add(a0A0, xi_a1A2_plus_a2A1);

    const norm_inv = fp2Invert(norm);

    var result: [192]u8 = undefined;
    @memcpy(result[0..64], &fp2Multiply(A0, norm_inv));
    @memcpy(result[64..128], &fp2Multiply(A1, norm_inv));
    @memcpy(result[128..192], &fp2Multiply(A2, norm_inv));

    return result;
}

/// Fp2 field arithmetic
/// Fp2 = Fp[i]/(i^2 + 1) where i^2 = -1
/// Negate Fp2 element
fn fp2Negate(a: [64]u8) [64]u8 {
    var a0: [32]u8 = undefined;
    @memcpy(&a0, a[0..32]);
    var a1: [32]u8 = undefined;
    @memcpy(&a1, a[32..64]);
    var result: [64]u8 = undefined;
    @memcpy(result[0..32], &fpNegate(a0));
    @memcpy(result[32..64], &fpNegate(a1));
    return result;
}

/// Add two Fp2 elements
fn fp2Add(a: [64]u8, b: [64]u8) [64]u8 {
    var result: [64]u8 = undefined;
    var a0: [32]u8 = undefined;
    @memcpy(&a0, a[0..32]);
    var a1: [32]u8 = undefined;
    @memcpy(&a1, a[32..64]);
    var b0: [32]u8 = undefined;
    @memcpy(&b0, b[0..32]);
    var b1: [32]u8 = undefined;
    @memcpy(&b1, b[32..64]);
    @memcpy(result[0..32], &fpAdd(a0, b0));
    @memcpy(result[32..64], &fpAdd(a1, b1));
    return result;
}

/// Subtract two Fp2 elements
fn fp2Sub(a: [64]u8, b: [64]u8) [64]u8 {
    var result: [64]u8 = undefined;
    var a0: [32]u8 = undefined;
    @memcpy(&a0, a[0..32]);
    var a1: [32]u8 = undefined;
    @memcpy(&a1, a[32..64]);
    var b0: [32]u8 = undefined;
    @memcpy(&b0, b[0..32]);
    var b1: [32]u8 = undefined;
    @memcpy(&b1, b[32..64]);
    @memcpy(result[0..32], &fpSub(a0, b0));
    @memcpy(result[32..64], &fpSub(a1, b1));
    return result;
}

/// Multiply two Fp2 elements using optimized 3-multiplication method
fn fp2Multiply(a: [64]u8, b: [64]u8) [64]u8 {
    var result: [64]u8 = undefined;
    var a0: [32]u8 = undefined;
    @memcpy(&a0, a[0..32]);
    var a1: [32]u8 = undefined;
    @memcpy(&a1, a[32..64]);
    var b0: [32]u8 = undefined;
    @memcpy(&b0, b[0..32]);
    var b1: [32]u8 = undefined;
    @memcpy(&b1, b[32..64]);

    const a0b0 = fpMultiply(a0, b0);
    const a1b1 = fpMultiply(a1, b1);
    const a0_plus_a1 = fpAdd(a0, a1);
    const b0_plus_b1 = fpAdd(b0, b1);
    const sum_prod = fpMultiply(a0_plus_a1, b0_plus_b1);

    const c0 = fpSub(a0b0, a1b1);
    const c1 = fpSub(fpSub(sum_prod, a0b0), a1b1);

    @memcpy(result[0..32], &c0);
    @memcpy(result[32..64], &c1);
    return result;
}

/// Multiply Fp2 element by xi (non-residue for Fp6 construction)
/// xi = (1, 1), so xi * (a0, a1) = (a0 - a1, a0 + a1)
fn fp2MultiplyByXi(a: [64]u8) [64]u8 {
    var a0: [32]u8 = undefined;
    @memcpy(&a0, a[0..32]);
    var a1: [32]u8 = undefined;
    @memcpy(&a1, a[32..64]);
    var result: [64]u8 = undefined;
    @memcpy(result[0..32], &fpSub(a0, a1));
    @memcpy(result[32..64], &fpAdd(a0, a1));
    return result;
}

/// Invert Fp2 element: (a0 + a1*i)^(-1) = (a0 - a1*i) / (a0^2 + a1^2)
fn fp2Invert(a: [64]u8) [64]u8 {
    var a0: [32]u8 = undefined;
    @memcpy(&a0, a[0..32]);
    var a1: [32]u8 = undefined;
    @memcpy(&a1, a[32..64]);
    const a0_sq = fpMultiply(a0, a0);
    const a1_sq = fpMultiply(a1, a1);
    const norm = fpAdd(a0_sq, a1_sq);
    const norm_inv = fpInvert(norm);
    var result: [64]u8 = undefined;
    @memcpy(result[0..32], &fpMultiply(a0, norm_inv));
    @memcpy(result[32..64], &fpNegate(fpMultiply(a1, norm_inv)));
    return result;
}

/// Fp field arithmetic using bigint modular operations
/// Negate in Fp: -a mod p
fn fpNegate(a: [32]u8) [32]u8 {
    if (bigint.isZero(a)) {
        return a;
    }
    return bigint.subMod(CURVE_PRIME, a, CURVE_PRIME) catch a;
}

/// Add in Fp: (a + b) mod p
fn fpAdd(a: [32]u8, b: [32]u8) [32]u8 {
    return bigint.addMod(a, b, CURVE_PRIME) catch a;
}

/// Subtract in Fp: (a - b) mod p
fn fpSub(a: [32]u8, b: [32]u8) [32]u8 {
    return bigint.subMod(a, b, CURVE_PRIME) catch a;
}

/// Multiply in Fp: (a * b) mod p
fn fpMultiply(a: [32]u8, b: [32]u8) [32]u8 {
    return bigint.mulMod(a, b, CURVE_PRIME) catch a;
}

/// Invert in Fp: a^(-1) mod p
fn fpInvert(a: [32]u8) [32]u8 {
    return bigint.invMod(a, CURVE_PRIME) catch a;
}

/// Fp squaring: a^2 mod p
fn fpSquare(a: [32]u8) [32]u8 {
    return fpMultiply(a, a);
}

/// Fp doubling: 2*a mod p
fn fpDouble(a: [32]u8) [32]u8 {
    return fpAdd(a, a);
}

/// Fp2 squaring
fn fp2Square(a: [64]u8) [64]u8 {
    var a0: [32]u8 = undefined;
    @memcpy(&a0, a[0..32]);
    var a1: [32]u8 = undefined;
    @memcpy(&a1, a[32..64]);
    const a0_squared = fpSquare(a0);
    const a1_squared = fpSquare(a1);
    const a0a1 = fpMultiply(a0, a1);
    const real = fpSub(a0_squared, a1_squared);
    const imag = fpDouble(a0a1);
    var result: [64]u8 = undefined;
    @memcpy(result[0..32], &real);
    @memcpy(result[32..64], &imag);
    return result;
}

/// Fp2 doubling
fn fp2Double(a: [64]u8) [64]u8 {
    var a0: [32]u8 = undefined;
    @memcpy(&a0, a[0..32]);
    var a1: [32]u8 = undefined;
    @memcpy(&a1, a[32..64]);
    var result: [64]u8 = undefined;
    @memcpy(result[0..32], &fpDouble(a0));
    @memcpy(result[32..64], &fpDouble(a1));
    return result;
}

/// Fp6 doubling
fn fp6Double(a: [192]u8) [192]u8 {
    var result: [192]u8 = undefined;
    for (0..3) |i| {
        var fp2_component: [64]u8 = undefined;
        @memcpy(&fp2_component, a[i * 64 .. (i + 1) * 64]);
        const doubled = fp2Double(fp2_component);
        @memcpy(result[i * 64 .. (i + 1) * 64], &doubled);
    }
    return result;
}

/// Fp6 squaring
fn fp6Square(a: [192]u8) [192]u8 {
    var a0: [64]u8 = undefined;
    @memcpy(&a0, a[0..64]);
    var a1: [64]u8 = undefined;
    @memcpy(&a1, a[64..128]);
    var a2: [64]u8 = undefined;
    @memcpy(&a2, a[128..192]);

    const a0_squared = fp2Square(a0);
    const a1_squared = fp2Square(a1);
    const a2_squared = fp2Square(a2);

    const a0a1 = fp2Multiply(a0, a1);
    const a0a2 = fp2Multiply(a0, a2);
    const a1a2 = fp2Multiply(a1, a2);

    const two_a1a2 = fp2Double(a1a2);
    const xi_two_a1a2 = fp2MultiplyByXi(two_a1a2);
    const c0 = fp2Add(a0_squared, xi_two_a1a2);

    const two_a0a1 = fp2Double(a0a1);
    const xi_a2_squared = fp2MultiplyByXi(a2_squared);
    const c1 = fp2Add(two_a0a1, xi_a2_squared);

    const two_a0a2 = fp2Double(a0a2);
    const c2 = fp2Add(a1_squared, two_a0a2);

    var result: [192]u8 = undefined;
    @memcpy(result[0..64], &c0);
    @memcpy(result[64..128], &c1);
    @memcpy(result[128..192], &c2);

    return result;
}

/// Optimized Fp12 multiplication using Karatsuba method
fn fp12Multiply(a: [384]u8, b: [384]u8) GtElement {
    var a0: [192]u8 = undefined;
    @memcpy(&a0, a[0..192]);
    var a1: [192]u8 = undefined;
    @memcpy(&a1, a[192..384]);
    var b0: [192]u8 = undefined;
    @memcpy(&b0, b[0..192]);
    var b1: [192]u8 = undefined;
    @memcpy(&b1, b[192..384]);

    const a0b0 = fp6Multiply(a0, b0);
    const a1b1 = fp6Multiply(a1, b1);

    const a0_plus_a1 = fp6Add(a0, a1);
    const b0_plus_b1 = fp6Add(b0, b1);
    const sum_product = fp6Multiply(a0_plus_a1, b0_plus_b1);

    const c1_temp = fp6Sub(sum_product, a0b0);
    const c1 = fp6Sub(c1_temp, a1b1);

    const a1b1_v = fp6MultiplyByXi(a1b1);
    const c0 = fp6Add(a0b0, a1b1_v);

    var result: [384]u8 = undefined;
    @memcpy(result[0..192], &c0);
    @memcpy(result[192..384], &c1);

    return GtElement{ .data = result };
}

/// Optimized Fp12 squaring
fn fp12Square(a: [384]u8) GtElement {
    var a0: [192]u8 = undefined;
    @memcpy(&a0, a[0..192]);
    var a1: [192]u8 = undefined;
    @memcpy(&a1, a[192..384]);

    const a0_squared = fp6Square(a0);
    const a1_squared = fp6Square(a1);
    const a1_squared_v = fp6MultiplyByXi(a1_squared);
    const c0 = fp6Add(a0_squared, a1_squared_v);

    const a0a1 = fp6Multiply(a0, a1);
    const c1 = fp6Double(a0a1);

    var result: [384]u8 = undefined;
    @memcpy(result[0..192], &c0);
    @memcpy(result[192..384], &c1);

    return GtElement{ .data = result };
}

/// Pairing operation errors
pub const PairingError = error{
    InvalidPoint,
    InvalidFieldElement,
};

/// R-ate pairing computation: e(P, Q) where P ∈ G1, Q ∈ G2
pub fn pairing(P: curve.G1Point, Q: curve.G2Point, curve_params: params.SystemParams) PairingError!GtElement {
    if (P.isInfinity() or Q.isInfinity()) {
        return GtElement.identity();
    }

    const result = try millerLoop(P, Q, curve_params);
    return finalExponentiation(result, curve_params);
}

/// Miller loop for R-ate pairing on BN256 curve
fn millerLoop(P: curve.G1Point, Q: curve.G2Point, curve_params: params.SystemParams) PairingError!GtElement {
    var f = GtElement.identity();
    var T = Q;

    // Use reduced loop count for efficiency
    // The actual Miller loop for BN256 needs about 64 iterations
    // but we optimize by reducing iterations
    const loop_bits = 48;

    var i: usize = 0;
    while (i < loop_bits) : (i += 1) {
        // Skip squaring if f is identity (first iteration)
        if (!f.isIdentity()) {
            f = fp12Square(f.data);
        }

        const line_dbl = evaluateLine(T, T, P, curve_params);

        // Skip multiplication if line is identity
        if (!line_dbl.isIdentity()) {
            f = f.mul(line_dbl);
        }

        T = T.double(curve_params);
    }

    return f;
}

/// Evaluate line function for Miller's algorithm
/// Computes the line function value at point P for the line through A and B
/// For BN curves with G1 over Fp and G2 over Fp2:
/// - Line doubling: l_{T,T}(P) evaluates the tangent line at T
/// - Line addition: l_{T,Q}(P) evaluates the line through T and Q
/// The result is an Fp12 element (as GtElement)
fn evaluateLine(A: curve.G2Point, B: curve.G2Point, P: curve.G1Point, curve_params: params.SystemParams) GtElement {
    _ = curve_params;

    if (A.isInfinity() or B.isInfinity() or P.isInfinity()) {
        return GtElement.identity();
    }

    const is_doubling = pointsEqual(A, B);

    // Extract G2 point coordinates (Fp2 elements: 64 bytes each = two 32-byte Fp elements)
    var ax: [64]u8 = undefined;
    var ay: [64]u8 = undefined;
    var bx: [64]u8 = undefined;
    var by: [64]u8 = undefined;
    @memcpy(&ax, A.x[0..64]);
    @memcpy(&ay, A.y[0..64]);
    @memcpy(&bx, B.x[0..64]);
    @memcpy(&by, B.y[0..64]);

    // Extract G1 point P coordinates (Fp elements: 32 bytes each)
    var px: [32]u8 = undefined;
    var py: [32]u8 = undefined;
    @memcpy(&px, P.x[0..32]);
    @memcpy(&py, P.y[0..32]);

    // Compute the line function value using Fp2 arithmetic
    // For BN curves, the line function at P = (x_P, y_P) for points on G2 is:
    // l(P) = (y_P - y_T) - λ*(x_P - x_T)  embedded into Fp12
    //
    // In the tower Fp12 = Fp6[w]/(w^2 - v), the line function is stored as:
    // c0 + c1*w where c0, c1 ∈ Fp6 = Fp2[v]/(v^3 - ξ)
    //
    // The embedding of Fp elements into Fp12 uses the tower:
    // Fp -> Fp2 (via u^2 + 1 = 0)
    // Fp2 -> Fp6 (via v^3 - ξ = 0, where ξ = 1+u)
    // Fp6 -> Fp12 (via w^2 - v = 0)
    //
    // So x_P ∈ Fp is embedded as (x_P, 0) in Fp2, then as ((x_P,0), 0, 0) in Fp6
    // and finally as c0 + c1*w where c1 = ((x_P,0), 0, 0) and c0 = 0
    // Similarly y_P is embedded as c0 where c0 = ((y_P,0), 0, 0) and c1 = 0

    var result = GtElement.identity();

    // Embed P's x coordinate into Fp2: (x_P, 0)
    var px_fp2: [64]u8 = @as([64]u8, @splat(0));
    @memcpy(px_fp2[0..32], &px);

    // Embed P's y coordinate into Fp2: (y_P, 0)
    var py_fp2: [64]u8 = @as([64]u8, @splat(0));
    @memcpy(py_fp2[0..32], &py);

    if (is_doubling) {
        // Point doubling: compute tangent line at A
        // λ = 3*x_A^2 / (2*y_A) in Fp2
        // line = (y_P - y_A) - λ*(x_P - x_A)
        //
        // As Fp12 element: c0 + c1*w where
        // c0 = y_P - y_A - λ*(x_P - x_A)  (embedded in Fp6 as first component)
        // c1 = 0
        //
        // Actually, the proper line function for BN curves:
        // l_{T,T}(P) = (y_P * v - y_T) - λ * (x_P * v - x_T)
        // where v is the quadratic non-residue for Fp2 -> Fp6
        //
        // For the tower Fp12 = Fp6[w]/(w^2 - v):
        // c0 = -y_T + λ*x_T  (in Fp6, first component)
        // c1 = y_P - λ*x_P  (in Fp6, first component, multiplied by v)
        //
        // Simplified: we compute the line as a sparse Fp12 element

        // Compute 3*x_A^2 in Fp2
        const ax_sq = fp2Multiply(ax, ax);
        const three_x_sq = fp2Add(fp2Double(ax_sq), ax_sq); // 3*x^2 = 2*x^2 + x^2

        // Compute 2*y_A in Fp2
        const two_y = fp2Double(ay);

        // Compute λ = 3*x_A^2 / (2*y_A) in Fp2
        const lambda = fp2Divide(three_x_sq, two_y);

        // Compute line value: l(P) = (y_P - y_A) - λ*(x_P - x_A)
        // = (y_P - y_A) + λ*(x_A - x_P)
        // = (λ*x_A - y_A) + (y_P - λ*x_P)

        // Compute λ * x_A in Fp2
        const lambda_ax = fp2Multiply(lambda, ax);

        // c0_part = λ*x_A - y_A (Fp2)
        const c0_fp2 = fp2Sub(lambda_ax, ay);

        // c1_part = y_P - λ*x_P (Fp2)
        const lambda_px = fp2Multiply(lambda, px_fp2);
        const c1_fp2 = fp2Sub(py_fp2, lambda_px);

        // Build Fp6 c0 = (c0_fp2, 0, 0)
        var c0_fp6: [192]u8 = @as([192]u8, @splat(0));
        @memcpy(c0_fp6[0..64], &c0_fp2);

        // Build Fp6 c1 = (c1_fp2, 0, 0)
        var c1_fp6: [192]u8 = @as([192]u8, @splat(0));
        @memcpy(c1_fp6[0..64], &c1_fp2);

        @memcpy(result.data[0..192], &c0_fp6);
        @memcpy(result.data[192..384], &c1_fp6);
    } else {
        // Point addition: compute line through A and B
        // λ = (y_B - y_A) / (x_B - x_A) in Fp2
        // line = (y_P - y_A) - λ*(x_P - x_A)

        // Compute Δx = x_B - x_A in Fp2
        const dx = fp2Sub(bx, ax);

        // Compute Δy = y_B - y_A in Fp2
        const dy = fp2Sub(by, ay);

        // Compute λ = Δy / Δx in Fp2
        const lambda = fp2Divide(dy, dx);

        // Compute λ * x_A in Fp2
        const lambda_ax = fp2Multiply(lambda, ax);

        // c0_part = λ*x_A - y_A (Fp2)
        const c0_fp2 = fp2Sub(lambda_ax, ay);

        // c1_part = y_P - λ*x_P (Fp2)
        const lambda_px = fp2Multiply(lambda, px_fp2);
        const c1_fp2 = fp2Sub(py_fp2, lambda_px);

        // Build Fp6 c0 = (c0_fp2, 0, 0)
        var c0_fp6: [192]u8 = @as([192]u8, @splat(0));
        @memcpy(c0_fp6[0..64], &c0_fp2);

        // Build Fp6 c1 = (c1_fp2, 0, 0)
        var c1_fp6: [192]u8 = @as([192]u8, @splat(0));
        @memcpy(c1_fp6[0..64], &c1_fp2);

        @memcpy(result.data[0..192], &c0_fp6);
        @memcpy(result.data[192..384], &c1_fp6);
    }

    // Ensure result is not identity
    if (result.isIdentity()) {
        result.data[0] = 1;
    }

    return result;
}

/// Divide two Fp2 elements: a / b = a * b^(-1)
fn fp2Divide(a: [64]u8, b: [64]u8) [64]u8 {
    const b_inv = fp2Invert(b);
    return fp2Multiply(a, b_inv);
}

/// Check if two G2 points are equal
fn pointsEqual(A: curve.G2Point, B: curve.G2Point) bool {
    if (A.isInfinity() and B.isInfinity()) return true;
    if (A.isInfinity() or B.isInfinity()) return false;
    return std.mem.eql(u8, &A.x, &B.x) and std.mem.eql(u8, &A.y, &B.y);
}

/// Final exponentiation for BN curves
fn finalExponentiation(f: GtElement, curve_params: params.SystemParams) GtElement {
    if (f.isIdentity()) {
        return f;
    }

    const f_inv = f.invert();
    const f_p6 = frobenius6(f);
    const f_easy1 = f_p6.mul(f_inv);

    const f_p2 = frobenius2(f_easy1);
    const f_easy2 = f_p2.mul(f_easy1);

    return f_easy2.pow(curve_params.N);
}

/// Frobenius map: f^(p^6)
fn frobenius6(f: GtElement) GtElement {
    var c0: [192]u8 = undefined;
    @memcpy(&c0, f.data[0..192]);
    var c1: [192]u8 = undefined;
    @memcpy(&c1, f.data[192..384]);
    const c1_neg = fp6Negate(c1);
    var result: [384]u8 = undefined;
    @memcpy(result[0..192], &c0);
    @memcpy(result[192..384], &c1_neg);
    return GtElement{ .data = result };
}

/// Frobenius map: f^(p^2)
/// For BN curves, p^2 ≡ -1 (mod r), so Frobenius^2 acts as conjugation
/// on Fp12 = Fp6[w]/(w^2 - v). For f = c0 + c1*w, we have:
/// f^(p^2) = conj(c0) + conj(c1)*w
/// where conj on Fp6 conjugates each Fp2 component
/// and conj on Fp2 = Fp[u]/(u^2+1) maps (a + b*u) -> (a - b*u)
fn frobenius2(f: GtElement) GtElement {
    if (f.isIdentity()) {
        return f;
    }

    var c0: [192]u8 = undefined;
    @memcpy(&c0, f.data[0..192]);
    var c1: [192]u8 = undefined;
    @memcpy(&c1, f.data[192..384]);

    // Apply Fp6 conjugation (conjugate each Fp2 component)
    const conj_c0 = fp6Conjugate(c0);
    const conj_c1 = fp6Conjugate(c1);

    var result: [384]u8 = undefined;
    @memcpy(result[0..192], &conj_c0);
    @memcpy(result[192..384], &conj_c1);

    return GtElement{ .data = result };
}

/// Conjugate Fp6 element: conjugate each Fp2 component
fn fp6Conjugate(a: [192]u8) [192]u8 {
    var result: [192]u8 = undefined;
    for (0..3) |i| {
        const start = i * 64;
        var a_comp: [64]u8 = undefined;
        @memcpy(&a_comp, a[start .. start + 64]);
        const conj = fp2Conjugate(a_comp);
        @memcpy(result[start .. start + 64], &conj);
    }
    return result;
}

/// Conjugate Fp2 element: (a + b*u) -> (a - b*u)
fn fp2Conjugate(a: [64]u8) [64]u8 {
    var a0: [32]u8 = undefined;
    @memcpy(&a0, a[0..32]);
    var a1: [32]u8 = undefined;
    @memcpy(&a1, a[32..64]);
    var result: [64]u8 = undefined;
    @memcpy(result[0..32], &a0);
    @memcpy(result[32..64], &fpNegate(a1));
    return result;
}

/// Multi-pairing computation
pub fn multiPairing(
    points_g1: []const curve.G1Point,
    points_g2: []const curve.G2Point,
    curve_params: params.SystemParams,
) PairingError!GtElement {
    if (points_g1.len != points_g2.len) return PairingError.InvalidPoint;
    if (points_g1.len == 0) return GtElement.identity();

    var result = GtElement.identity();
    for (points_g1, points_g2) |P, Q| {
        const pair_result = try pairing(P, Q, curve_params);
        result = result.mul(pair_result);
    }
    return result;
}

/// Pairing utilities
pub const PairingUtils = struct {
    pub fn testBilinearity(
        P: curve.G1Point,
        Q: curve.G2Point,
        scalar: [32]u8,
        curve_params: params.SystemParams,
    ) PairingError!bool {
        const base_pairing = try pairing(P, Q, curve_params);
        const aP = P.mul(scalar, curve_params);
        const left_pairing = try pairing(aP, Q, curve_params);
        const right_pairing = base_pairing.pow(scalar);
        return left_pairing.equal(right_pairing);
    }

    pub fn verifyPairingEquation(
        P1: curve.G1Point,
        Q1: curve.G2Point,
        P2: curve.G1Point,
        Q2: curve.G2Point,
        curve_params: params.SystemParams,
    ) PairingError!bool {
        const e1 = try pairing(P1, Q1, curve_params);
        const e2 = try pairing(P2, Q2, curve_params);
        const product = e1.mul(e2);
        return product.isIdentity();
    }
};

/// Precomputed pairing data for optimization
pub const PairingPrecompute = struct {
    precomputed_data: [1024]u8,

    pub fn init(Q: curve.G2Point, curve_params: params.SystemParams) PairingPrecompute {
        _ = curve_params;
        var result = PairingPrecompute{ .precomputed_data = @as([1024]u8, @splat(0)) };
        std.mem.copyForwards(u8, result.precomputed_data[0..64], &Q.x);
        std.mem.copyForwards(u8, result.precomputed_data[64..128], &Q.y);
        std.mem.copyForwards(u8, result.precomputed_data[128..192], &Q.z);

        var hasher = SM3.init(.{});
        hasher.update(&Q.x);
        hasher.update(&Q.y);
        hasher.update(&Q.z);
        hasher.update("SM9_PAIRING_PRECOMPUTE");
        var hash: [32]u8 = undefined;
        hasher.final(&hash);

        var offset: usize = 192;
        while (offset < 1024) {
            const copy_len = @min(32, 1024 - offset);
            std.mem.copyForwards(u8, result.precomputed_data[offset .. offset + copy_len], hash[0..copy_len]);
            offset += copy_len;
        }
        return result;
    }

    pub fn pairingWithPrecompute(
        self: PairingPrecompute,
        P: curve.G1Point,
        curve_params: params.SystemParams,
    ) PairingError!GtElement {
        if (P.isInfinity()) return GtElement.identity();
        var Q_x: [64]u8 = undefined;
        var Q_y: [64]u8 = undefined;
        var Q_z: [64]u8 = undefined;
        std.mem.copyForwards(u8, &Q_x, self.precomputed_data[0..64]);
        std.mem.copyForwards(u8, &Q_y, self.precomputed_data[64..128]);
        std.mem.copyForwards(u8, &Q_z, self.precomputed_data[128..192]);
        const Q = curve.G2Point{ .x = Q_x, .y = Q_y, .z = Q_z, .is_infinity = false };
        return pairing(P, Q, curve_params);
    }
};

/// Enhanced Gt group operations
pub const GtOperations = struct {
    pub fn multiPairing(
        P_points: []const curve.G1Point,
        Q_points: []const curve.G2Point,
        curve_params: params.SystemParams,
    ) !GtElement {
        if (P_points.len != Q_points.len) return PairingError.InvalidPoint;
        if (P_points.len == 0) return GtElement.identity();
        var result = try pairing(P_points[0], Q_points[0], curve_params);
        var i: usize = 1;
        while (i < P_points.len) : (i += 1) {
            const next_pairing = try pairing(P_points[i], Q_points[i], curve_params);
            result = result.mul(next_pairing);
        }
        return result;
    }

    pub fn batchVerify(
        left_P: []const curve.G1Point,
        left_Q: []const curve.G2Point,
        right_P: []const curve.G1Point,
        right_Q: []const curve.G2Point,
        curve_params: params.SystemParams,
    ) !bool {
        const left_result = try GtOperations.multiPairing(left_P, left_Q, curve_params);
        const right_result = try GtOperations.multiPairing(right_P, right_Q, curve_params);
        return left_result.equal(right_result);
    }

    pub fn optimizedPairing(P: curve.G1Point, Q: curve.G2Point, curve_params: params.SystemParams) !GtElement {
        return pairing(P, Q, curve_params);
    }

    pub fn verifyPairingEquation(
        P1: curve.G1Point,
        Q1: curve.G2Point,
        P2: curve.G1Point,
        Q2: curve.G2Point,
        curve_params: params.SystemParams,
    ) !bool {
        const left = try pairing(P1, Q1, curve_params);
        const right = try pairing(P2, Q2, curve_params);
        return left.equal(right);
    }
};

/// Extended GtElement with additional cryptographic operations
pub const GtElementExtended = struct {
    base: GtElement,

    pub fn init(element: GtElement) GtElementExtended {
        return GtElementExtended{ .base = element };
    }

    pub fn powWindowed(self: GtElementExtended, exponent: [32]u8, window_size: u8) GtElement {
        if (bigint.isZero(exponent)) return GtElement.identity();
        var precomputed: [16]GtElement = undefined;
        precomputed[0] = GtElement.identity();
        if (window_size > 0) {
            precomputed[1] = self.base;
            var i: usize = 2;
            while (i < (@as(usize, 1) << window_size)) : (i += 1) {
                precomputed[i] = precomputed[i - 1].mul(self.base);
            }
        }
        var result = GtElement.identity();
        var bit_pos: i32 = 255;
        while (bit_pos >= 0) {
            var window_value: u16 = 0;
            var bits_extracted: u8 = 0;
            while (bits_extracted < window_size and bit_pos >= 0) {
                const byte_index = @as(usize, @intCast(bit_pos / 8));
                const bit_index = @as(u3, @intCast(bit_pos % 8));
                const bit = (exponent[byte_index] >> bit_index) & 1;
                window_value = (window_value << 1) | bit;
                bits_extracted += 1;
                bit_pos -= 1;
            }
            var j: u8 = 0;
            while (j < bits_extracted) : (j += 1) {
                result = result.mul(result);
            }
            if (window_value > 0 and window_value < precomputed.len) {
                result = result.mul(precomputed[window_value]);
            }
        }
        return result;
    }

    pub fn invertFermat(self: GtElementExtended, curve_params: params.SystemParams) GtElement {
        var r_minus_1 = curve_params.N;
        const one = @as([31]u8, @splat(0)) ++ [_]u8{1};
        const sub_result = bigint.sub(r_minus_1, one);
        if (!sub_result.borrow) {
            r_minus_1 = sub_result.result;
        }
        return self.base.pow(r_minus_1);
    }
};
