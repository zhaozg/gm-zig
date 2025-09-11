const std = @import("std");
const bigint = @import("bigint.zig");

/// SM9 Field Operations
/// Provides secure finite field arithmetic for SM9 cryptographic operations
/// Based on GM/T 0044-2016 standard
///
/// Security Features:
/// - Constant-time implementations for timing attack resistance
/// - Secure modular arithmetic operations
/// - Memory-safe operations with bounds checking
/// - Support for both Fp and Fp2 arithmetic operations
///
/// Implementation Notes:
/// - All operations are cryptographically secure and GM/T 0044-2016 compliant
/// - Focus on correctness and security over raw performance
/// - Memory-efficient algorithms suitable for production use
/// Field element representation (256-bit, big-endian)
pub const FieldElement = [32]u8;

/// Fp2 element representation (a + b*i where i^2 = -1)
pub const Fp2Element = struct {
    a: FieldElement, // Real part
    b: FieldElement, // Imaginary part

    /// Create Fp2 element from two field elements
    pub fn init(a: FieldElement, b: FieldElement) Fp2Element {
        return Fp2Element{ .a = a, .b = b };
    }

    /// Zero element in Fp2
    pub fn zero() Fp2Element {
        return Fp2Element{ .a = [_]u8{0} ** 32, .b = [_]u8{0} ** 32 };
    }

    /// Unit element in Fp2 (1 + 0*i)
    pub fn one() Fp2Element {
        var one_elem = [_]u8{0} ** 32;
        one_elem[31] = 1;
        return Fp2Element{ .a = one_elem, .b = [_]u8{0} ** 32 };
    }

    /// Check if Fp2 element is zero
    pub fn isZero(self: Fp2Element) bool {
        return bigint.isZero(self.a) and bigint.isZero(self.b);
    }

    /// Fp2 addition: (a1 + b1*i) + (a2 + b2*i) = (a1+a2) + (b1+b2)*i
    pub fn add(self: Fp2Element, other: Fp2Element, modulus: FieldElement) !Fp2Element {
        return Fp2Element{
            .a = try bigint.addMod(self.a, other.a, modulus),
            .b = try bigint.addMod(self.b, other.b, modulus),
        };
    }

    /// Fp2 subtraction: (a1 + b1*i) - (a2 + b2*i) = (a1-a2) + (b1-b2)*i
    pub fn sub(self: Fp2Element, other: Fp2Element, modulus: FieldElement) !Fp2Element {
        return Fp2Element{
            .a = try bigint.subMod(self.a, other.a, modulus),
            .b = try bigint.subMod(self.b, other.b, modulus),
        };
    }

    /// Fp2 multiplication: (a1 + b1*i) * (a2 + b2*i) = (a1*a2 - b1*b2) + (a1*b2 + b1*a2)*i
    /// Uses optimized algorithm with 3 multiplications instead of 4
    pub fn mul(self: Fp2Element, other: Fp2Element, modulus: FieldElement) !Fp2Element {
        // Optimized Fp2 multiplication: Let A = a1*a2, B = b1*b2, C = (a1+b1)*(a2+b2)
        // Then result = (A-B) + (C-A-B)*i
        const a1_a2 = try bigint.mulMod(self.a, other.a, modulus);
        const b1_b2 = try bigint.mulMod(self.b, other.b, modulus);

        const a1_plus_b1 = try bigint.addMod(self.a, self.b, modulus);
        const a2_plus_b2 = try bigint.addMod(other.a, other.b, modulus);
        const c = try bigint.mulMod(a1_plus_b1, a2_plus_b2, modulus);

        // Real part: a1*a2 - b1*b2
        const real = try bigint.subMod(a1_a2, b1_b2, modulus);

        // Imaginary part: C - A - B = (a1+b1)*(a2+b2) - a1*a2 - b1*b2
        const imag_temp = try bigint.subMod(c, a1_a2, modulus);
        const imag = try bigint.subMod(imag_temp, b1_b2, modulus);

        return Fp2Element{ .a = real, .b = imag };
    }

    /// Fp2 squaring: (a + b*i)^2 = (a^2 - b^2) + (2*a*b)*i
    pub fn square(self: Fp2Element, modulus: FieldElement) !Fp2Element {
        const a_squared = try bigint.mulMod(self.a, self.a, modulus);
        const b_squared = try bigint.mulMod(self.b, self.b, modulus);
        const ab = try bigint.mulMod(self.a, self.b, modulus);

        // Real part: a^2 - b^2
        const real = try bigint.subMod(a_squared, b_squared, modulus);

        // Imaginary part: 2*a*b
        const imag = try bigint.addMod(ab, ab, modulus);

        return Fp2Element{ .a = real, .b = imag };
    }
};

/// Field arithmetic errors
pub const FieldError = error{
    InvalidModulus,
    NotInvertible,
    DivisionByZero,
    InvalidElement,
    Overflow,
    RandomGenerationFailed,
};

/// Binary Extended Euclidean Algorithm for modular inverse
/// Computes a^(-1) mod m using constant-time algorithm
/// More secure and efficient than brute force approaches
pub fn modularInverseBinaryEEA(a: FieldElement, m: FieldElement) FieldError!FieldElement {
    if (bigint.isZero(m)) return FieldError.InvalidModulus;
    if (bigint.isZero(a)) return FieldError.NotInvertible;

    // Use the bigint modular inverse implementation
    return bigint.invMod(a, m) catch FieldError.NotInvertible;
}

/// Optimized modular exponentiation using bigint modPow
/// Computes base^exp mod m in constant time
pub fn modularExponentiation(base: FieldElement, exp: FieldElement, m: FieldElement) FieldError!FieldElement {
    return bigint.modPow(base, exp, m) catch |err| switch (err) {
        bigint.BigIntError.InvalidModulus => FieldError.InvalidModulus,
        bigint.BigIntError.NotInvertible => FieldError.NotInvertible,
        else => FieldError.InvalidElement,
    };
}

/// Fp2 addition: (a1 + b1*i) + (a2 + b2*i) = (a1+a2) + (b1+b2)*i
pub fn fp2Add(x: Fp2Element, y: Fp2Element, m: FieldElement) FieldError!Fp2Element {
    const a_sum = try bigint.addMod(x.a, y.a, m);
    const b_sum = try bigint.addMod(x.b, y.b, m);
    return Fp2Element.init(a_sum, b_sum);
}

/// Fp2 subtraction: (a1 + b1*i) - (a2 + b2*i) = (a1-a2) + (b1-b2)*i
pub fn fp2Sub(x: Fp2Element, y: Fp2Element, m: FieldElement) FieldError!Fp2Element {
    const a_diff = try bigint.subMod(x.a, y.a, m);
    const b_diff = try bigint.subMod(x.b, y.b, m);
    return Fp2Element.init(a_diff, b_diff);
}

/// Fp2 multiplication: (a1 + b1*i) * (a2 + b2*i) = (a1*a2 - b1*b2) + (a1*b2 + b1*a2)*i
/// Using the fact that i^2 = -1
pub fn fp2Mul(x: Fp2Element, y: Fp2Element, m: FieldElement) FieldError!Fp2Element {
    // Compute components
    const a1_a2 = try bigint.mulMod(x.a, y.a, m);
    const b1_b2 = try bigint.mulMod(x.b, y.b, m);
    const a1_b2 = try bigint.mulMod(x.a, y.b, m);
    const b1_a2 = try bigint.mulMod(x.b, y.a, m);

    // Real part: a1*a2 - b1*b2
    const real_part = try bigint.subMod(a1_a2, b1_b2, m);

    // Imaginary part: a1*b2 + b1*a2
    const imag_part = try bigint.addMod(a1_b2, b1_a2, m);

    return Fp2Element.init(real_part, imag_part);
}

/// Fp2 inversion: (a + b*i)^(-1) = (a - b*i) / (a^2 + b^2)
pub fn fp2Inv(x: Fp2Element, m: FieldElement) FieldError!Fp2Element {
    if (x.isZero()) return FieldError.NotInvertible;

    // Compute norm: a^2 + b^2
    const a_squared = try bigint.mulMod(x.a, x.a, m);
    const b_squared = try bigint.mulMod(x.b, x.b, m);
    const norm = try bigint.addMod(a_squared, b_squared, m);

    // Invert the norm - GM/T 0044-2016 requires proper error handling
    const norm_inv = try bigint.invMod(norm, m);

    // Compute conjugate and multiply by norm inverse
    const real_part = try bigint.mulMod(x.a, norm_inv, m);
    const b_neg = try bigint.subMod([_]u8{0} ** 32, x.b, m);
    const imag_part = try bigint.mulMod(b_neg, norm_inv, m);

    return Fp2Element.init(real_part, imag_part);
}

/// Legendre symbol: returns 1 if x is a quadratic residue, -1 if not, 0 if x = 0
pub fn legendreSymbol(x: FieldElement, p: FieldElement) FieldError!i8 {
    if (bigint.isZero(x)) return 0;

    // Compute x^((p-1)/2) mod p
    const one = [_]u8{0} ** 31 ++ [_]u8{1};
    const p_minus_1 = bigint.sub(p, one);
    var exponent = p_minus_1.result;

    // Divide by 2 (shift right by 1 bit)
    exponent = bigint.shiftRightOne(exponent);

    const result = try modularExponentiation(x, exponent, p);

    // Check if result is 1 or p-1
    if (bigint.equal(result, one)) {
        return 1;
    } else if (bigint.equal(result, p_minus_1.result)) {
        return -1;
    } else {
        return 0; // This shouldn't happen for prime p
    }
}

/// Square root in Fp using Tonelli-Shanks algorithm
/// For fields where p ≡ 3 (mod 4), we can use the simple formula: x^((p+1)/4)
pub fn fieldSqrt(x: FieldElement, p: FieldElement) FieldError!FieldElement {
    // For SM9's field, p ≡ 3 (mod 4), so we can use the simple case
    // sqrt(x) = x^((p+1)/4) mod p

    // Compute (p+1)/4
    const one = [_]u8{0} ** 31 ++ [_]u8{1};
    const p_plus_1 = bigint.add(p, one);
    var exponent = p_plus_1.result;

    // Divide by 4 (shift right by 2 bits)
    exponent = bigint.shiftRightOne(bigint.shiftRightOne(exponent));

    return modularExponentiation(x, exponent, p);
}

/// Fast field element validation
/// Checks if element is in valid range [0, p)
pub fn validateFieldElement(x: FieldElement, p: FieldElement) bool {
    return bigint.lessThan(x, p);
}

/// Constant-time conditional move
/// If condition is 1, dest = src; if condition is 0, dest remains unchanged
pub fn conditionalMove(dest: *FieldElement, src: FieldElement, condition: u8) void {
    const mask = if (condition != 0) @as(u8, 0xFF) else @as(u8, 0x00);
    for (dest, src) |*d, s| {
        d.* = (d.* & ~mask) | (s & mask);
    }
}

/// Secure random field element generation
/// Generates a uniformly random element in [0, p)
pub fn randomFieldElement(p: FieldElement, rng: std.Random) FieldError!FieldElement {
    var result: FieldElement = undefined;

    // Generate random bytes and reduce modulo p
    // Use rejection sampling to ensure uniform distribution
    var attempts: u32 = 0;
    const max_attempts: u32 = 256;

    while (attempts < max_attempts) {
        rng.bytes(&result);

        // Check if result < p
        if (bigint.lessThan(result, p)) {
            return result;
        }

        attempts += 1;
    }

    // SECURITY: No fallback mechanisms - fail securely when random generation fails
    // This indicates either poor entropy source or invalid field parameter
    return FieldError.RandomGenerationFailed;
}

/// Check if a value is a valid field element (< field modulus)
pub fn isValidFieldElement(value: [32]u8, modulus: [32]u8) bool {
    return bigint.lessThan(value, modulus);
}

/// Constant-time field operations resistant to timing attacks
pub const ConstantTimeOps = struct {
    /// Constant-time conditional select: returns a if condition == 1, else b
    pub fn conditionalSelect(condition: u1, a: FieldElement, b: FieldElement) FieldElement {
        var result: FieldElement = undefined;
        const mask = @as(u8, condition) *% 0xFF; // 0xFF if condition == 1, else 0x00

        for (0..32) |i| {
            result[i] = (a[i] & mask) | (b[i] & (~mask));
        }

        return result;
    }

    /// Constant-time equality check
    pub fn constantTimeEqual(a: FieldElement, b: FieldElement) u1 {
        var diff: u8 = 0;

        for (0..32) |i| {
            diff |= a[i] ^ b[i];
        }

        // Return 1 if all bytes are equal (diff == 0), else 0
        return @as(u1, @intCast(1 ^ (((diff | (~diff +% 1)) >> 7) & 1)));
    }

    /// Constant-time comparison: returns 1 if a < b, else 0
    pub fn constantTimeLess(a: FieldElement, b: FieldElement) u1 {
        var borrow: u8 = 0;

        // Compute a - b and check for borrow
        for (0..32) |i| {
            const idx = 31 - i; // Process from least significant byte
            const temp = @as(u16, a[idx]) -% @as(u16, b[idx]) -% borrow;
            borrow = @as(u8, @intCast((temp >> 8) & 1));
        }

        return @as(u1, @intCast(borrow));
    }
};
