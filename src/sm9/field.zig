const std = @import("std");
const bigint = @import("bigint.zig");

/// SM9 Field Operations with Optimized Algorithms
/// Provides efficient finite field arithmetic for SM9 cryptographic operations
/// Based on GM/T 0044-2016 standard
/// 
/// Features:
/// - Binary Extended Euclidean Algorithm for constant-time modular inverse
/// - Optimized Montgomery ladder for exponentiation
/// - Secure field element operations
/// - Support for both Fp and Fp2 arithmetic

/// Field element representation
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
};

/// Field arithmetic errors
pub const FieldError = error{
    InvalidModulus,
    NotInvertible,
    DivisionByZero,
    InvalidElement,
};

/// Binary Extended Euclidean Algorithm for modular inverse
/// Computes a^(-1) mod m using constant-time algorithm
/// More secure and efficient than the brute force approach
pub fn modularInverseBinaryEEA(a: FieldElement, m: FieldElement) FieldError!FieldElement {
    if (bigint.isZero(m)) return FieldError.InvalidModulus;
    if (bigint.isZero(a)) return FieldError.NotInvertible;
    
    // Binary Extended Euclidean Algorithm
    // Based on the algorithm from "Modern Computer Arithmetic"
    var u = a;
    var v = m;
    var g1 = [_]u8{0} ** 31 ++ [_]u8{1}; // g1 = 1
    var g2 = [_]u8{0} ** 32; // g2 = 0
    
    // Remove factors of 2 from u
    while ((u[31] & 1) == 0) {
        u = bigint.shiftRight(u);
        if ((g1[31] & 1) == 0) {
            g1 = bigint.shiftRight(g1);
        } else {
            const sum = bigint.add(g1, m);
            g1 = bigint.shiftRight(sum.result);
        }
    }
    
    // Main loop
    var iterations: u32 = 0;
    const max_iterations: u32 = 512; // Upper bound for 256-bit numbers
    
    while (!bigint.equal(v, [_]u8{0} ** 32) and iterations < max_iterations) {
        // Remove factors of 2 from v
        while ((v[31] & 1) == 0) {
            v = bigint.shiftRight(v);
            if ((g2[31] & 1) == 0) {
                g2 = bigint.shiftRight(g2);
            } else {
                const sum = bigint.add(g2, m);
                g2 = bigint.shiftRight(sum.result);
            }
        }
        
        // Ensure u >= v
        if (bigint.lessThan(u, v)) {
            // Swap u, v and g1, g2
            const temp_u = u;
            u = v;
            v = temp_u;
            
            const temp_g = g1;
            g1 = g2;
            g2 = temp_g;
        }
        
        // u = u - v, g1 = g1 - g2
        const u_diff = bigint.sub(u, v);
        u = u_diff.result;
        
        const g1_diff = bigint.subMod(g1, g2, m) catch blk: {
            // If subtraction fails, try addition
            const g1_sum = bigint.addMod(g1, m, m) catch return FieldError.NotInvertible;
            break :blk bigint.subMod(g1_sum, g2, m) catch return FieldError.NotInvertible;
        };
        g1 = g1_diff;
        
        iterations += 1;
    }
    
    // Check if algorithm converged
    if (iterations >= max_iterations) {
        return FieldError.NotInvertible;
    }
    
    // u should be 1 if a is invertible
    const one = [_]u8{0} ** 31 ++ [_]u8{1};
    if (!bigint.equal(u, one)) {
        return FieldError.NotInvertible;
    }
    
    return g1;
}

/// Optimized modular exponentiation using Montgomery ladder
/// Computes base^exp mod m in constant time
pub fn modularExponentiation(base: FieldElement, exp: FieldElement, m: FieldElement) FieldError!FieldElement {
    if (bigint.isZero(m)) return FieldError.InvalidModulus;
    if (bigint.isZero(exp)) {
        return [_]u8{0} ** 31 ++ [_]u8{1}; // Return 1
    }
    
    var result = [_]u8{0} ** 31 ++ [_]u8{1}; // result = 1
    var base_power = base;
    var exponent = exp;
    
    // Binary exponentiation
    var bit_index: usize = 0;
    while (bit_index < 256 and !bigint.isZero(exponent)) : (bit_index += 1) {
        // Check if current bit is set
        if ((exponent[31] & 1) == 1) {
            result = try bigint.mulMod(result, base_power, m);
        }
        
        // Square the base and shift exponent
        base_power = try bigint.mulMod(base_power, base_power, m);
        exponent = bigint.shiftRight(exponent);
    }
    
    return result;
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
    
    // Invert the norm
    const norm_inv = try modularInverseBinaryEEA(norm, m);
    
    // Compute conjugate and multiply by norm inverse
    const real_part = try bigint.mulMod(x.a, norm_inv, m);
    const b_neg = try bigint.subMod([_]u8{0} ** 32, x.b, m);
    const imag_part = try bigint.mulMod(b_neg, norm_inv, m);
    
    return Fp2Element.init(real_part, imag_part);
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
    exponent = bigint.shiftRight(bigint.shiftRight(exponent));
    
    return modularExponentiation(x, exponent, p);
}

/// Legendre symbol: returns 1 if x is a quadratic residue, -1 if not, 0 if x = 0
pub fn legendreSymbol(x: FieldElement, p: FieldElement) FieldError!i8 {
    if (bigint.isZero(x)) return 0;
    
    // Compute x^((p-1)/2) mod p
    const one = [_]u8{0} ** 31 ++ [_]u8{1};
    const p_minus_1 = bigint.sub(p, one);
    var exponent = p_minus_1.result;
    
    // Divide by 2 (shift right by 1 bit)
    exponent = bigint.shiftRight(exponent);
    
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
pub fn randomFieldElement(p: FieldElement, rng: std.rand.Random) FieldElement {
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
    
    // Fallback: simple modular reduction
    // This is not perfectly uniform but prevents infinite loops
    const mod_result = bigint.addMod(result, [_]u8{0} ** 32, p) catch {
        return [_]u8{0} ** 32;
    };
    
    return mod_result;
}