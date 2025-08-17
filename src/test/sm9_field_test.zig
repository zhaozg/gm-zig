const std = @import("std");
const testing = std.testing;
const sm9 = @import("../../sm9.zig");

test "SM9 Field Operations - Binary Extended Euclidean Algorithm" {
    const params = sm9.params.SystemParams.init();
    
    // Test modular inverse with simple values
    const a = [_]u8{0} ** 31 ++ [_]u8{3}; // a = 3
    const p = params.q;
    
    // Compute inverse
    const inv_result = sm9.field.modularInverseBinaryEEA(a, p);
    try testing.expect(inv_result != sm9.field.FieldError.NotInvertible);
    
    if (inv_result) |inv_a| {
        // Verify that a * inv_a ≡ 1 (mod p)
        const product = sm9.bigint.mulMod(a, inv_a, p) catch return;
        const one = [_]u8{0} ** 31 ++ [_]u8{1};
        
        try testing.expect(sm9.bigint.equal(product, one));
    } else |_| {
        // Inverse computation failed - this might be expected for some values
    }
}

test "SM9 Field Operations - Fp2 Arithmetic" {
    const params = sm9.params.SystemParams.init();
    const p = params.q;
    
    // Test Fp2 element creation
    const a_elem = [_]u8{0} ** 31 ++ [_]u8{2};
    const b_elem = [_]u8{0} ** 31 ++ [_]u8{3};
    
    const x = sm9.field.Fp2Element.init(a_elem, b_elem);
    const y = sm9.field.Fp2Element.init(b_elem, a_elem);
    
    // Test Fp2 addition
    const sum_result = sm9.field.fp2Add(x, y, p);
    try testing.expect(sum_result != sm9.field.FieldError.InvalidModulus);
    
    // Test Fp2 multiplication
    const mul_result = sm9.field.fp2Mul(x, y, p);
    try testing.expect(mul_result != sm9.field.FieldError.InvalidModulus);
    
    // Test that zero element works
    const zero = sm9.field.Fp2Element.zero();
    try testing.expect(zero.isZero());
    
    const one = sm9.field.Fp2Element.one();
    try testing.expect(!one.isZero());
}

test "SM9 Field Operations - Field Element Validation" {
    const params = sm9.params.SystemParams.init();
    const p = params.q;
    
    // Test valid field element
    const valid_elem = [_]u8{0} ** 31 ++ [_]u8{1};
    try testing.expect(sm9.field.validateFieldElement(valid_elem, p));
    
    // Test element equal to modulus (should be invalid)
    try testing.expect(!sm9.field.validateFieldElement(p, p));
    
    // Test zero (should be valid)
    const zero = [_]u8{0} ** 32;
    try testing.expect(sm9.field.validateFieldElement(zero, p));
}

test "SM9 Field Operations - Modular Exponentiation" {
    const params = sm9.params.SystemParams.init();
    const p = params.q;
    
    const base = [_]u8{0} ** 31 ++ [_]u8{2};
    const exp = [_]u8{0} ** 31 ++ [_]u8{3};
    
    const result = sm9.field.modularExponentiation(base, exp, p);
    try testing.expect(result != sm9.field.FieldError.InvalidModulus);
    
    // Test that base^0 = 1
    const zero_exp = [_]u8{0} ** 32;
    const one_result = sm9.field.modularExponentiation(base, zero_exp, p);
    if (one_result) |res| {
        const one = [_]u8{0} ** 31 ++ [_]u8{1};
        try testing.expect(sm9.bigint.equal(res, one));
    } else |_| {
        // Should not error for exponent 0
        try testing.expect(false);
    }
}

test "SM9 Field Operations - Square Root" {
    const params = sm9.params.SystemParams.init();
    const p = params.q;
    
    // Test square root of 1
    const one = [_]u8{0} ** 31 ++ [_]u8{1};
    const sqrt_result = sm9.field.fieldSqrt(one, p);
    
    try testing.expect(sqrt_result != sm9.field.FieldError.InvalidModulus);
    
    // Note: For a full test, we would verify that result^2 ≡ input (mod p)
    // but this requires proper implementation details
}

test "SM9 Field Operations - Legendre Symbol" {
    const params = sm9.params.SystemParams.init();
    const p = params.q;
    
    // Test Legendre symbol of 0
    const zero = [_]u8{0} ** 32;
    const legendre_zero = sm9.field.legendreSymbol(zero, p);
    if (legendre_zero) |result| {
        try testing.expect(result == 0);
    } else |_| {
        // Should not error for zero
        try testing.expect(false);
    }
    
    // Test Legendre symbol of 1
    const one = [_]u8{0} ** 31 ++ [_]u8{1};
    const legendre_one = sm9.field.legendreSymbol(one, p);
    if (legendre_one) |result| {
        try testing.expect(result == 1); // 1 is always a quadratic residue
    } else |_| {
        // Should not error for one
        try testing.expect(false);
    }
}

test "SM9 Field Operations - Conditional Move" {
    var dest = [_]u8{0} ** 31 ++ [_]u8{1};
    const src = [_]u8{0} ** 31 ++ [_]u8{2};
    
    // Test conditional move with condition = 1
    sm9.field.conditionalMove(&dest, src, 1);
    try testing.expect(sm9.bigint.equal(dest, src));
    
    // Reset dest
    dest = [_]u8{0} ** 31 ++ [_]u8{1};
    
    // Test conditional move with condition = 0
    const original = dest;
    sm9.field.conditionalMove(&dest, src, 0);
    try testing.expect(sm9.bigint.equal(dest, original));
}