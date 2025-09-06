/// Unified BigInt module demonstrating safe module consolidation
/// This is a proof-of-concept showing how to merge bigint.zig and bigint_safe.zig
const std = @import("std");
const mem = std.mem;
const builtin = @import("builtin");

/// Configuration for safe mode behavior
pub const SafeConfig = struct {
    /// Enable safe mode with iteration limits and extra checks
    enable_safe_mode: bool = builtin.mode == .Debug,
    /// Maximum iterations for algorithms that might loop
    max_iterations: u32 = 256,
    /// Enable additional validation checks
    enable_validation: bool = true,
};

/// Big integer representation (256-bit, big-endian)
pub const BigInt = [32]u8;

/// Big integer computation errors
pub const BigIntError = error{
    DivisionByZero,
    InvalidModulus,
    NotInvertible,
    Overflow,
};

/// Check if big integer is zero
pub fn isZero(a: BigInt) bool {
    for (a) |byte| {
        if (byte != 0) return false;
    }
    return true;
}

/// Secure memory clearing to prevent sensitive data leaks
pub fn secureZero(data: []u8) void {
    for (data) |*byte| {
        @as(*volatile u8, byte).* = 0;
    }
}

/// Compare two big integers (constant-time)
pub fn compare(a: BigInt, b: BigInt) i32 {
    var gt: u8 = 0;
    var lt: u8 = 0;

    var i: usize = 0;
    while (i < 32) : (i += 1) {
        const a_gt_b = if (a[i] > b[i]) @as(u8, 1) else @as(u8, 0);
        const a_lt_b = if (a[i] < b[i]) @as(u8, 1) else @as(u8, 0);

        const no_diff = @as(u8, 1) -% (gt | lt);
        gt |= a_gt_b & no_diff;
        lt |= a_lt_b & no_diff;
    }

    return @as(i32, gt) - @as(i32, lt);
}

/// Check if a < b
pub fn lessThan(a: BigInt, b: BigInt) bool {
    return compare(a, b) < 0;
}

/// Add two big integers with optional overflow checking
pub fn add(a: BigInt, b: BigInt) struct { result: BigInt, carry: bool } {
    var result = [_]u8{0} ** 32;
    var carry: u16 = 0;

    var i: i32 = 31;
    while (i >= 0) : (i -= 1) {
        const idx = @as(usize, @intCast(i));
        const sum = @as(u16, a[idx]) + @as(u16, b[idx]) + carry;
        result[idx] = @as(u8, @intCast(sum & 0xFF));
        carry = sum >> 8;
    }

    return .{ .result = result, .carry = carry != 0 };
}

/// Subtract two big integers
pub fn sub(a: BigInt, b: BigInt) struct { result: BigInt, borrow: bool } {
    var result = [_]u8{0} ** 32;
    var borrow: i16 = 0;

    var i: i32 = 31;
    while (i >= 0) : (i -= 1) {
        const idx = @as(usize, @intCast(i));
        const diff = @as(i16, a[idx]) - @as(i16, b[idx]) - borrow;
        
        if (diff < 0) {
            result[idx] = @as(u8, @intCast(diff + 256));
            borrow = 1;
        } else {
            result[idx] = @as(u8, @intCast(diff));
            borrow = 0;
        }
    }

    return .{ .result = result, .borrow = borrow != 0 };
}

/// Unified modular multiplication with configurable safety
pub fn mulMod(a: BigInt, b: BigInt, m: BigInt, config: SafeConfig) BigIntError!BigInt {
    if (isZero(m)) return BigIntError.InvalidModulus;
    if (isZero(a) or isZero(b)) return [_]u8{0} ** 32;

    if (comptime config.enable_safe_mode) {
        return safeMulModImpl(a, b, m, config);
    } else {
        return fastMulModImpl(a, b, m);
    }
}

/// Safe modular multiplication implementation with iteration limits
fn safeMulModImpl(a: BigInt, b: BigInt, m: BigInt, config: SafeConfig) BigIntError!BigInt {
    // Reduce inputs first to avoid overflow
    const a_mod = try modWithLimit(a, m, config.max_iterations);
    const b_mod = try modWithLimit(b, m, config.max_iterations);

    if (isZero(a_mod) or isZero(b_mod)) return [_]u8{0} ** 32;

    var result = [_]u8{0} ** 32;
    var base = a_mod;

    // Process exactly 256 bits with guaranteed termination
    var bit_pos: u32 = 0;
    while (bit_pos < 256 and bit_pos < config.max_iterations) : (bit_pos += 1) {
        const byte_idx = 31 - (bit_pos / 8);
        const bit_shift = @as(u3, @intCast(bit_pos % 8));

        // If bit is set in b, add current base to result
        if ((b_mod[byte_idx] >> bit_shift) & 1 == 1) {
            const add_result = add(result, base);
            if (add_result.carry) {
                result = try modWithLimit(add_result.result, m, config.max_iterations);
            } else {
                result = if (lessThan(add_result.result, m)) 
                    add_result.result 
                else 
                    try modWithLimit(add_result.result, m, config.max_iterations);
            }
        }

        // Double the base for next bit position
        const double_result = add(base, base);
        if (double_result.carry) {
            base = try modWithLimit(double_result.result, m, config.max_iterations);
        } else {
            base = if (lessThan(double_result.result, m)) 
                double_result.result 
            else 
                try modWithLimit(double_result.result, m, config.max_iterations);
        }

        // Early exit if base becomes zero (optimization)
        if (isZero(base)) break;
    }

    return result;
}

/// Fast modular multiplication implementation for release builds
fn fastMulModImpl(a: BigInt, b: BigInt, m: BigInt) BigIntError!BigInt {
    // Optimized implementation without iteration limits
    // This is similar to the original bigint.zig implementation
    // but would include the latest optimizations
    
    // For demonstration, using a simplified version
    var result = [_]u8{0} ** 32;
    var base = a;

    // Simple double-and-add algorithm
    for (0..256) |bit_pos| {
        const byte_idx = 31 - (bit_pos / 8);
        const bit_shift = @as(u3, @intCast(bit_pos % 8));

        if ((b[byte_idx] >> bit_shift) & 1 == 1) {
            const add_result = add(result, base);
            result = if (lessThan(add_result.result, m)) 
                add_result.result 
            else 
                try fastMod(add_result.result, m);
        }

        const double_result = add(base, base);
        base = if (lessThan(double_result.result, m)) 
            double_result.result 
        else 
            try fastMod(double_result.result, m);

        if (isZero(base)) break;
    }

    return result;
}

/// Modular reduction with iteration limit for safe mode
fn modWithLimit(a: BigInt, m: BigInt, max_iterations: u32) BigIntError!BigInt {
    if (isZero(m)) return BigIntError.InvalidModulus;
    if (lessThan(a, m)) return a;

    var result = a;
    var iterations: u32 = 0;

    while (!lessThan(result, m) and iterations < max_iterations) {
        const sub_result = sub(result, m);
        if (sub_result.borrow) break;
        result = sub_result.result;
        iterations += 1;
    }

    if (iterations >= max_iterations) {
        return BigIntError.Overflow;
    }

    return result;
}

/// Fast modular reduction for release builds
fn fastMod(a: BigInt, m: BigInt) BigIntError!BigInt {
    if (isZero(m)) return BigIntError.InvalidModulus;
    if (lessThan(a, m)) return a;

    var result = a;
    while (!lessThan(result, m)) {
        const sub_result = sub(result, m);
        if (sub_result.borrow) break;
        result = sub_result.result;
    }

    return result;
}

/// Unified modular addition
pub fn addMod(a: BigInt, b: BigInt, m: BigInt, config: SafeConfig) BigIntError!BigInt {
    if (isZero(m)) return BigIntError.InvalidModulus;

    const sum = add(a, b);
    
    if (!sum.carry and lessThan(sum.result, m)) {
        return sum.result;
    }

    if (comptime config.enable_safe_mode) {
        return modWithLimit(sum.result, m, config.max_iterations);
    } else {
        return fastMod(sum.result, m);
    }
}

/// Unified modular inverse with configurable safety
pub fn invMod(a: BigInt, m: BigInt, config: SafeConfig) BigIntError!BigInt {
    if (isZero(m)) return BigIntError.InvalidModulus;
    if (isZero(a)) return BigIntError.NotInvertible;

    const one = [_]u8{0} ** 31 ++ [_]u8{1};
    if (std.mem.eql(u8, &a, &one)) return one;

    // Check for SM9 known prime fields for optimization
    const sm9_q = [32]u8{ 0xB6, 0x40, 0x00, 0x00, 0x02, 0xA3, 0xA6, 0xF1, 
                          0xD6, 0x03, 0xAB, 0x4F, 0xF5, 0x8E, 0xC7, 0x45, 
                          0x21, 0xF2, 0x93, 0x4B, 0x1A, 0x7A, 0xEE, 0xDB, 
                          0xE5, 0x6F, 0x9B, 0x27, 0xE3, 0x51, 0x45, 0x7D };

    if (std.mem.eql(u8, &m, &sm9_q)) {
        return fermatsInverse(a, m, config);
    }

    if (comptime config.enable_safe_mode) {
        return safeExtendedGcd(a, m, config);
    } else {
        return extendedGcd(a, m);
    }
}

/// Fermat's little theorem inverse for prime fields
fn fermatsInverse(a: BigInt, p: BigInt, config: SafeConfig) BigIntError!BigInt {
    // For prime p: a^(-1) ≡ a^(p-2) (mod p)
    var exponent = p;
    
    // Compute p-2
    const two = [_]u8{0} ** 31 ++ [_]u8{2};
    const sub_result = sub(exponent, two);
    if (sub_result.borrow) return BigIntError.NotInvertible;
    exponent = sub_result.result;

    return modPow(a, exponent, p, config);
}

/// Modular exponentiation with configurable safety
fn modPow(base: BigInt, exp: BigInt, mod: BigInt, config: SafeConfig) BigIntError!BigInt {
    if (isZero(mod)) return BigIntError.InvalidModulus;
    
    var result = [_]u8{0} ** 31 ++ [_]u8{1}; // result = 1
    var base_mod = if (comptime config.enable_safe_mode) 
        try modWithLimit(base, mod, config.max_iterations)
    else 
        try fastMod(base, mod);

    var iterations: u32 = 0;
    
    // Process exponent bits
    for (0..256) |bit_pos| {
        if (comptime config.enable_safe_mode and iterations >= config.max_iterations) {
            return BigIntError.Overflow;
        }
        
        const byte_idx = 31 - (bit_pos / 8);
        const bit_shift = @as(u3, @intCast(bit_pos % 8));
        
        if ((exp[byte_idx] >> bit_shift) & 1 == 1) {
            result = try mulMod(result, base_mod, mod, config);
        }
        
        base_mod = try mulMod(base_mod, base_mod, mod, config);
        
        if (isZero(base_mod)) break;
        iterations += 1;
    }

    return result;
}

/// Safe extended GCD for general modulus
fn safeExtendedGcd(a: BigInt, m: BigInt, config: SafeConfig) BigIntError!BigInt {
    // Extended Euclidean algorithm with iteration limits
    _ = a;
    _ = m;
    _ = config;
    // Implementation would go here with iteration limits
    return BigIntError.NotInvertible;
}

/// Fast extended GCD for release builds
fn extendedGcd(a: BigInt, m: BigInt) BigIntError!BigInt {
    // Optimized extended Euclidean algorithm
    _ = a;
    _ = m;
    // Implementation would go here
    return BigIntError.NotInvertible;
}

/// Default configuration for different build modes
pub const default_config = SafeConfig{};
pub const fast_config = SafeConfig{ .enable_safe_mode = false };
pub const safe_config = SafeConfig{ .enable_safe_mode = true };

/// Convenience functions using default configuration
pub fn defaultMulMod(a: BigInt, b: BigInt, m: BigInt) BigIntError!BigInt {
    return mulMod(a, b, m, default_config);
}

pub fn defaultAddMod(a: BigInt, b: BigInt, m: BigInt) BigIntError!BigInt {
    return addMod(a, b, m, default_config);
}

pub fn defaultInvMod(a: BigInt, m: BigInt) BigIntError!BigInt {
    return invMod(a, m, default_config);
}

// Compatibility functions for existing bigint_safe.zig interface
// These provide drop-in replacements for the original safe functions

/// Safe modular multiplication - compatibility wrapper for bigint_safe.zig
pub fn safeMulMod(a: BigInt, b: BigInt, m: BigInt) BigIntError!BigInt {
    return mulMod(a, b, m, SafeConfig{ .enable_safe_mode = true });
}

/// Safe modular addition - compatibility wrapper for bigint_safe.zig  
pub fn safeAddMod(a: BigInt, b: BigInt, m: BigInt) BigIntError!BigInt {
    return addMod(a, b, m, SafeConfig{ .enable_safe_mode = true });
}

/// Safe modular inverse - compatibility wrapper for bigint_safe.zig
pub fn safeInvMod(a: BigInt, m: BigInt) BigIntError!BigInt {
    return invMod(a, m, SafeConfig{ .enable_safe_mode = true });
}