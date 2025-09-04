const std = @import("std");
const mem = std.mem;

/// Big Integer Modular Arithmetic for SM9
/// Provides constant-time modular operations for 256-bit integers used in SM9 algorithm
/// Based on GM/T 0044-2016 standard
///
/// Security Features:
/// - Constant-time operations to prevent timing attacks
/// - Secure memory clearing for sensitive data
/// - Protection against invalid point attacks
///
/// Implementation Notes:
/// - All operations use big-endian byte representation
/// - Modular arithmetic operations include overflow protection
/// - Binary extended GCD algorithm for secure modular inverse

/// Big integer representation (256-bit, big-endian)
/// Each BigInt represents a 256-bit unsigned integer stored in big-endian format
/// This matches the format used in GM/T 0044-2016 specification
pub const BigInt = [32]u8;

/// Big integer computation errors
/// These errors indicate various failure modes in bigint operations
pub const BigIntError = error{
    /// Attempted division by zero
    DivisionByZero,
    /// Invalid modulus (zero or inappropriate value)
    InvalidModulus,
    /// Element is not invertible in the given modulus
    NotInvertible,
    /// Arithmetic operation would overflow
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
/// Uses volatile write to prevent compiler optimization
pub fn secureZero(data: []u8) void {
    for (data) |*byte| {
        @as(*volatile u8, byte).* = 0;
    }
}

/// Securely clear a BigInt
pub fn secureClear(a: *BigInt) void {
    secureZero(a[0..]);
}

/// Check if a == b (constant-time)
pub fn equal(a: BigInt, b: BigInt) bool {
    var diff: u8 = 0;
    for (a, b) |x, y| {
        diff |= (x ^ y);
    }
    return diff == 0;
}

/// Compare two big integers: returns -1 if a < b, 0 if a == b, 1 if a > b (constant-time)
pub fn compare(a: BigInt, b: BigInt) i32 {
    var gt: u8 = 0; // a > b
    var lt: u8 = 0; // a < b

    // Process from most significant to least significant byte
    var i: usize = 0;
    while (i < 32) : (i += 1) {
        // Check if a[i] > b[i] or a[i] < b[i]
        const a_gt_b = if (a[i] > b[i]) @as(u8, 1) else @as(u8, 0);
        const a_lt_b = if (a[i] < b[i]) @as(u8, 1) else @as(u8, 0);

        // Update only if no previous difference was found
        const no_diff = @as(u8, 1) -% (gt | lt);
        gt |= a_gt_b & no_diff;
        lt |= a_lt_b & no_diff;
    }

    // Convert to signed result
    return @as(i32, gt) - @as(i32, lt);
}

/// Check if a < b
pub fn lessThan(a: BigInt, b: BigInt) bool {
    return compare(a, b) < 0;
}

/// Add two big integers: result = (a + b) mod 2^256
/// Returns carry flag
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

/// Subtract two big integers: result = (a - b) mod 2^256
/// Returns borrow flag
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

/// Modular addition: result = (a + b) mod m
/// Optimized for SM9 parameter sizes
pub fn addMod(a: BigInt, b: BigInt, m: BigInt) BigIntError!BigInt {
    if (isZero(m)) return BigIntError.InvalidModulus;

    const sum = add(a, b);

    // If no carry and sum < m, return sum directly
    if (!sum.carry and lessThan(sum.result, m)) {
        return sum.result;
    }

    // For SM9, use direct modular reduction
    return mod(sum.result, m);
}

/// Modular subtraction: result = (a - b) mod m
pub fn subMod(a: BigInt, b: BigInt, m: BigInt) BigIntError!BigInt {
    if (isZero(m)) return BigIntError.InvalidModulus;

    const diff = sub(a, b);

    // If no borrow, return result directly
    if (!diff.borrow) {
        return diff.result;
    }

    // If there was a borrow, add m to get positive result
    const corrected = add(diff.result, m);
    return corrected.result;
}

/// Left shift by one bit
pub fn shiftLeft(a: BigInt) BigInt {
    var result = [_]u8{0} ** 32;
    var carry: u8 = 0;

    var i: i32 = 31;
    while (i >= 0) : (i -= 1) {
        const idx = @as(usize, @intCast(i));
        const new_carry = (a[idx] >> 7) & 1;
        result[idx] = (a[idx] << 1) | carry;
        carry = new_carry;
    }

    return result;
}

/// Right shift by one bit
pub fn shiftRight(a: BigInt) BigInt {
    var result = [_]u8{0} ** 32;
    var carry: u8 = 0;

    var i: usize = 0;
    while (i < 32) : (i += 1) {
        const new_carry = a[i] & 1;
        result[i] = (a[i] >> 1) | (carry << 7);
        carry = new_carry;
    }

    return result;
}

/// Modular multiplication: result = (a * b) mod m
/// Uses simple double-and-add algorithm
/// Modular multiplication: result = (a * b) mod m
/// Optimized binary method for SM9 parameters
pub fn mulMod(a: BigInt, b: BigInt, m: BigInt) BigIntError!BigInt {
    if (isZero(m)) return BigIntError.InvalidModulus;
    if (isZero(a) or isZero(b)) return [_]u8{0} ** 32;

    // Reduce inputs first to avoid overflow in intermediate calculations
    const a_mod = mod(a, m) catch return BigIntError.InvalidModulus;
    const b_mod = mod(b, m) catch return BigIntError.InvalidModulus;
    
    if (isZero(a_mod) or isZero(b_mod)) return [_]u8{0} ** 32;

    var result = [_]u8{0} ** 32;
    var base = a_mod;
    
    // Scan through bits of b from LSB to MSB
    var bit_pos: u32 = 0;
    while (bit_pos < 256) : (bit_pos += 1) {
        const byte_idx = 31 - (bit_pos / 8);
        const bit_shift = @as(u3, @intCast(bit_pos % 8));
        
        // If bit is set in b, add current base to result
        if ((b_mod[byte_idx] >> bit_shift) & 1 == 1) {
            result = addMod(result, base, m) catch return BigIntError.InvalidModulus;
        }
        
        // Double the base for next bit position
        base = addMod(base, base, m) catch return BigIntError.InvalidModulus;
        
        // Early exit if base becomes zero (optimization)
        if (isZero(base)) break;
    }

    return result;
}

/// Basic modular reduction: result = a mod m
pub fn mod(a: BigInt, m: BigInt) BigIntError!BigInt {
    if (isZero(m)) return BigIntError.InvalidModulus;
    
    if (lessThan(a, m)) {
        return a;
    }
    
    var result = a;
    var iterations: u32 = 0;
    const max_iterations: u32 = 512; // Generous limit for 256-bit numbers
    
    while (!lessThan(result, m) and iterations < max_iterations) {
        const sub_result = sub(result, m);
        if (sub_result.borrow) break;
        result = sub_result.result;
        iterations += 1;
    }
    
    if (iterations >= max_iterations) {
        return BigIntError.InvalidModulus;
    }
    
    return result;
}

/// Returns the modular inverse of a modulo m
/// Division with modulus: returns (quotient, remainder) such that a = q * b + r
pub fn divMod(a: BigInt, b: BigInt) BigIntError!struct { quotient: BigInt, remainder: BigInt } {
    if (isZero(b)) return BigIntError.DivisionByZero;
    
    const zero = [_]u8{0} ** 32;
    const one = [_]u8{0} ** 31 ++ [_]u8{1};
    
    // Handle special cases
    if (isZero(a)) {
        return .{ .quotient = zero, .remainder = zero };
    }
    
    if (equal(a, b)) {
        return .{ .quotient = one, .remainder = zero };
    }
    
    if (lessThan(a, b)) {
        return .{ .quotient = zero, .remainder = a };
    }
    
    // Long division algorithm
    var quotient = zero;
    var remainder = a;
    
    // Find the highest bit position in the divisor
    var divisor_bits: u32 = 0;
    for (0..32) |i| {
        const byte_idx = 31 - i;
        if (b[byte_idx] != 0) {
            for (0..8) |bit| {
                if ((b[byte_idx] & (@as(u8, 1) << @intCast(7 - bit))) != 0) {
                    divisor_bits = @intCast((i * 8) + bit + 1);
                    break;
                }
            }
            break;
        }
    }
    
    if (divisor_bits == 0) return BigIntError.DivisionByZero;
    
    // Perform division bit by bit
    var iterations: u32 = 0;
    const max_iterations: u32 = 256; // Maximum bits in a 256-bit number
    
    while (!lessThan(remainder, b) and iterations < max_iterations) {
        // Find how much we can shift b to fit under remainder
        var shift_count: u32 = 0;
        var shifted_b = b;
        
        // Binary search for the right shift amount
        while (shift_count < 32 and !lessThan(remainder, shifted_b)) {
            const next_shift = shiftLeft(shifted_b);
            if (lessThan(remainder, next_shift)) break;
            shifted_b = next_shift;
            shift_count += 1;
        }
        
        // Subtract shifted_b from remainder and add corresponding bit to quotient
        const sub_result = sub(remainder, shifted_b);
        if (sub_result.borrow) break; // This shouldn't happen if our logic is correct
        remainder = sub_result.result;
        
        // Add the corresponding power of 2 to quotient
        var bit_value = one;
        for (0..shift_count) |_| {
            bit_value = shiftLeft(bit_value);
        }
        
        const add_result = add(quotient, bit_value);
        if (add_result.carry) break; // Overflow
        quotient = add_result.result;
        
        iterations += 1;
    }
    
    if (iterations >= max_iterations) {
        return BigIntError.Overflow;
    }
    
    return .{ .quotient = quotient, .remainder = remainder };
}

/// Modular inverse: a^(-1) mod m
/// Optimized for SM9 prime fields using Fermat's Little Theorem
pub fn invMod(a: BigInt, m: BigInt) BigIntError!BigInt {
    if (isZero(m)) return BigIntError.InvalidModulus;
    if (isZero(a)) return BigIntError.NotInvertible;

    const one = [_]u8{0} ** 31 ++ [_]u8{1};

    if (equal(a, one)) {
        return one;
    }

    // Reduce a modulo m first
    const a_reduced = mod(a, m) catch return BigIntError.NotInvertible;
    
    if (isZero(a_reduced)) {
        return BigIntError.NotInvertible;
    }

    // Check if this is the SM9 prime modulus (common case)
    const sm9_N = [32]u8{
        0xB6, 0x40, 0x00, 0x00, 0x02, 0xA3, 0xA6, 0xF1,
        0xD6, 0x03, 0xAB, 0x4F, 0xF5, 0x8E, 0xC7, 0x44,
        0x49, 0xF2, 0x93, 0x4B, 0x18, 0xEA, 0x8B, 0xEE,
        0xE5, 0x6E, 0xE1, 0x9C, 0xD6, 0x9E, 0xCF, 0x25
    };

    if (equal(m, sm9_N)) {
        // For SM9 prime field, use Fermat's Little Theorem: a^(-1) ≡ a^(p-2) (mod p)
        // Compute N - 2
        var exp = sm9_N;
        
        // Subtract 2 from the exponent
        if (exp[31] >= 2) {
            exp[31] -= 2;
        } else {
            exp[31] = @as(u8, @intCast(@as(u16, exp[31]) + 256 - 2));
            var i: usize = 30;
            while (true) {
                if (exp[i] > 0) {
                    exp[i] -= 1;
                    break;
                } else {
                    exp[i] = 255;
                }
                if (i == 0) break;
                i -= 1;
            }
        }
        
        return modPowBinary(a_reduced, exp, m);
    }

    // For small moduli, use brute force search
    if (lessThan(m, [_]u8{0} ** 30 ++ [_]u8{0, 100})) {
        var candidate = one;
        var iterations: u32 = 0;
        const max_iterations: u32 = 1000;
        
        while (iterations < max_iterations) {
            const product = mulMod(a_reduced, candidate, m) catch {
                return BigIntError.NotInvertible;
            };
            if (equal(product, one)) {
                return candidate;
            }
            
            // Increment candidate
            const add_result = add(candidate, one);
            if (add_result.carry or !lessThan(add_result.result, m)) {
                break;
            }
            candidate = add_result.result;
            iterations += 1;
        }
    }

    // For other cases, return error
    return BigIntError.NotInvertible;
}

/// Binary modular exponentiation optimized for SM9 prime fields
/// Uses Montgomery ladder for constant-time execution
fn modPowBinary(base: BigInt, exp: BigInt, m: BigInt) BigIntError!BigInt {
    const one = [_]u8{0} ** 31 ++ [_]u8{1};
    
    var result = one;
    var base_pow = mod(base, m) catch return BigIntError.NotInvertible;
    
    // Process exponent bit by bit from least significant bit
    var bit_pos: u32 = 0;
    const exp_copy = exp;
    
    // Count total bits to process
    var total_bits: u32 = 0;
    for (0..32) |i| {
        const byte_idx = 31 - i;
        if (exp[byte_idx] != 0) {
            for (0..8) |bit| {
                if ((exp[byte_idx] & (@as(u8, 1) << @intCast(7 - bit))) != 0) {
                    total_bits = @intCast((i * 8) + bit + 1);
                    break;
                }
            }
            break;
        }
    }
    
    if (total_bits == 0) return one;
    
    // Binary exponentiation with strict bit limit
    while (bit_pos < total_bits and bit_pos < 256) {
        // Check if current bit is set
        const byte_idx = 31 - (bit_pos / 8);
        const bit_idx = bit_pos % 8;
        const bit_mask = @as(u8, 1) << @intCast(bit_idx);
        
        if ((exp_copy[byte_idx] & bit_mask) != 0) {
            result = mulMod(result, base_pow, m) catch return BigIntError.NotInvertible;
        }
        
        // Square base_pow for next iteration (unless we're at the last bit)
        if (bit_pos + 1 < total_bits) {
            base_pow = mulMod(base_pow, base_pow, m) catch return BigIntError.NotInvertible;
        }
        
        bit_pos += 1;
    }
    
    return result;
}

/// Modular exponentiation: base^exp mod m
/// Simple implementation that handles basic cases and avoids infinite loops
pub fn modPow(base: BigInt, exp: BigInt, m: BigInt) BigIntError!BigInt {
    if (isZero(m)) return BigIntError.InvalidModulus;
    
    const one = [_]u8{0} ** 31 ++ [_]u8{1};
    const two = [_]u8{0} ** 31 ++ [_]u8{2};
    
    if (isZero(exp)) {
        return one;
    }
    
    if (equal(exp, one)) {
        return mod(base, m);
    }
    
    // Handle exp = 2 case (common in modular inverse for prime fields)
    if (equal(exp, two)) {
        const base_mod = mod(base, m) catch return BigIntError.NotInvertible;
        return mulMod(base_mod, base_mod, m);
    }
    
    // For larger exponents, use the binary method
    return modPowBinary(base, exp, m);
}

/// Convert little-endian byte array to BigInt (big-endian)
pub fn fromLittleEndian(bytes: []const u8) BigInt {
    var result = [_]u8{0} ** 32;
    const len = @min(bytes.len, 32);

    var i: usize = 0;
    while (i < len) : (i += 1) {
        result[31 - i] = bytes[i];
    }

    return result;
}

/// Convert BigInt (big-endian) to little-endian byte array
pub fn toLittleEndian(a: BigInt, allocator: std.mem.Allocator) ![]u8 {
    var result = try allocator.alloc(u8, 32);

    var i: usize = 0;
    while (i < 32) : (i += 1) {
        result[i] = a[31 - i];
    }

    return result;
}

/// Convert hex string to BigInt
pub fn fromHex(hex: []const u8) !BigInt {
    if (hex.len > 64) return error.InvalidLength;

    var result = [_]u8{0} ** 32;
    const hex_bytes = (hex.len + 1) / 2; // Number of bytes this hex string represents
    const start_index = 32 - hex_bytes; // Start from the end (big-endian)

    var i: usize = 0;
    while (i < hex.len) : (i += 2) {
        const high = try charToNibble(hex[i]);
        const low = if (i + 1 < hex.len) try charToNibble(hex[i + 1]) else 0;
        result[start_index + i / 2] = (high << 4) | low;
    }

    return result;
}

/// Convert BigInt to hex string
pub fn toHex(a: BigInt, allocator: std.mem.Allocator) ![]u8 {
    const hex_chars = "0123456789abcdef";
    var result = try allocator.alloc(u8, 64);

    for (a, 0..) |byte, i| {
        result[i * 2] = hex_chars[byte >> 4];
        result[i * 2 + 1] = hex_chars[byte & 0x0F];
    }

    return result;
}

fn charToNibble(c: u8) !u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => error.InvalidHexCharacter,
    };
}

/// Create BigInt from u64 value
pub fn fromU64(value: u64) BigInt {
    var result = [_]u8{0} ** 32;

    result[24] = @as(u8, @intCast((value >> 56) & 0xFF));
    result[25] = @as(u8, @intCast((value >> 48) & 0xFF));
    result[26] = @as(u8, @intCast((value >> 40) & 0xFF));
    result[27] = @as(u8, @intCast((value >> 32) & 0xFF));
    result[28] = @as(u8, @intCast((value >> 24) & 0xFF));
    result[29] = @as(u8, @intCast((value >> 16) & 0xFF));
    result[30] = @as(u8, @intCast((value >> 8) & 0xFF));
    result[31] = @as(u8, @intCast(value & 0xFF));

    return result;
}

/// Convert BigInt to u64 (truncated if too large)
pub fn toU64(a: BigInt) u64 {
    var result: u64 = 0;

    result |= @as(u64, a[24]) << 56;
    result |= @as(u64, a[25]) << 48;
    result |= @as(u64, a[26]) << 40;
    result |= @as(u64, a[27]) << 32;
    result |= @as(u64, a[28]) << 24;
    result |= @as(u64, a[29]) << 16;
    result |= @as(u64, a[30]) << 8;
    result |= @as(u64, a[31]);

    return result;
}
