const std = @import("std");
const mem = std.mem;

/// Big Integer Modular Arithmetic for SM9
/// Provides modular operations for 256-bit integers used in SM9 algorithm
/// Based on GM/T 0044-2016 standard

/// Big integer representation (256-bit, big-endian)
pub const BigInt = [32]u8;

/// Big integer errors
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

/// Check if a == b
pub fn equal(a: BigInt, b: BigInt) bool {
    for (a, b) |x, y| {
        if (x != y) return false;
    }
    return true;
}

/// Compare two big integers: returns -1 if a < b, 0 if a == b, 1 if a > b
pub fn compare(a: BigInt, b: BigInt) i32 {
    var i: usize = 0;
    while (i < 32) : (i += 1) {
        if (a[i] < b[i]) return -1;
        if (a[i] > b[i]) return 1;
    }
    return 0;
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
pub fn addMod(a: BigInt, b: BigInt, m: BigInt) BigIntError!BigInt {
    if (isZero(m)) return BigIntError.InvalidModulus;
    
    const sum = add(a, b);
    
    // If no carry and sum < m, return sum directly
    if (!sum.carry and lessThan(sum.result, m)) {
        return sum.result;
    }
    
    // Otherwise, compute sum mod m using subtraction
    var result = sum.result;
    
    // Simple reduction: keep subtracting m until result < m
    while (!lessThan(result, m)) {
        const diff = sub(result, m);
        if (diff.borrow) break; // This shouldn't happen in valid cases
        result = diff.result;
    }
    
    return result;
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
fn shiftLeft(a: BigInt) BigInt {
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
fn shiftRight(a: BigInt) BigInt {
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
pub fn mulMod(a: BigInt, b: BigInt, m: BigInt) BigIntError!BigInt {
    if (isZero(m)) return BigIntError.InvalidModulus;
    if (isZero(a) or isZero(b)) return [_]u8{0} ** 32;
    
    var result = [_]u8{0} ** 32;
    var temp_a = a;
    var temp_b = b;
    
    // Simple double-and-add multiplication
    var bit_index: usize = 0;
    while (bit_index < 256) : (bit_index += 1) {
        // Check if current bit of b is set
        const byte_index = 31 - (bit_index / 8);
        const bit_offset = @as(u3, @intCast(bit_index % 8));
        
        if ((temp_b[byte_index] >> bit_offset) & 1 == 1) {
            result = try addMod(result, temp_a, m);
        }
        
        // Double temp_a for next iteration
        temp_a = try addMod(temp_a, temp_a, m);
    }
    
    return result;
}

/// Extended Euclidean Algorithm for modular inverse
/// Returns (gcd, x, y) where gcd = ax + by
fn extendedGcd(a: BigInt, b: BigInt) struct { gcd: BigInt, x: BigInt, y: BigInt } {
    if (isZero(b)) {
        // Return (a, 1, 0)
        var one = [_]u8{0} ** 32;
        one[31] = 1;
        var zero = [_]u8{0} ** 32;
        return .{ .gcd = a, .x = one, .y = zero };
    }
    
    // For simplicity, return identity for non-zero case
    // TODO: Implement full extended GCD algorithm
    var one = [_]u8{0} ** 32;
    one[31] = 1;
    return .{ .gcd = one, .x = one, .y = one };
}

/// Modular inverse: result = a^(-1) mod m
/// Uses extended Euclidean algorithm
pub fn invMod(a: BigInt, m: BigInt) BigIntError!BigInt {
    if (isZero(m)) return BigIntError.InvalidModulus;
    if (isZero(a)) return BigIntError.NotInvertible;
    
    // Simplified implementation - for full implementation, need extended GCD
    // For now, return a itself as placeholder (this is incorrect but allows compilation)
    // TODO: Implement proper modular inverse using extended Euclidean algorithm
    
    // Simple case: if a == 1, return 1
    var one = [_]u8{0} ** 32;
    one[31] = 1;
    
    if (equal(a, one)) {
        return one;
    }
    
    // For other cases, return error for now
    return BigIntError.NotInvertible;
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
    const start_index = if (hex.len <= 64) 32 - (hex.len + 1) / 2 else 0;
    
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