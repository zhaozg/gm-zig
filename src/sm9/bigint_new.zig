const std = @import("std");
const mem = std.mem;
const big = std.math.big;

/// Big Integer Modular Arithmetic for SM9 using std.math.big.int
/// Provides constant-time modular operations for 256-bit integers used in SM9 algorithm
/// Based on GM/T 0044-2016 standard

/// Big integer representation (256-bit, big-endian)
pub const BigInt = [32]u8;

/// Big integer computation errors
pub const BigIntError = error{
    DivisionByZero,
    InvalidModulus,
    NotInvertible,
    Overflow,
    OutOfMemory,
    InvalidBase,
    InvalidCharacter,
};

/// Thread-local allocator for big integer operations
var gpa = std.heap.GeneralPurposeAllocator(.{}){};
const allocator = gpa.allocator();

/// Convert BigInt to std.math.big.int.Managed using simple set operations
fn toBigInt(a: BigInt) BigIntError!big.int.Managed {
    var result = big.int.Managed.init(allocator) catch return BigIntError.OutOfMemory;
    errdefer result.deinit();
    
    // Start with zero
    result.set(0) catch return BigIntError.OutOfMemory;
    
    // Build up the value byte by byte from most significant
    for (a) |byte| {
        // Multiply by 256 and add the byte
        result.shiftLeft(&result, 8) catch return BigIntError.OutOfMemory;
        var byte_val = big.int.Managed.init(allocator) catch return BigIntError.OutOfMemory;
        defer byte_val.deinit();
        byte_val.set(byte) catch return BigIntError.OutOfMemory;
        result.add(&result, &byte_val) catch return BigIntError.OutOfMemory;
    }
    
    return result;
}

/// Convert std.math.big.int.Managed to BigInt
fn fromBigInt(a: big.int.Managed) BigIntError!BigInt {
    var result: BigInt = [_]u8{0} ** 32;
    
    // Check if the number fits in 256 bits
    const bit_count = a.toConst().bitCountTwosComp();
    if (bit_count > 256) {
        return BigIntError.Overflow;
    }
    
    // Make a working copy
    var temp = a.clone() catch return BigIntError.OutOfMemory;
    defer temp.deinit();
    
    var divisor = big.int.Managed.init(allocator) catch return BigIntError.OutOfMemory;
    defer divisor.deinit();
    divisor.set(256) catch return BigIntError.OutOfMemory;
    
    // Extract bytes from least significant to most significant
    var i: usize = 32;
    while (i > 0 and !temp.eqlZero()) {
        i -= 1;
        var quotient = big.int.Managed.init(allocator) catch return BigIntError.OutOfMemory;
        defer quotient.deinit();
        var remainder = big.int.Managed.init(allocator) catch return BigIntError.OutOfMemory;
        defer remainder.deinit();
        
        temp.divFloor(&quotient, &remainder, &divisor) catch return BigIntError.OutOfMemory;
        result[i] = @as(u8, @intCast(remainder.to(u64) catch 0));
        temp.copy(quotient.toConst()) catch return BigIntError.OutOfMemory;
    }
    
    return result;
}

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

/// Secure clear BigInt
pub fn secureClear(a: *BigInt) void {
    secureZero(a[0..]);
}

/// Check if two big integers are equal
pub fn equal(a: BigInt, b: BigInt) bool {
    return mem.eql(u8, &a, &b);
}

/// Compare two big integers
/// Returns: -1 if a < b, 0 if a == b, 1 if a > b
pub fn compare(a: BigInt, b: BigInt) i32 {
    for (0..32) |i| {
        if (a[i] < b[i]) return -1;
        if (a[i] > b[i]) return 1;
    }
    return 0;
}

/// Check if a < b
pub fn lessThan(a: BigInt, b: BigInt) bool {
    return compare(a, b) < 0;
}

/// Addition: a + b
pub fn add(a: BigInt, b: BigInt) struct { result: BigInt, carry: bool } {
    var a_big = toBigInt(a) catch return .{ .result = [_]u8{0} ** 32, .carry = true };
    defer a_big.deinit();
    
    var b_big = toBigInt(b) catch return .{ .result = [_]u8{0} ** 32, .carry = true };
    defer b_big.deinit();
    
    var result_big = big.int.Managed.init(allocator) catch return .{ .result = [_]u8{0} ** 32, .carry = true };
    defer result_big.deinit();
    
    result_big.add(&a_big, &b_big) catch return .{ .result = [_]u8{0} ** 32, .carry = true };
    
    const result = fromBigInt(result_big) catch return .{ .result = [_]u8{0} ** 32, .carry = true };
    
    // Check for overflow (result should fit in 256 bits)
    const bit_count = result_big.toConst().bitCountTwosComp();
    const carry = bit_count > 256;
    
    return .{ .result = result, .carry = carry };
}

/// Subtraction: a - b
pub fn sub(a: BigInt, b: BigInt) struct { result: BigInt, borrow: bool } {
    var a_big = toBigInt(a) catch return .{ .result = [_]u8{0} ** 32, .borrow = true };
    defer a_big.deinit();
    
    var b_big = toBigInt(b) catch return .{ .result = [_]u8{0} ** 32, .borrow = true };
    defer b_big.deinit();
    
    var result_big = big.int.Managed.init(allocator) catch return .{ .result = [_]u8{0} ** 32, .borrow = true };
    defer result_big.deinit();
    
    result_big.sub(&a_big, &b_big) catch return .{ .result = [_]u8{0} ** 32, .borrow = true };
    
    // Check for borrow (negative result)
    const borrow = !result_big.isPositive();
    
    if (borrow) {
        // Make positive
        result_big.abs();
        var modulus = big.int.Managed.init(allocator) catch return .{ .result = [_]u8{0} ** 32, .borrow = true };
        defer modulus.deinit();
        modulus.set(1) catch return .{ .result = [_]u8{0} ** 32, .borrow = true };
        modulus.shiftLeft(&modulus, 256) catch return .{ .result = [_]u8{0} ** 32, .borrow = true };
        result_big.sub(&modulus, &result_big) catch return .{ .result = [_]u8{0} ** 32, .borrow = true };
    }
    
    const result = fromBigInt(result_big) catch return .{ .result = [_]u8{0} ** 32, .borrow = true };
    
    return .{ .result = result, .borrow = borrow };
}

/// Addition modulo m: (a + b) mod m
pub fn addMod(a: BigInt, b: BigInt, m: BigInt) BigIntError!BigInt {
    if (isZero(m)) return BigIntError.InvalidModulus;
    
    var a_big = try toBigInt(a);
    defer a_big.deinit();
    
    var b_big = try toBigInt(b);
    defer b_big.deinit();
    
    var m_big = try toBigInt(m);
    defer m_big.deinit();
    
    var result_big = try big.int.Managed.init(allocator);
    defer result_big.deinit();
    
    try result_big.add(&a_big, &b_big);
    
    var temp = try big.int.Managed.init(allocator);
    defer temp.deinit();
    try result_big.divFloor(&temp, &result_big, &m_big);
    
    return try fromBigInt(result_big);
}

/// Subtraction modulo m: (a - b) mod m  
pub fn subMod(a: BigInt, b: BigInt, m: BigInt) BigIntError!BigInt {
    if (isZero(m)) return BigIntError.InvalidModulus;
    
    var a_big = try toBigInt(a);
    defer a_big.deinit();
    
    var b_big = try toBigInt(b);
    defer b_big.deinit();
    
    var m_big = try toBigInt(m);
    defer m_big.deinit();
    
    var result_big = try big.int.Managed.init(allocator);
    defer result_big.deinit();
    
    try result_big.sub(&a_big, &b_big);
    
    // Handle negative results
    if (!result_big.isPositive()) {
        try result_big.add(&result_big, &m_big);
    }
    
    var temp = try big.int.Managed.init(allocator);
    defer temp.deinit();
    try result_big.divFloor(&temp, &result_big, &m_big);
    
    return try fromBigInt(result_big);
}

/// Shift left by one bit
pub fn shiftLeft(a: BigInt) BigInt {
    var a_big = toBigInt(a) catch return [_]u8{0} ** 32;
    defer a_big.deinit();
    
    a_big.shiftLeft(&a_big, 1) catch return [_]u8{0} ** 32;
    
    return fromBigInt(a_big) catch [_]u8{0} ** 32;
}

/// Shift right by one bit
pub fn shiftRight(a: BigInt) BigInt {
    var a_big = toBigInt(a) catch return [_]u8{0} ** 32;
    defer a_big.deinit();
    
    a_big.shiftRight(&a_big, 1) catch return [_]u8{0} ** 32;
    
    return fromBigInt(a_big) catch [_]u8{0} ** 32;
}

/// Multiplication modulo m: (a * b) mod m
pub fn mulMod(a: BigInt, b: BigInt, m: BigInt) BigIntError!BigInt {
    if (isZero(m)) return BigIntError.InvalidModulus;
    
    var a_big = try toBigInt(a);
    defer a_big.deinit();
    
    var b_big = try toBigInt(b);
    defer b_big.deinit();
    
    var m_big = try toBigInt(m);
    defer m_big.deinit();
    
    var result_big = try big.int.Managed.init(allocator);
    defer result_big.deinit();
    
    try result_big.mul(&a_big, &b_big);
    
    var temp = try big.int.Managed.init(allocator);
    defer temp.deinit();
    try result_big.divFloor(&temp, &result_big, &m_big);
    
    return try fromBigInt(result_big);
}

/// Modulo operation: a mod m
pub fn mod(a: BigInt, m: BigInt) BigIntError!BigInt {
    if (isZero(m)) return BigIntError.InvalidModulus;
    
    var a_big = try toBigInt(a);
    defer a_big.deinit();
    
    var m_big = try toBigInt(m);
    defer m_big.deinit();
    
    var result_big = try big.int.Managed.init(allocator);
    defer result_big.deinit();
    
    var temp = try big.int.Managed.init(allocator);
    defer temp.deinit();
    
    try a_big.divFloor(&temp, &result_big, &m_big);
    
    return try fromBigInt(result_big);
}

/// Division: a / b (quotient and remainder)
pub fn divMod(a: BigInt, b: BigInt) BigIntError!struct { quotient: BigInt, remainder: BigInt } {
    if (isZero(b)) return BigIntError.DivisionByZero;
    
    var a_big = try toBigInt(a);
    defer a_big.deinit();
    
    var b_big = try toBigInt(b);
    defer b_big.deinit();
    
    var quotient_big = try big.int.Managed.init(allocator);
    defer quotient_big.deinit();
    
    var remainder_big = try big.int.Managed.init(allocator);
    defer remainder_big.deinit();
    
    try a_big.divFloor(&quotient_big, &remainder_big, &b_big);
    
    return .{
        .quotient = try fromBigInt(quotient_big),
        .remainder = try fromBigInt(remainder_big),
    };
}

/// Modular inverse: a^(-1) mod m
pub fn invMod(a: BigInt, m: BigInt) BigIntError!BigInt {
    if (isZero(m)) return BigIntError.InvalidModulus;
    if (isZero(a)) return BigIntError.NotInvertible;
    
    var a_big = try toBigInt(a);
    defer a_big.deinit();
    
    var m_big = try toBigInt(m);
    defer m_big.deinit();
    
    // Use extended Euclidean algorithm
    var gcd_result = try big.int.Managed.init(allocator);
    defer gcd_result.deinit();
    var x = try big.int.Managed.init(allocator);
    defer x.deinit();
    var y = try big.int.Managed.init(allocator);
    defer y.deinit();
    
    try extendedGcd(&gcd_result, &x, &y, &a_big, &m_big);
    
    // Check if gcd(a, m) == 1 (required for inverse to exist)
    var one = try big.int.Managed.init(allocator);
    defer one.deinit();
    try one.set(1);
    
    if (!gcd_result.eql(one)) {
        return BigIntError.NotInvertible;
    }
    
    // Ensure positive result
    if (!x.isPositive()) {
        try x.add(&x, &m_big);
    }
    
    return try fromBigInt(x);
}

/// Extended Euclidean algorithm implementation
fn extendedGcd(gcd_out: *big.int.Managed, x: *big.int.Managed, y: *big.int.Managed, a: *big.int.Managed, b: *big.int.Managed) BigIntError!void {
    if (a.eqlZero()) {
        try gcd_out.copy(b.toConst());
        try x.set(0);
        try y.set(1);
        return;
    }
    
    var temp_gcd = try big.int.Managed.init(gcd_out.allocator);
    defer temp_gcd.deinit();
    var x1 = try big.int.Managed.init(gcd_out.allocator);
    defer x1.deinit();
    var y1 = try big.int.Managed.init(gcd_out.allocator);
    defer y1.deinit();
    
    var b_mod_a = try big.int.Managed.init(gcd_out.allocator);
    defer b_mod_a.deinit();
    var temp = try big.int.Managed.init(gcd_out.allocator);
    defer temp.deinit();
    
    try b.divFloor(&temp, &b_mod_a, a);
    
    try extendedGcd(&temp_gcd, &x1, &y1, &b_mod_a, a);
    
    try gcd_out.copy(temp_gcd.toConst());
    
    // x = y1 - (b/a) * x1
    try b.divFloor(&temp, &b_mod_a, a); // temp = b/a
    try temp.mul(&temp, &x1); // temp = (b/a) * x1
    try x.sub(&y1, &temp); // x = y1 - temp
    
    // y = x1
    try y.copy(x1.toConst());
}

/// Modular exponentiation: base^exp mod m
pub fn modPow(base: BigInt, exp: BigInt, m: BigInt) BigIntError!BigInt {
    if (isZero(m)) return BigIntError.InvalidModulus;
    
    var base_big = try toBigInt(base);
    defer base_big.deinit();
    
    var exp_big = try toBigInt(exp);
    defer exp_big.deinit();
    
    var m_big = try toBigInt(m);
    defer m_big.deinit();
    
    var result_big = try big.int.Managed.init(allocator);
    defer result_big.deinit();
    
    try result_big.powMod(&base_big, &exp_big, &m_big);
    
    return try fromBigInt(result_big);
}

/// Convert from little-endian bytes
pub fn fromLittleEndian(bytes: []const u8) BigInt {
    var result: BigInt = [_]u8{0} ** 32;
    const len = @min(bytes.len, 32);
    
    // Convert little-endian to big-endian
    for (0..len) |i| {
        result[31 - i] = bytes[i];
    }
    
    return result;
}

/// Convert to little-endian bytes
pub fn toLittleEndian(a: BigInt, alloc: std.mem.Allocator) ![]u8 {
    var result = try alloc.alloc(u8, 32);
    
    // Convert big-endian to little-endian
    for (0..32) |i| {
        result[i] = a[31 - i];
    }
    
    return result;
}

/// Convert from hexadecimal string
pub fn fromHex(hex: []const u8) !BigInt {
    if (hex.len > 64) return BigIntError.Overflow; // Max 32 bytes = 64 hex chars
    
    var result: BigInt = [_]u8{0} ** 32;
    const start_offset = 32 - (hex.len + 1) / 2;
    
    var i: usize = 0;
    var offset: usize = start_offset;
    
    // Handle odd number of hex digits
    if (hex.len % 2 == 1) {
        result[offset] = try std.fmt.charToDigit(hex[0], 16);
        i = 1;
        offset += 1;
    }
    
    while (i < hex.len) : (i += 2) {
        const high = try std.fmt.charToDigit(hex[i], 16);
        const low = try std.fmt.charToDigit(hex[i + 1], 16);
        result[offset] = (high << 4) | low;
        offset += 1;
    }
    
    return result;
}

/// Convert to hexadecimal string
pub fn toHex(a: BigInt, alloc: std.mem.Allocator) ![]u8 {
    var result = try alloc.alloc(u8, 64);
    
    for (0..32) |i| {
        const hex_chars = "0123456789abcdef";
        result[i * 2] = hex_chars[a[i] >> 4];
        result[i * 2 + 1] = hex_chars[a[i] & 0x0F];
    }
    
    return result;
}

/// Convert from 64-bit unsigned integer
pub fn fromU64(value: u64) BigInt {
    var result: BigInt = [_]u8{0} ** 32;
    
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

/// Convert to 64-bit unsigned integer (truncated)
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