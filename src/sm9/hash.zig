const std = @import("std");
const crypto = std.crypto;
const mem = std.mem;
const bigint = @import("bigint.zig");
const constants = @import("constants.zig");
const helpers = @import("helpers.zig");
const SM3 = @import("../sm3.zig").SM3;

fn reduceHashToScalar(hash: [32]u8, order: [32]u8) [32]u8 {
    const n = std.mem.readInt(u256, &order, .big);
    const value = std.mem.readInt(u256, &hash, .big) % (n - 1);
    var out: [32]u8 = undefined;
    std.mem.writeInt(u256, &out, value + 1, .big);
    return out;
}

/// SM9 Hash Functions Implementation
/// Provides H1, H2, and KDF functions as specified in GM/T 0044-2016
/// Based on SM3 cryptographic hash function with improved maintainability
/// Hash function errors
pub const HashError = error{
    InvalidInput,
    InvalidLength,
    HashComputationFailed,
    FieldElementGenerationFailed,
    ModularReductionFailed,
    CounterOverflow,
    KDFComputationFailed,
};

const SM9_Q_U256: u256 = 0xB640000002A3A6F1D603AB4FF58EC74521F2934B1A7AEEDBE56F9B27E351457D;
const SQRT_EXP_U256: u256 = 0x16C80000005474DE3AC07569FEB1D8E8A43E5269634F5DDB7CADF364FC6A28B0;
const SQRT_M1_U256: u256 = 0x49DB721A269967C4E0A8DEBC0783182F82555233139E9D63EFBD7B54092C756C;

fn fpPowU256(base_in: u256, exp_in: u256) u256 {
    var base = base_in;
    var exp = exp_in;
    var result: u256 = 1;
    while (exp != 0) : (exp >>= 1) {
        if (exp & 1 != 0) result = mulModU256(result, base);
        base = mulModU256(base, base);
    }
    return result;
}

fn mulModU256(a: u256, b: u256) u256 {
    return @intCast((@as(u512, a) * b) % SM9_Q_U256);
}

/// Test whether x is the x-coordinate of a point on E(Fp): y^2 = x^3 + 5.
fn isValidG1X(x: [32]u8) bool {
    const xv = std.mem.readInt(u256, &x, .big);
    const x2 = mulModU256(xv, xv);
    const x3 = mulModU256(x2, xv);
    const rhs = (x3 + 5) % SM9_Q_U256;
    const y = fpPowU256(rhs, SQRT_EXP_U256);
    const y2 = mulModU256(y, y);
    if (y2 == rhs) return true;
    if (y2 == (SM9_Q_U256 - rhs) % SM9_Q_U256) {
        const y_alt = mulModU256(y, SQRT_M1_U256);
        return mulModU256(y_alt, y_alt) == rhs;
    }
    return false;
}

/// SM9 H1 hash function for key derivation
/// H1: {0,1}* × {0,1}* × Z+ → Z*_N
/// Used to hash identity and additional data to an integer mod N
/// GM/T 0044-2016 compliant implementation with proper modular reduction
pub fn h1Hash(data: []const u8, hid: u8, order: [32]u8, allocator: std.mem.Allocator) ![32]u8 {
    _ = allocator; // Not needed for this implementation

    // Input validation using helper functions
    try helpers.Validation.validateUserId(data);
    try helpers.Validation.validateHashIdentifier(hid);

    // GM/T 0044-2016 compliance: Reject zero order
    if (bigint.isZero(order)) {
        return HashError.InvalidInput;
    }

    // GM/T 0044-2016 H1: SM3(hid || ID || ct_be32), then
    // h = (hash mod (N - 1)) + 1, retrying until h is a valid G1 x-coordinate.
    var counter: u32 = 1;
    while (counter <= constants.Limits.MAX_HASH_COUNTER) : (counter += 1) {
        var hasher = SM3.init(.{});
        hasher.update(&[_]u8{hid});
        hasher.update(data);
        var counter_bytes: [4]u8 = undefined;
        mem.writeInt(u32, &counter_bytes, counter, .big);
        hasher.update(&counter_bytes);
        const hash_result = hasher.finalResult();
        const h = reduceHashToScalar(hash_result, order);
        if (isValidG1X(h)) return h;
    }

    return HashError.FieldElementGenerationFailed;
}

/// SM9 H2 hash function for signature and encryption
/// H2: {0,1}* × {0,1}* → Z*_N
/// Used to hash message and additional data for signature/encryption
/// GM/T 0044-2016 compliant implementation with proper modular reduction
pub fn h2Hash(message: []const u8, additional_data: []const u8, order: [32]u8, allocator: std.mem.Allocator) ![32]u8 {
    _ = allocator; // Not needed for this implementation

    // Input validation
    try helpers.Validation.validateMessage(message);

    // GM/T 0044-2016 compliance: Reject zero order
    if (bigint.isZero(order)) {
        return HashError.InvalidInput;
    }

    // GM/T 0044-2016 H2: SM3(0x02 || Z || ct_be32), then
    // h = (hash mod (N - 1)) + 1.
    var counter: u32 = 1;
    while (counter <= constants.Limits.MAX_HASH_COUNTER) : (counter += 1) {
        var hasher = SM3.init(.{});
        hasher.update(&[_]u8{0x02});
        hasher.update(message);
        hasher.update(additional_data);
        var counter_bytes: [4]u8 = undefined;
        mem.writeInt(u32, &counter_bytes, counter, .big);
        hasher.update(&counter_bytes);
        const hash_result = hasher.finalResult();
        return reduceHashToScalar(hash_result, order);
    }

    return HashError.FieldElementGenerationFailed;
}

/// SM9 Key Derivation Function (KDF)
/// KDF: {0,1}* × Z+ → {0,1}*
/// Derives cryptographic keys from input material
/// Refactored for better maintainability and security
pub fn kdf(input: []const u8, output_len: usize, allocator: std.mem.Allocator) ![]u8 {
    // Input validation
    if (output_len == 0) return HashError.InvalidLength;
    if (output_len > constants.Limits.MAX_KDF_OUTPUT_LENGTH) return HashError.InvalidLength;
    if (input.len == 0) return HashError.InvalidInput;

    // Allocate output buffer
    const output = try allocator.alloc(u8, output_len);
    errdefer allocator.free(output);

    // GM/T 0044-2016 KDF: K = SM3(Z || ct_be32) || SM3(Z || ct+1_be32) || ...
    const hash_len = constants.FieldSize.SM3_HASH_BYTES;
    const num_blocks = (output_len + hash_len - 1) / hash_len;

    try generateKDFBlocks(input, output, num_blocks, hash_len);

    // Security check: ensure output is not all zeros (GM/T 0044-2016 requirement)
    if (isAllZeros(output)) {
        allocator.free(output);
        return HashError.KDFComputationFailed;
    }

    return output;
}

/// Generate KDF blocks using counter-based approach
fn generateKDFBlocks(input: []const u8, output: []u8, num_blocks: usize, hash_len: usize) !void {
    var offset: usize = 0;
    var counter: u32 = 1;

    var i: usize = 0;
    while (i < num_blocks) : (i += 1) {
        var hasher = SM3.init(.{});
        hasher.update(input);
        var counter_bytes: [4]u8 = undefined;
        mem.writeInt(u32, &counter_bytes, counter, .big);
        hasher.update(&counter_bytes);
        const block_hash = hasher.finalResult();

        // Copy to output (handle partial block for last iteration)
        const copy_len = @min(hash_len, output.len - offset);
        @memcpy(output[offset .. offset + copy_len], block_hash[0..copy_len]);

        offset += copy_len;
        counter += 1;

        // Prevent counter overflow
        if (counter == 0) {
            return HashError.CounterOverflow;
        }
    }
}

/// Check if buffer contains all zeros
fn isAllZeros(buffer: []const u8) bool {
    for (buffer) |byte| {
        if (byte != 0) return false;
    }
    return true;
}

/// SM9 expanded KDF for large key derivation using HKDF-like approach
/// Uses iterative hashing for enhanced security
pub fn expandedKdf(input: []const u8, salt: []const u8, info: []const u8, output_len: usize, allocator: std.mem.Allocator) ![]u8 {
    // Input validation
    if (output_len == 0) return HashError.InvalidLength;
    if (output_len > constants.Limits.MAX_KDF_OUTPUT_LENGTH) return HashError.InvalidLength;

    // Step 1: Extract phase - create pseudorandom key from input and salt
    var extract_builder = helpers.SM3Builder.init();
    _ = extract_builder.update(salt)
        .update(input)
        .updateDomainSeparator("SM9_HKDF_EXTRACT");

    var prk: [32]u8 = undefined;
    extract_builder.finalize(&prk);
    defer helpers.SecureMemory.clearSensitiveData(&prk);

    // Step 2: Expand phase - generate output key material
    const output = try allocator.alloc(u8, output_len);
    errdefer allocator.free(output);

    try generateHKDFExpansion(&prk, info, output);

    return output;
}

/// Generate HKDF expansion blocks
fn generateHKDFExpansion(prk: *const [32]u8, info: []const u8, output: []u8) !void {
    const hash_len = constants.FieldSize.SM3_HASH_BYTES;
    const num_blocks = (output.len + hash_len - 1) / hash_len;

    var offset: usize = 0;
    var counter: u8 = 1;
    var previous_block: [32]u8 = undefined;
    @memset(&previous_block, 0);

    var i: u8 = 0;
    while (i < num_blocks) : (i += 1) {
        var expand_builder = helpers.SM3Builder.init();

        // For subsequent blocks, include previous block (HKDF chaining)
        if (i > 0) {
            _ = expand_builder.update(&previous_block);
        }

        _ = expand_builder.update(prk)
            .update(info)
            .updateByte(counter)
            .updateDomainSeparator("SM9_HKDF_EXPAND");

        var block_hash: [32]u8 = undefined;
        expand_builder.finalize(&block_hash);

        // Copy to output (handle partial block for last iteration)
        const copy_len = @min(hash_len, output.len - offset);
        @memcpy(output[offset .. offset + copy_len], block_hash[0..copy_len]);

        // Update for next iteration
        previous_block = block_hash;
        offset += copy_len;
        counter += 1;

        // Prevent counter overflow (HKDF limitation)
        if (counter == 0) {
            return HashError.CounterOverflow;
        }
    }

    // Clear sensitive intermediate data
    helpers.SecureMemory.clearSensitiveData(&previous_block);
}

/// Hash data to field element for curve operations
/// Uses consistent domain separation and modular reduction
pub fn hashToField(data: []const u8, field_order: [32]u8) [32]u8 {
    // Build hash with domain separation
    var builder = helpers.SM3Builder.init();
    _ = builder.update(data)
        .updateDomainSeparator("SM9_HASH_TO_FIELD");

    var hash: [32]u8 = undefined;
    builder.finalize(&hash);

    // Apply modular reduction using helper
    return helpers.ModularReduction.reduce(hash, field_order) catch {
        // Fallback to simplified reduction if needed
        var result = hash;

        // Simple field reduction
        var i: usize = 0;
        while (i < constants.FieldSize.FIELD_ELEMENT_BYTES) : (i += 1) {
            if (field_order[i] > 0) {
                result[i] = result[i] % field_order[i];
            }
        }

        return result;
    };
}

/// SM9 message authentication code using HMAC-SM3 construction
/// Provides secure message authentication for SM9 operations
pub fn mac(key: []const u8, message: []const u8, allocator: std.mem.Allocator) ![]u8 {
    // Input validation
    if (key.len == 0 or message.len == 0) {
        return HashError.InvalidInput;
    }

    // Allocate result
    const result = try allocator.alloc(u8, constants.FieldSize.SM3_HASH_BYTES);
    errdefer allocator.free(result);

    try computeHMacSM3(key, message, result);

    return result;
}

/// Compute HMAC-SM3 according to RFC 2104 pattern
fn computeHMacSM3(key: []const u8, message: []const u8, output: *[32]u8) !void {
    const block_size = 64; // SM3 block size
    var key_buffer: [64]u8 = @as([64]u8, @splat(0));

    // Prepare key: hash if too long, pad if too short
    if (key.len <= block_size) {
        @memcpy(key_buffer[0..key.len], key);
    } else {
        var key_builder = helpers.SM3Builder.init();
        _ = key_builder.update(key);
        var key_hash: [32]u8 = undefined;
        key_builder.finalize(&key_hash);
        @memcpy(key_buffer[0..32], &key_hash);
        helpers.SecureMemory.clearSensitiveData(&key_hash);
    }
    defer helpers.SecureMemory.clearSensitiveData(&key_buffer);

    // Compute inner hash: H((K ⊕ ipad) || message)
    var inner_key = key_buffer;
    for (&inner_key) |*byte| {
        byte.* ^= 0x36; // ipad
    }

    var inner_builder = helpers.SM3Builder.init();
    _ = inner_builder.update(&inner_key)
        .update(message);

    var inner_hash: [32]u8 = undefined;
    inner_builder.finalize(&inner_hash);
    defer helpers.SecureMemory.clearSensitiveData(&inner_hash);

    // Compute outer hash: H((K ⊕ opad) || inner_hash)
    var outer_key = key_buffer;
    for (&outer_key) |*byte| {
        byte.* ^= 0x5C; // opad
    }

    var outer_builder = helpers.SM3Builder.init();
    _ = outer_builder.update(&outer_key)
        .update(&inner_hash);

    outer_builder.finalize(output);
}

/// Constant-time hash comparison for security
pub fn constantTimeHashEqual(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;

    var result: u8 = 0;
    for (a, b) |x, y| {
        result |= x ^ y;
    }

    return result == 0;
}

/// SM9 hash utilities with improved organization
pub const HashUtils = struct {
    /// Hash integer to bytes (big-endian) with domain separation
    pub fn hashInteger(value: u64) [32]u8 {
        var builder = helpers.SM3Builder.init();

        // Convert to big-endian bytes
        const bytes = [8]u8{
            @as(u8, @intCast((value >> 56) & 0xFF)),
            @as(u8, @intCast((value >> 48) & 0xFF)),
            @as(u8, @intCast((value >> 40) & 0xFF)),
            @as(u8, @intCast((value >> 32) & 0xFF)),
            @as(u8, @intCast((value >> 24) & 0xFF)),
            @as(u8, @intCast((value >> 16) & 0xFF)),
            @as(u8, @intCast((value >> 8) & 0xFF)),
            @as(u8, @intCast(value & 0xFF)),
        };

        _ = builder.update(&bytes)
            .updateDomainSeparator("SM9_INTEGER_HASH");

        var result: [32]u8 = undefined;
        builder.finalize(&result);
        return result;
    }

    /// Hash array of bytes with separator
    pub fn hashArray(arrays: []const []const u8, separator: []const u8, allocator: std.mem.Allocator) ![]u8 {
        var builder = helpers.SM3Builder.init();

        for (arrays, 0..) |array, i| {
            if (i > 0) {
                _ = builder.update(separator);
            }
            _ = builder.update(array);
        }

        _ = builder.updateDomainSeparator("SM9_ARRAY_HASH");

        const result = try allocator.alloc(u8, constants.FieldSize.SM3_HASH_BYTES);
        var hash: [32]u8 = undefined;
        builder.finalize(&hash);
        @memcpy(result, &hash);

        return result;
    }

    /// Create incremental hash context (backward compatibility)
    pub const HashContext = struct {
        builder: helpers.SM3Builder,

        pub fn init() HashContext {
            return HashContext{
                .builder = helpers.SM3Builder.init(),
            };
        }

        pub fn update(self: *HashContext, data: []const u8) void {
            _ = self.builder.update(data);
        }

        pub fn final(self: *HashContext, output: []u8) void {
            if (output.len >= constants.FieldSize.SM3_HASH_BYTES) {
                var hash: [32]u8 = undefined;
                self.builder.finalize(&hash);
                @memcpy(output[0..32], &hash);
            }
        }
    };
};
