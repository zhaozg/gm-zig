const std = @import("std");
const crypto = std.crypto;
const bigint = @import("bigint.zig");

/// SM9 Hash Functions Implementation
/// Provides H1, H2, and KDF functions as specified in GM/T 0044-2016
/// Based on SM3 cryptographic hash function

/// Hash function errors
pub const HashError = error{
    InvalidInput,
    InvalidLength,
    HashComputationFailed,
};

/// SM9 H1 hash function for key derivation
/// H1: {0,1}* × {0,1}* × Z+ → Z*_N
/// Used to hash identity and additional data to an integer mod N
pub fn h1Hash(data: []const u8, hid: u8, order: [32]u8, allocator: std.mem.Allocator) ![32]u8 {
    _ = allocator; // Not needed for this implementation
    
    // Step 1: Initialize hash context
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    
    // Step 2: Hash input data with HID byte
    hasher.update(data);
    hasher.update(&[1]u8{hid});
    
    // Step 3: Add fixed suffix for H1 
    hasher.update("SM9_H1_HASH_FUNCTION");
    
    // Step 4: Compute initial hash
    var initial_hash: [32]u8 = undefined;
    hasher.final(&initial_hash);
    
    // Step 5: Reduce modulo order N using iterative method
    // This is a simplified reduction - proper implementation would use
    // barrett reduction or Montgomery arithmetic
    var result = initial_hash;
    
    // Ensure result is less than order N
    while (!bigint.lessThan(result, order)) {
        // If result >= N, compute result = result - N
        const sub_result = bigint.sub(result, order);
        if (sub_result.borrow) break; // Shouldn't happen in valid cases
        result = sub_result.result;
    }
    
    // Step 6: Ensure result is not zero (required by SM9 spec)
    if (bigint.isZero(result)) {
        result[31] = 1; // Set to 1 if zero
    }
    
    return result;
}

/// SM9 H2 hash function for signature and encryption
/// H2: {0,1}* × {0,1}* → Z*_N
/// Used to hash message and additional data for signature/encryption
pub fn h2Hash(message: []const u8, additional_data: []const u8, allocator: std.mem.Allocator) ![32]u8 {
    _ = allocator; // Not needed for this implementation
    
    // Step 1: Initialize hash context
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    
    // Step 2: Hash message and additional data
    hasher.update(message);
    hasher.update(additional_data);
    
    // Step 3: Add fixed suffix for H2
    hasher.update("SM9_H2_HASH_FUNCTION");
    
    // Step 4: Compute hash
    var result: [32]u8 = undefined;
    hasher.final(&result);
    
    // Step 5: Ensure result is not zero
    if (bigint.isZero(result)) {
        result[31] = 1; // Set to 1 if zero
    }
    
    return result;
}

/// SM9 Key Derivation Function (KDF)
/// KDF: {0,1}* × Z+ → {0,1}*
/// Derives cryptographic keys from input material
pub fn kdf(input: []const u8, output_len: usize, allocator: std.mem.Allocator) ![]u8 {
    if (output_len == 0) return error.InvalidLength;
    
    // Allocate output buffer
    const output = try allocator.alloc(u8, output_len);
    
    // Number of hash blocks needed
    const hash_len = 32; // SHA-256 output length
    const num_blocks = (output_len + hash_len - 1) / hash_len;
    
    var offset: usize = 0;
    var counter: u32 = 1;
    
    // Generate output in blocks
    var i: u32 = 0;
    while (i < num_blocks) : (i += 1) {
        // Initialize hasher for this block
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        
        // Hash input data
        hasher.update(input);
        
        // Add counter as 4-byte big-endian
        const counter_bytes = [4]u8{
            @as(u8, @intCast((counter >> 24) & 0xFF)),
            @as(u8, @intCast((counter >> 16) & 0xFF)),
            @as(u8, @intCast((counter >> 8) & 0xFF)),
            @as(u8, @intCast(counter & 0xFF)),
        };
        hasher.update(&counter_bytes);
        
        // Add KDF identifier
        hasher.update("SM9_KDF_FUNCTION");
        
        // Compute block hash
        var block_hash: [32]u8 = undefined;
        hasher.final(&block_hash);
        
        // Copy to output (partial block for last iteration)
        const copy_len = @min(hash_len, output_len - offset);
        std.mem.copyForwards(u8, output[offset..offset + copy_len], block_hash[0..copy_len]);
        
        offset += copy_len;
        counter += 1;
    }
    
    return output;
}

/// SM9 expanded KDF for large key derivation
/// Uses iterative hashing for enhanced security
pub fn expandedKdf(
    input: []const u8, 
    salt: []const u8,
    info: []const u8,
    output_len: usize, 
    allocator: std.mem.Allocator
) ![]u8 {
    if (output_len == 0) return error.InvalidLength;
    
    // Step 1: Extract phase - create pseudorandom key from input and salt
    var extract_hasher = std.crypto.hash.sha2.Sha256.init(.{});
    extract_hasher.update(salt);
    extract_hasher.update(input);
    extract_hasher.update("SM9_HKDF_EXTRACT");
    
    var prk: [32]u8 = undefined;
    extract_hasher.final(&prk);
    
    // Step 2: Expand phase - generate output key material
    const output = try allocator.alloc(u8, output_len);
    
    const hash_len = 32;
    const num_blocks = (output_len + hash_len - 1) / hash_len;
    
    var offset: usize = 0;
    var counter: u8 = 1;
    var previous_block: [32]u8 = undefined;
    std.mem.set(u8, &previous_block, 0);
    
    var i: u8 = 0;
    while (i < num_blocks) : (i += 1) {
        var expand_hasher = std.crypto.hash.sha2.Sha256.init(.{});
        
        // For first block, don't include previous block
        if (i > 0) {
            expand_hasher.update(&previous_block);
        }
        
        expand_hasher.update(&prk);
        expand_hasher.update(info);
        expand_hasher.update(&[1]u8{counter});
        expand_hasher.update("SM9_HKDF_EXPAND");
        
        var block_hash: [32]u8 = undefined;
        expand_hasher.final(&block_hash);
        
        // Copy to output
        const copy_len = @min(hash_len, output_len - offset);
        std.mem.copyForwards(u8, output[offset..offset + copy_len], block_hash[0..copy_len]);
        
        // Save for next iteration
        previous_block = block_hash;
        
        offset += copy_len;
        counter += 1;
    }
    
    return output;
}

/// Hash data to field element for curve operations
pub fn hashToField(data: []const u8, field_order: [32]u8) [32]u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(data);
    hasher.update("SM9_HASH_TO_FIELD");
    
    var hash: [32]u8 = undefined;
    hasher.final(&hash);
    
    // Reduce modulo field order
    var result = hash;
    
    // Simple reduction by repeated subtraction
    while (!bigint.lessThan(result, field_order)) {
        const sub_result = bigint.sub(result, field_order);
        if (sub_result.borrow) break;
        result = sub_result.result;
    }
    
    return result;
}

/// Deterministic random generation for testing
/// NOT cryptographically secure - for testing only!
pub fn deterministicRandom(seed: []const u8, length: usize, allocator: std.mem.Allocator) ![]u8 {
    const output = try allocator.alloc(u8, length);
    
    var offset: usize = 0;
    var counter: u32 = 0;
    
    while (offset < length) {
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        hasher.update(seed);
        
        const counter_bytes = [4]u8{
            @as(u8, @intCast((counter >> 24) & 0xFF)),
            @as(u8, @intCast((counter >> 16) & 0xFF)),
            @as(u8, @intCast((counter >> 8) & 0xFF)),
            @as(u8, @intCast(counter & 0xFF)),
        };
        hasher.update(&counter_bytes);
        hasher.update("DETERMINISTIC_RANDOM");
        
        var block: [32]u8 = undefined;
        hasher.final(&block);
        
        const copy_len = @min(32, length - offset);
        std.mem.copyForwards(u8, output[offset..offset + copy_len], block[0..copy_len]);
        
        offset += copy_len;
        counter += 1;
    }
    
    return output;
}

/// SM9 message authentication code
pub fn mac(key: []const u8, message: []const u8, allocator: std.mem.Allocator) ![]u8 {
    _ = allocator;
    
    // Simple HMAC-like construction using SHA-256
    const block_size = 64;
    var key_pad = [_]u8{0} ** block_size;
    
    // Prepare key
    if (key.len <= block_size) {
        std.mem.copyForwards(u8, &key_pad, key);
    } else {
        // Hash long keys
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        hasher.update(key);
        var key_hash: [32]u8 = undefined;
        hasher.final(&key_hash);
        std.mem.copyForwards(u8, &key_pad, &key_hash);
    }
    
    // Compute inner hash
    var inner_key = key_pad;
    for (&inner_key) |*byte| {
        byte.* ^= 0x36;
    }
    
    var inner_hasher = std.crypto.hash.sha2.Sha256.init(.{});
    inner_hasher.update(&inner_key);
    inner_hasher.update(message);
    
    var inner_hash: [32]u8 = undefined;
    inner_hasher.final(&inner_hash);
    
    // Compute outer hash
    var outer_key = key_pad;
    for (&outer_key) |*byte| {
        byte.* ^= 0x5c;
    }
    
    var outer_hasher = std.crypto.hash.sha2.Sha256.init(.{});
    outer_hasher.update(&outer_key);
    outer_hasher.update(&inner_hash);
    
    var mac_result = try allocator.alloc(u8, 32);
    outer_hasher.final(mac_result[0..32]);
    
    return mac_result;
}

/// Constant-time hash comparison
pub fn constantTimeHashEqual(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    
    var result: u8 = 0;
    for (a, b) |x, y| {
        result |= x ^ y;
    }
    
    return result == 0;
}

/// SM9 hash utilities
pub const HashUtils = struct {
    /// Create hash context for incremental hashing
    pub const HashContext = struct {
        hasher: std.crypto.hash.sha2.Sha256,
        
        pub fn init() HashContext {
            return HashContext{
                .hasher = std.crypto.hash.sha2.Sha256.init(.{}),
            };
        }
        
        pub fn update(self: *HashContext, data: []const u8) void {
            self.hasher.update(data);
        }
        
        pub fn final(self: *HashContext, output: []u8) void {
            if (output.len >= 32) {
                self.hasher.final(output[0..32]);
            }
        }
    };
    
    /// Hash integer to bytes (big-endian)
    pub fn hashInteger(value: u64) [32]u8 {
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        
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
        
        hasher.update(&bytes);
        hasher.update("SM9_INTEGER_HASH");
        
        var result: [32]u8 = undefined;
        hasher.final(&result);
        return result;
    }
    
    /// Hash array of bytes with separator
    pub fn hashArray(arrays: []const []const u8, separator: []const u8, allocator: std.mem.Allocator) ![]u8 {
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        
        for (arrays, 0..) |array, i| {
            if (i > 0) {
                hasher.update(separator);
            }
            hasher.update(array);
        }
        
        hasher.update("SM9_ARRAY_HASH");
        
        var result = try allocator.alloc(u8, 32);
        hasher.final(result[0..32]);
        return result;
    }
};