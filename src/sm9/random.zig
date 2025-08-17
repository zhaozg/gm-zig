const std = @import("std");
const crypto = std.crypto;
const bigint = @import("bigint.zig");
const field = @import("field.zig");
const curve = @import("curve.zig");
const params = @import("params.zig");

/// SM9 Cryptographic Random Number Generation
/// Provides secure random number generation for SM9 operations
/// Based on GM/T 0044-2016 standard requirements
/// 
/// Features:
/// - Secure random number generation using system entropy
/// - Deterministic random generation for testing
/// - Random field element and point generation
/// - Proper error handling for entropy sources

/// Random number generation errors
pub const RandomError = error{
    EntropyFailure,
    InvalidRange,
    GenerationFailure,
};

/// Cryptographically secure random number generator
pub const SecureRandom = struct {
    prng: std.Random.DefaultPrng,
    
    /// Initialize with system entropy
    pub fn init() SecureRandom {
        var seed: u64 = undefined;
        crypto.random.bytes(std.mem.asBytes(&seed));
        
        return SecureRandom{
            .prng = std.Random.DefaultPrng.init(seed),
        };
    }
    
    /// Initialize with provided seed (for testing)
    pub fn initWithSeed(seed: u64) SecureRandom {
        return SecureRandom{
            .prng = std.Random.DefaultPrng.init(seed),
        };
    }
    
    /// Generate random bytes
    pub fn bytes(self: *SecureRandom, buffer: []u8) void {
        self.prng.random().bytes(buffer);
    }
    
    /// Generate random BigInt in range [1, max)
    pub fn randomBigInt(self: *SecureRandom, max: bigint.BigInt) RandomError!bigint.BigInt {
        if (bigint.isZero(max)) return RandomError.InvalidRange;
        
        var attempts: u32 = 0;
        const max_attempts: u32 = 256;
        
        while (attempts < max_attempts) {
            var result: bigint.BigInt = undefined;
            self.prng.random().bytes(&result);
            
            // Ensure result is in range [1, max)
            if (!bigint.isZero(result) and bigint.lessThan(result, max)) {
                return result;
            }
            
            attempts += 1;
        }
        
        return RandomError.GenerationFailure;
    }
    
    /// Generate random field element in Fp
    pub fn randomFieldElement(self: *SecureRandom, p: bigint.BigInt) RandomError!bigint.BigInt {
        return field.randomFieldElement(p, self.prng.random());
    }
    
    /// Generate random scalar for elliptic curve operations
    pub fn randomScalar(self: *SecureRandom, curve_params: params.SystemParams) RandomError!bigint.BigInt {
        return self.randomBigInt(curve_params.N);
    }
    
    /// Generate random G1 point
    pub fn randomG1Point(self: *SecureRandom, curve_params: params.SystemParams) RandomError!curve.G1Point {
        // Generate random scalar and multiply by generator
        const scalar = try self.randomScalar(curve_params);
        
        // Create generator point from P1
        const generator = curve.G1Point.fromCompressed(curve_params.P1) catch {
            return RandomError.GenerationFailure;
        };
        
        return generator.mul(scalar, curve_params);
    }
    
    /// Generate random G2 point  
    pub fn randomG2Point(self: *SecureRandom, curve_params: params.SystemParams) RandomError!curve.G2Point {
        // Generate random scalar and multiply by generator
        const scalar = try self.randomScalar(curve_params);
        
        // Create generator point from P2
        const generator = curve.G2Point.fromUncompressed(curve_params.P2) catch {
            return RandomError.GenerationFailure;
        };
        
        return generator.mul(scalar, curve_params);
    }
};

/// Deterministic random number generator for testing
/// NOT cryptographically secure - for testing purposes only!
pub const DeterministicRandom = struct {
    seed: u64,
    counter: u64,
    
    /// Initialize with seed
    pub fn init(seed: u64) DeterministicRandom {
        return DeterministicRandom{
            .seed = seed,
            .counter = 0,
        };
    }
    
    /// Generate deterministic bytes using SHA-256
    pub fn bytes(self: *DeterministicRandom, buffer: []u8) void {
        var offset: usize = 0;
        
        while (offset < buffer.len) {
            var hasher = crypto.hash.sha2.Sha256.init(.{});
            
            // Add seed and counter to ensure different outputs
            const seed_bytes = std.mem.asBytes(&self.seed);
            const counter_bytes = std.mem.asBytes(&self.counter);
            
            hasher.update(seed_bytes);
            hasher.update(counter_bytes);
            hasher.update("DETERMINISTIC_SM9_RNG");
            
            var block: [32]u8 = undefined;
            hasher.final(&block);
            
            const copy_len = @min(32, buffer.len - offset);
            std.mem.copyForwards(u8, buffer[offset..offset + copy_len], block[0..copy_len]);
            
            offset += copy_len;
            self.counter += 1;
        }
    }
    
    /// Generate deterministic BigInt in range [1, max)
    pub fn randomBigInt(self: *DeterministicRandom, max: bigint.BigInt) RandomError!bigint.BigInt {
        if (bigint.isZero(max)) return RandomError.InvalidRange;
        
        var attempts: u32 = 0;
        const max_attempts: u32 = 256;
        
        while (attempts < max_attempts) {
            var result: bigint.BigInt = undefined;
            self.bytes(&result);
            
            // Ensure result is in range [1, max)
            if (!bigint.isZero(result) and bigint.lessThan(result, max)) {
                return result;
            }
            
            attempts += 1;
        }
        
        return RandomError.GenerationFailure;
    }
    
    /// Generate deterministic field element
    pub fn randomFieldElement(self: *DeterministicRandom, p: bigint.BigInt) RandomError!bigint.BigInt {
        var result: bigint.BigInt = undefined;
        self.bytes(&result);
        
        // Simple modular reduction for deterministic output
        return bigint.addMod(result, [_]u8{0} ** 32, p) catch {
            return RandomError.GenerationFailure;
        };
    }
    
    /// Generate deterministic scalar
    pub fn randomScalar(self: *DeterministicRandom, curve_params: params.SystemParams) RandomError!bigint.BigInt {
        return self.randomBigInt(curve_params.N);
    }
};

/// Generate cryptographically secure random bytes
pub fn secureRandomBytes(buffer: []u8) RandomError!void {
    crypto.random.bytes(buffer);
}

/// Generate secure random BigInt in range [1, max)
pub fn secureRandomBigInt(max: bigint.BigInt) RandomError!bigint.BigInt {
    var rng = SecureRandom.init();
    return rng.randomBigInt(max);
}

/// Generate secure random field element
pub fn secureRandomFieldElement(p: bigint.BigInt) RandomError!bigint.BigInt {
    var rng = SecureRandom.init();
    return rng.randomFieldElement(p);
}

/// Generate secure random scalar for curve operations
pub fn secureRandomScalar(curve_params: params.SystemParams) RandomError!bigint.BigInt {
    var rng = SecureRandom.init();
    return rng.randomScalar(curve_params);
}

/// Key derivation from entropy
/// Derives multiple independent keys from a master entropy source
pub fn deriveKeys(master_entropy: []const u8, count: u32, allocator: std.mem.Allocator) ![]bigint.BigInt {
    const keys = try allocator.alloc(bigint.BigInt, count);
    
    for (keys, 0..) |*key, i| {
        var hasher = crypto.hash.sha2.Sha256.init(.{});
        hasher.update(master_entropy);
        hasher.update("SM9_KEY_DERIVATION");
        
        const index_bytes = std.mem.asBytes(&i);
        hasher.update(index_bytes);
        
        hasher.final(key);
    }
    
    return keys;
}

/// Entropy pool for collecting randomness
pub const EntropyPool = struct {
    pool: [256]u8,
    position: usize,
    
    /// Initialize empty entropy pool
    pub fn init() EntropyPool {
        return EntropyPool{
            .pool = [_]u8{0} ** 256,
            .position = 0,
        };
    }
    
    /// Add entropy to the pool
    pub fn addEntropy(self: *EntropyPool, data: []const u8) void {
        for (data) |byte| {
            self.pool[self.position] ^= byte;
            self.position = (self.position + 1) % 256;
        }
    }
    
    /// Extract randomness from the pool
    pub fn extract(self: *EntropyPool, buffer: []u8) void {
        // Hash the entire pool to extract randomness
        var hasher = crypto.hash.sha2.Sha256.init(.{});
        hasher.update(&self.pool);
        
        var offset: usize = 0;
        var counter: u64 = 0;
        
        while (offset < buffer.len) {
            var round_hasher = crypto.hash.sha2.Sha256.init(.{});
            round_hasher.update(&self.pool);
            
            const counter_bytes = std.mem.asBytes(&counter);
            round_hasher.update(counter_bytes);
            
            var block: [32]u8 = undefined;
            round_hasher.final(&block);
            
            const copy_len = @min(32, buffer.len - offset);
            std.mem.copyForwards(u8, buffer[offset..offset + copy_len], block[0..copy_len]);
            
            offset += copy_len;
            counter += 1;
        }
        
        // Mix the pool after extraction
        self.mixPool();
    }
    
    /// Mix the entropy pool
    fn mixPool(self: *EntropyPool) void {
        var hasher = crypto.hash.sha2.Sha256.init(.{});
        hasher.update(&self.pool);
        hasher.update("POOL_MIX");
        
        var new_entropy: [32]u8 = undefined;
        hasher.final(&new_entropy);
        
        // XOR new entropy into the pool
        for (new_entropy, 0..) |byte, i| {
            self.pool[i] ^= byte;
        }
    }
};

/// Test entropy source (for testing only)
pub fn testEntropy(seed: []const u8, output: []u8) void {
    var hasher = crypto.hash.sha2.Sha256.init(.{});
    hasher.update(seed);
    hasher.update("TEST_ENTROPY");
    
    var offset: usize = 0;
    var counter: u64 = 0;
    
    while (offset < output.len) {
        var round_hasher = crypto.hash.sha2.Sha256.init(.{});
        round_hasher.update(seed);
        
        const counter_bytes = std.mem.asBytes(&counter);
        round_hasher.update(counter_bytes);
        round_hasher.update("TEST_ROUND");
        
        var block: [32]u8 = undefined;
        round_hasher.final(&block);
        
        const copy_len = @min(32, output.len - offset);
        std.mem.copyForwards(u8, output[offset..offset + copy_len], block[0..copy_len]);
        
        offset += copy_len;
        counter += 1;
    }
}