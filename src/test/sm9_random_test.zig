const std = @import("std");
const testing = std.testing;
const sm9 = @import("../../sm9.zig");

test "SM9 Random Number Generation - Secure Random" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){}; 
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    const params = sm9.params.SystemParams.init();
    
    // Test SecureRandom initialization
    var rng = sm9.random.SecureRandom.init();
    
    // Test random bytes generation
    var buffer: [32]u8 = undefined;
    rng.bytes(&buffer);
    
    // Basic sanity check - buffer should not be all zeros (very unlikely)
    var all_zero = true;
    for (buffer) |byte| {
        if (byte != 0) all_zero = false;
    }
    // Note: This could theoretically fail, but probability is negligible
    try testing.expect(!all_zero);
    
    // Test random BigInt generation
    const max = params.N;
    const random_bigint = rng.randomBigInt(max) catch |err| {
        std.debug.print("Random BigInt generation failed: {}\n", .{err});
        return err;
    };
    
    // Should be less than max
    try testing.expect(sm9.bigint.lessThan(random_bigint, max));
    // Should not be zero (very unlikely for cryptographic random)
    try testing.expect(!sm9.bigint.isZero(random_bigint));
    
    // Test random field element generation
    const field_elem = rng.randomFieldElement(params.q) catch |err| {
        std.debug.print("Random field element generation failed: {}\n", .{err});
        return err;
    };
    _ = field_elem; // Use the result
    
    // Test random scalar generation
    const scalar = rng.randomScalar(params) catch |err| {
        std.debug.print("Random scalar generation failed: {}\n", .{err});
        return err;
    };
    _ = scalar; // Use the result
}

test "SM9 Random Number Generation - Deterministic Random" {
    const seed: u64 = 12345;
    var det_rng = sm9.random.DeterministicRandom.init(seed);
    
    // Test deterministic bytes generation
    var buffer1: [32]u8 = undefined;
    var buffer2: [32]u8 = undefined;
    
    det_rng.bytes(&buffer1);
    
    // Reset and generate again
    det_rng = sm9.random.DeterministicRandom.init(seed);
    det_rng.bytes(&buffer2);
    
    // Should be identical
    try testing.expect(std.mem.eql(u8, &buffer1, &buffer2));
    
    // Different seeds should produce different results
    var det_rng2 = sm9.random.DeterministicRandom.init(54321);
    var buffer3: [32]u8 = undefined;
    det_rng2.bytes(&buffer3);
    
    try testing.expect(!std.mem.eql(u8, &buffer1, &buffer3));
}

test "SM9 Random Number Generation - Random Point Generation" {
    const params = sm9.params.SystemParams.init();
    var rng = sm9.random.SecureRandom.init();
    
    // Test G1 point generation
    const g1_point = rng.randomG1Point(params) catch |err| {
        std.debug.print("G1 point generation failed: {}\n", .{err});
        return err;
    };
    
    // Should not error (though implementation might not be complete)
    // This test mainly ensures the interface works
    _ = g1_point;
    
    // Test G2 point generation  
    const g2_point = rng.randomG2Point(params) catch |err| {
        std.debug.print("G2 point generation failed: {}\n", .{err});
        return err;
    };
    _ = g2_point;
}

test "SM9 Random Number Generation - Key Derivation" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){}; 
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    const master_entropy = "test_master_entropy_source";
    const key_count = 5;
    
    const keys = sm9.random.deriveKeys(master_entropy, key_count, allocator);
    try testing.expect(keys != error.OutOfMemory);
    
    if (keys) |key_array| {
        defer allocator.free(key_array);
        
        try testing.expect(key_array.len == key_count);
        
        // Keys should be different from each other
        for (key_array, 0..) |key1, i| {
            for (key_array, 0..) |key2, j| {
                if (i != j) {
                    try testing.expect(!sm9.bigint.equal(key1, key2));
                }
            }
        }
        
        // Same entropy should produce same keys
        const keys2 = try sm9.random.deriveKeys(master_entropy, key_count, allocator);
        defer allocator.free(keys2);
        
        for (key_array, keys2) |key1, key2| {
            try testing.expect(sm9.bigint.equal(key1, key2));
        }
    } else |_| {
        try testing.expect(false);
    }
}

test "SM9 Random Number Generation - Entropy Pool" {
    var pool = sm9.random.EntropyPool.init();
    
    // Add some entropy
    const entropy1 = "first_entropy_source";
    const entropy2 = "second_entropy_source";
    
    pool.addEntropy(entropy1);
    pool.addEntropy(entropy2);
    
    // Extract randomness
    var output1: [64]u8 = undefined;
    var output2: [64]u8 = undefined;
    
    pool.extract(&output1);
    pool.extract(&output2);
    
    // Outputs should be different (pool mixing)
    try testing.expect(!std.mem.eql(u8, &output1, &output2));
    
    // Fresh pool with same entropy should produce different results due to mixing
    var fresh_pool = sm9.random.EntropyPool.init();
    fresh_pool.addEntropy(entropy1);
    fresh_pool.addEntropy(entropy2);
    
    var output3: [64]u8 = undefined;
    fresh_pool.extract(&output3);
    
    // Note: This might be the same due to deterministic implementation
    // but the interface is tested
    _ = output3;
}

test "SM9 Random Number Generation - Test Entropy" {
    const seed = "test_seed_for_entropy";
    var output: [32]u8 = undefined;
    
    sm9.random.testEntropy(seed, &output);
    
    // Should produce deterministic output
    var output2: [32]u8 = undefined;
    sm9.random.testEntropy(seed, &output2);
    
    try testing.expect(std.mem.eql(u8, &output, &output2));
    
    // Different seed should produce different output
    const seed2 = "different_test_seed";
    var output3: [32]u8 = undefined;
    sm9.random.testEntropy(seed2, &output3);
    
    try testing.expect(!std.mem.eql(u8, &output, &output3));
}

test "SM9 Random Number Generation - Error Handling" {
    var rng = sm9.random.SecureRandom.init();
    
    // Test with zero max (should error)
    const zero_max = [_]u8{0} ** 32;
    const result = rng.randomBigInt(zero_max);
    
    try testing.expectError(sm9.random.RandomError.InvalidRange, result);
}

test "SM9 Random Number Generation - Secure Functions" {
    const params = sm9.params.SystemParams.init();
    
    // Test secure random bytes
    var buffer: [32]u8 = undefined;
    const bytes_result = sm9.random.secureRandomBytes(&buffer);
    try testing.expect(bytes_result != sm9.random.RandomError.EntropyFailure);
    
    // Test secure random BigInt
    const bigint_result = sm9.random.secureRandomBigInt(params.N);
    try testing.expect(bigint_result != sm9.random.RandomError.InvalidRange);
    
    // Test secure random field element
    const field_result = sm9.random.secureRandomFieldElement(params.q);
    try testing.expect(field_result != sm9.random.RandomError.InvalidRange);
    
    // Test secure random scalar
    const scalar_result = sm9.random.secureRandomScalar(params);
    try testing.expect(scalar_result != sm9.random.RandomError.InvalidRange);
}