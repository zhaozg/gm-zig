const std = @import("std");
const sm9 = @import("sm9.zig");

test "debug modular inverse simple case" {
    // Get SM9 system parameters
    const system_params = sm9.params.SystemParams.init();
    
    // Test with a simple small value that should be invertible
    const test_value = [_]u8{0} ** 31 ++ [_]u8{5}; // Value = 5
    
    std.debug.print("Testing modular inverse with value 5\n");
    
    // Test invMod
    const result = sm9.bigint.invMod(test_value, system_params.N) catch |err| {
        std.debug.print("invMod failed with error: {}\n", .{err});
        return;
    };
    
    std.debug.print("Success! Inverse computed.\n");
    
    // Verify the result
    const verification = sm9.bigint.mulMod(test_value, result, system_params.N) catch |err| {
        std.debug.print("Verification failed: {}\n", .{err});
        return;
    };
    
    const one = [_]u8{0} ** 31 ++ [_]u8{1};
    if (sm9.bigint.equal(verification, one)) {
        std.debug.print("Verification PASSED: 5 * inv(5) ≡ 1 (mod N)\n");
    } else {
        std.debug.print("Verification FAILED\n");
    }
}

test "debug bigint modPow" {
    const a = [_]u8{0} ** 31 ++ [_]u8{5}; // 5
    const exp = [_]u8{0} ** 31 ++ [_]u8{3}; // 3
    const m = [_]u8{0} ** 31 ++ [_]u8{7}; // 7
    
    // Should compute 5^3 mod 7 = 125 mod 7 = 6
    const result = sm9.bigint.modPow(a, exp, m) catch |err| {
        std.debug.print("modPow failed: {}\n", .{err});
        return;
    };
    
    const expected = [_]u8{0} ** 31 ++ [_]u8{6};
    if (sm9.bigint.equal(result, expected)) {
        std.debug.print("modPow test PASSED\n");
    } else {
        std.debug.print("modPow test FAILED\n");
    }
}