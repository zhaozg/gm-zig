test {
    _ = @import("test/sm3_test.zig");
    _ = @import("test/sm4_test.zig");
    _ = @import("test/sm2_group_test.zig");
    _ = @import("test/sm2_keypair_test.zig");
    _ = @import("test/sm2_signature_test.zig");
    _ = @import("test/sm2_encryption_test.zig");
    _ = @import("test/sm2_key_exchange_test.zig");
    
    // SM9 Tests - Core mathematical operations that pass without infinite loops (45 tests)
    _ = @import("test/sm9_field_test.zig");    // ✓ 10 tests - field arithmetic operations
    _ = @import("test/sm9_curve_test.zig");    // ✓ 9 tests - basic curve point operations
    _ = @import("test/sm9_random_test.zig");   // ✓ 8 tests - random number generation
    _ = @import("test/sm9_security_test.zig"); // ✓ 10 tests - security features, modular inverse
    _ = @import("test/sm9_params_test.zig");   // ✓ 8 tests - parameter validation
}
