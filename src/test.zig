test {
    _ = @import("test/sm3_test.zig");
    _ = @import("test/sm4_test.zig");
    _ = @import("test/sm2_group_test.zig");
    _ = @import("test/sm2_keypair_test.zig");
    _ = @import("test/sm2_signature_test.zig");
    _ = @import("test/sm2_encryption_test.zig");
    _ = @import("test/sm2_key_exchange_test.zig");
    _ = @import("test/sm9_params_test.zig");
    _ = @import("test/sm9_key_extract_test.zig");
    _ = @import("test/sm9_sign_test.zig");
    _ = @import("test/sm9_encrypt_test.zig");
    _ = @import("test/sm9_mod_test.zig");
    _ = @import("test/sm9_implementation_test.zig");
    _ = @import("test/sm9_security_test.zig");
    _ = @import("test/sm9_standard_vectors_test.zig");
    _ = @import("test/sm9_standard_compliance_test.zig"); // New comprehensive compliance tests
    
    // Phase 3: Enhanced SM9 Core Operations Tests
    _ = @import("test/sm9_field_test.zig");
    _ = @import("test/sm9_random_test.zig");
    _ = @import("test/sm9_curve_test.zig");
    _ = @import("test/sm9_pairing_test.zig");
}
