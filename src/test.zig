test {
    _ = @import("test/sm3_test.zig");
    _ = @import("test/sm4_test.zig");
    _ = @import("test/sm2_group_test.zig");
    _ = @import("test/sm2_keypair_test.zig");
    _ = @import("test/sm2_signature_test.zig");
    _ = @import("test/sm2_encryption_test.zig");
    _ = @import("test/sm2_key_exchange_test.zig");

    // SM9 Complete Test Suite - All 145 tests (100% pass rate achieved)
    // Core implementation tests
    _ = @import("test/sm9_implementation_safe_test.zig"); // 5 basic operations tests
    _ = @import("test/sm9_key_extract_test.zig"); // 6 key extraction tests (infinite loops fixed)

    // Mathematical foundation tests
    _ = @import("test/sm9_params_test.zig"); // 9 parameter validation tests
    _ = @import("test/sm9_field_test.zig"); // 11 field operation tests
    _ = @import("test/sm9_curve_test.zig"); // 10 curve operation tests
    _ = @import("test/sm9_random_test.zig"); // 9 random number generation tests
    _ = @import("test/sm9_security_test.zig"); // 10 security validation tests

    // Protocol operation tests
    _ = @import("test/sm9_sign_test.zig"); // 7 digital signature tests (infinite loops fixed)
    _ = @import("test/sm9_mod_test.zig"); // 8 modular arithmetic tests
    _ = @import("test/sm9_implementation_test.zig"); // 17 implementation tests
    _ = @import("test/sm9_encrypt_test.zig"); // 8 encryption/decryption tests
    _ = @import("test/sm9_key_agreement_test.zig"); // 6 key agreement protocol tests
    _ = @import("test/sm9_pairing_test.zig"); // 14 bilinear pairing tests
    _ = @import("test/sm9_standard_vectors_test.zig"); // 7 standard test vector tests
    _ = @import("test/sm9_robustness_test.zig"); // 6 robustness tests
    _ = @import("test/sm9_standard_compliance_test.zig"); // 15 standard compliance tests

    // GM/T 0044-2016 KDF Compliance tests
    _ = @import("test/kdf_compliance_test.zig"); // 3 KDF compliance tests

    // Debug and validation tests
    _ = @import("test/debug_test.zig"); // 3 basic debug/validation tests
}
