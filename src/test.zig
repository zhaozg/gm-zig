test {
    _ = @import("test/sm3_test.zig");
    _ = @import("test/sm4_test.zig");
    _ = @import("test/sm2_group_test.zig");
    _ = @import("test/sm2_keypair_test.zig");
    _ = @import("test/sm2_signature_test.zig");
    _ = @import("test/sm2_encryption_test.zig");
    _ = @import("test/sm2_key_exchange_test.zig");
    _ = @import("test/secure_test.zig");

    _ = @import("zuc.zig");
    _ = @import("test/zuc256_test.zig");
    _ = @import("test/zuc_modes_test.zig");

    _ = @import("sm9/bn.zig");
    _ = @import("sm9/pairing_bn.zig");
    _ = @import("sm9/hash.zig");
    _ = @import("test/sm9_standard_test.zig");
}
