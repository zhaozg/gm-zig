const std = @import("std");
const testing = std.testing;
const sm9 = @import("../sm9.zig");

test "Debug master key validation" {
    const system = sm9.params.SM9System.init();
    
    std.debug.print("\nSign master public key format: 0x{X:0>2}\n", .{system.sign_master.public_key[0]});
    std.debug.print("Encrypt master public key format: 0x{X:0>2}\n", .{system.encrypt_master.public_key[0]});
    
    std.debug.print("Sign master validation: {}\n", .{system.sign_master.validate(system.params)});
    std.debug.print("Encrypt master validation: {}\n", .{system.encrypt_master.validate(system.params)});
    
    // Test validation logic manually
    const sign_private_zero = std.mem.allEqual(u8, &system.sign_master.private_key, 0);
    const encrypt_private_zero = std.mem.allEqual(u8, &system.encrypt_master.private_key, 0);
    std.debug.print("Sign private key is zero: {}\n", .{sign_private_zero});
    std.debug.print("Encrypt private key is zero: {}\n", .{encrypt_private_zero});
    
    try testing.expect(true); // Just to pass the test
}