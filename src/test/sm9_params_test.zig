const std = @import("std");
const testing = std.testing;
const sm9 = @import("../sm9.zig");

test "SM9 system parameters initialization" {
    const params = sm9.params.SystemParams.init();
    
    // Test default parameters
    try testing.expect(params.curve == .bn256);
    try testing.expect(params.v == 256);
    try testing.expect(params.validate());
}

test "SM9 signature master key pair generation" {
    const params = sm9.params.SystemParams.init();
    const master_keypair = sm9.params.SignMasterKeyPair.generate(params);
    
    // Test key pair validation
    try testing.expect(master_keypair.validate(params));
}

test "SM9 encryption master key pair generation" {
    const params = sm9.params.SystemParams.init();
    const master_keypair = sm9.params.EncryptMasterKeyPair.generate(params);
    
    // Test key pair validation
    try testing.expect(master_keypair.validate(params));
}

test "SM9 complete system initialization" {
    const system = sm9.params.SM9System.init();
    
    // Test system validation
    try testing.expect(system.validate());
    
    // Test individual components
    try testing.expect(system.params.validate());
    try testing.expect(system.sign_master.validate(system.params));
    try testing.expect(system.encrypt_master.validate(system.params));
}

test "SM9 system with custom parameters" {
    const custom_params = sm9.params.SystemParams.init();
    const system = try sm9.params.SM9System.initWithParams(custom_params);
    
    try testing.expect(system.validate());
}

test "SM9 master key pair from private key" {
    const params = sm9.params.SystemParams.init();
    // Use a valid non-zero private key (value = 1 in big-endian format)
    var private_key = std.mem.zeroes([32]u8);
    private_key[31] = 1;
    
    const sign_keypair = try sm9.params.SignMasterKeyPair.fromPrivateKey(params, private_key);
    try testing.expect(sign_keypair.validate(params));
    
    const encrypt_keypair = try sm9.params.EncryptMasterKeyPair.fromPrivateKey(params, private_key);
    try testing.expect(encrypt_keypair.validate(params));
}