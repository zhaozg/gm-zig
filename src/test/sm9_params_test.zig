const std = @import("std");
const testing = std.testing;
const sm9 = @import("../sm9.zig");
const curve = sm9.curve;

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

test "SM9 master key pair fromPrivateKey correctness" {
    const params = sm9.params.SystemParams.init();

    // 随机生成合法私钥 (限制重试次数防止无限循环)
    var private_key = [_]u8{0} ** 32;
    var attempts: u32 = 0;
    while (attempts < 100) : (attempts += 1) {
        std.crypto.random.bytes(&private_key);
        if (!sm9.params.isZero(private_key) and sm9.params.isLessThan(private_key, params.N)) break;
    }
    // 如果100次尝试都失败，使用确定性的合法私钥
    if (attempts >= 100) {
        private_key = [_]u8{0} ** 32;
        private_key[31] = 1; // 使用最小的非零值
    }

    // 用 generate 生成密钥对
    const sign_gen = sm9.params.SignMasterKeyPair.generate(params);
    try testing.expectEqual(false, sm9.params.isZero(sign_gen.private_key));
    const encrypt_gen = sm9.params.EncryptMasterKeyPair.generate(params);
    try testing.expectEqual(false, sm9.params.isZero(encrypt_gen.private_key));

    // 用 fromPrivateKey 生成密钥对
    const sign_from = try sm9.params.SignMasterKeyPair.fromPrivateKey(params, private_key);
    const encrypt_from = try sm9.params.EncryptMasterKeyPair.fromPrivateKey(params, private_key);

    // 公钥一致性
    try testing.expectEqualSlices(u8, &sign_from.public_key, &curve.CurveUtils.scalarMultiplyG2(
        try curve.G2Point.fromUncompressed(params.P2), private_key, params
    ).compress());
    try testing.expectEqualSlices(u8, &encrypt_from.public_key, &curve.CurveUtils.scalarMultiplyG1(
        try curve.G1Point.fromCompressed(params.P1), private_key, params
    ).compress());

    // 验证密钥对合法
    try testing.expect(sign_from.validate(params));
    try testing.expect(encrypt_from.validate(params));
}

test "SM9 fromPrivateKey invalid input" {
    const params = sm9.params.SystemParams.init();
    const zero_key = [_]u8{0} ** 32;
    const over_key = [_]u8{0xFF} ** 32;

    try testing.expectError(sm9.params.ParameterError.InvalidPrivateKey,
        sm9.params.SignMasterKeyPair.fromPrivateKey(params, zero_key));
    try testing.expectError(sm9.params.ParameterError.InvalidPrivateKey,
        sm9.params.EncryptMasterKeyPair.fromPrivateKey(params, zero_key));
    try testing.expectError(sm9.params.ParameterError.InvalidPrivateKey,
        sm9.params.SignMasterKeyPair.fromPrivateKey(params, over_key));
    try testing.expectError(sm9.params.ParameterError.InvalidPrivateKey,
        sm9.params.EncryptMasterKeyPair.fromPrivateKey(params, over_key));
}
