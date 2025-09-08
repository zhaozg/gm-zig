const std = @import("std");
const fmt = std.fmt;
const testing = std.testing;
const crypto = std.crypto;
const mem = std.mem;
const math = std.math;

const SM2 = @import("../sm2/group.zig").SM2;

// Helper function: hex string to byte array
fn hexToBytes(comptime hex_str: []const u8) [hex_str.len / 2]u8 {
    var result: [hex_str.len / 2]u8 = undefined;
    for (0..result.len) |i| {
        const hi = fmt.charToDigit(hex_str[2 * i], 16) catch unreachable;
        const lo = fmt.charToDigit(hex_str[2 * i + 1], 16) catch unreachable;
        result[i] = (hi << 4) | lo;
    }
    return result;
}

// Helper function: hex string to Fe
fn hexToFe(comptime hex_str: []const u8, endian: std.builtin.Endian) SM2.Fe {
    const bytes = hexToBytes(hex_str);
    return SM2.Fe.fromBytes(bytes, endian) catch unreachable;
}

// SM2 GMT standard test vectors
const test_vectors = struct {
    // Prime p
    const p = "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF";

    // Curve parameters a, b
    const a = "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC";
    const b = "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93";

    // Base point G
    const Gx = "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7";
    const Gy = "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0";

    // Order n
    const n = "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123";

    // Test vectors: expected results for k * G
    const k1 = "0000000000000000000000000000000000000000000000000000000000000001";
    const P1x = "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7";
    const P1y = "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0";

    const k2 = "0000000000000000000000000000000000000000000000000000000000000002";
    const P2x = "56CEFD60D7C87C000D58EF57FA73BA4D9C0DFA08C08A7331495C2E1DA3F2BD52";
    const P2y = "31B7E7E6CC8189F6687ACE086CD101D96E8ABE7377B8B50BD0D1A137F054F4E5";

    const k3 = "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54122"; // n-1
    const P3x = "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7";
    const P3y = "43C8C95D0F8B42BD32D1FADBBF1A31744FF0F761A5B7D9ABE3946B5E675A04F5";

    // Point doubling test vectors
    const double1x = "56CEFD60D7C87C000D58EF57FA73BA4D9C0DFA08C08A7331495C2E1DA3F2BD52";
    const double1y = "31B7E7E6CC8189F6687ACE086CD101D96E8ABE7377B8B50BD0D1A137F054F4E5";

    const double2x = "7D29778500BB5D73CDD8E03FBDFED36D5F8C449F4F9628B7A70A4EED4D1A0F3C";
    const double2y = "02A8A31F7D1E4C1D6E8F0A0F1C4D8CEE9B19B9A6A0F8B1D9E6A0F8B1D9E6A0F8";
};

test "SM2: Point doubling operation verification" {
    const base = SM2.basePoint;
    const double1 = base.dbl();
    const k2: [32]u8 = [_]u8{0} ** 31 ++ [_]u8{2};
    const p2 = try SM2.basePoint.mul(k2, .big);
    try testing.expect(double1.equivalent(p2));
}

test "SM2: Point addition operation verification" {
    const base = SM2.basePoint;
    const sum1 = base.add(base);
    const double = base.dbl();
    try testing.expect(sum1.equivalent(double));
}

test "SM2: Point subtraction operation verification" {
    const base = SM2.basePoint;
    const double = base.dbl();
    const sub1 = double.sub(base);
    try testing.expect(sub1.equivalent(base));
}

test "SM2: Mixed point addition operation verification" {
    const base = SM2.basePoint;
    const base_affine = base.affineCoordinates();

    // Compute G + G (using mixed addition)
    const sum1 = base.addMixed(base_affine);

    // Compute 2G (via point doubling)
    const double = base.dbl();

    // 验证结果相同
    try testing.expect(sum1.equivalent(double));
}

test "SM2: Mixed point subtraction operation verification" {
    const base = SM2.basePoint;
    const base_affine = base.affineCoordinates();
    const double = base.dbl();

    // Compute 2G - G = G
    const sub = double.subMixed(base_affine);
    try testing.expect(sub.equivalent(base));
}

test "SM2: Neutral element property verification" {
    const identity = SM2.identityElement;
    const base = SM2.basePoint;

    // Verify P + 0 = P
    const sum1 = base.add(identity);
    try testing.expect(sum1.equivalent(base));

    // Verify 0 + P = P
    const sum2 = identity.add(base);
    try testing.expect(sum2.equivalent(base));

    // Verify P - P = 0
    const sub = base.sub(base);
    try testing.expect(sub.equivalent(identity));

    // Verify the affine coordinates of 0 are (0,0)
    const affine = identity.affineCoordinates();
    try testing.expect(affine.x.isZero());
    try testing.expect(affine.y.isZero());
}

test "SM2: Negation operation verification" {
    const base = SM2.basePoint;

    // Compute -P
    const neg = base.neg();

    // Verify P + (-P) = 0
    const sum = base.add(neg);
    try testing.expectError(error.IdentityElement, sum.rejectIdentity());

    // Verify affine coordinate y value is negated
    const base_affine = base.affineCoordinates();
    const neg_affine = neg.affineCoordinates();
    try testing.expect(neg_affine.x.equivalent(base_affine.x));
    try testing.expect(neg_affine.y.equivalent(base_affine.y.neg()));
}

test "SM2: Scalar multiplication boundary cases" {
    // Order n (big endian)
    const n_bytes = hexToBytes(test_vectors.n);

    // Test n * G = 0
    const result1 = SM2.basePoint.mul(n_bytes, .big);
    try testing.expectError(error.IdentityElement, result1);

    // 计算 n+1 (大整数加法)
    var n_plus_one: [32]u8 = n_bytes;
    // 简单加1处理
    var carry: u16 = 1;
    var i: usize = 31;
    while (i >= 0) : (i -= 1) {
        const val = @as(u16, n_plus_one[i]) + carry;
        n_plus_one[i] = @truncate(val);
        carry = val >> 8;
        if (carry == 0) break;
        if (i == 0) break;
    }

    // 测试 (n+1) * G = G
    const result2 = try SM2.basePoint.mul(n_plus_one, .big);
    try testing.expect(result2.equivalent(SM2.basePoint));
}

test "SM2: Invalid point encoding handling" {
    // 创建无效点 (不在曲线上)
    const invalid_point = SM2{
        .x = SM2.Fe.one,
        .y = SM2.Fe.one,
        .z = SM2.Fe.one,
    };

    // 验证拒绝无效点
    try testing.expectError(error.InvalidEncoding, SM2.fromAffineCoordinates(invalid_point.affineCoordinates()));

    // 测试无效SEC1编码 (全FF)
    const invalid_sec1 = [_]u8{0x04} ++ [_]u8{0xFF} ** 64;

    // 预期错误应为 NonCanonical
    try testing.expectError(error.NonCanonical, SM2.fromSec1(&invalid_sec1));
}

test "SM2: Verify base point is on curve" {
    const base_affine = SM2.basePoint.affineCoordinates();
    const x3 = base_affine.x.sq().mul(base_affine.x);
    const ax = SM2.A.mul(base_affine.x);
    const right = x3.add(ax).add(SM2.B);
    const left = base_affine.y.sq();
    try testing.expect(left.equivalent(right));
}

test "SM2: Conditional selection (CMOV) verification" {
    var p1 = SM2.basePoint;
    const p2 = SM2.basePoint.dbl();

    // 条件为真时选择p2
    p1.cMov(p2, 1);
    try testing.expect(p1.equivalent(p2));

    // 条件为假时保持原值
    p1.cMov(SM2.basePoint, 0);
    try testing.expect(p1.equivalent(p2));
}

test "SM2: Public key scalar multiplication verification" {
    const k = [_]u8{0x03} ** 32;

    // 常规乘法
    const p1 = try SM2.basePoint.mul(k, .big);

    // 公钥乘法(可变时间)
    const p2 = try SM2.basePoint.mulPublic(k, .big);

    // 验证结果相同
    try testing.expect(p1.equivalent(p2));
}

test "SM2: ECDH key exchange" {
    const dha = SM2.scalar.random(.little);
    const dhb = SM2.scalar.random(.little);

    const dhA = try SM2.basePoint.mul(dha, .little);
    const dhB = try SM2.basePoint.mul(dhb, .little);

    const shareda = try dhA.mul(dhb, .little);
    const sharedb = try dhB.mul(dha, .little);

    try testing.expect(shareda.equivalent(sharedb));
}

test "SM2: Create point from affine coordinates" {
    // 国标定义的基点坐标
    const x = hexToFe(test_vectors.Gx, .big);
    const y = hexToFe(test_vectors.Gy, .big);

    // 从仿射坐标创建点
    const p = try SM2.fromAffineCoordinates(.{ .x = x, .y = y });

    // 验证点与基点等价
    try testing.expect(p.equivalent(SM2.basePoint));
}

test "SM2: SEC1 compressed format encoding/decoding" {
    const p = SM2.random();
    const s = p.toCompressedSec1();
    const q = try SM2.fromSec1(&s);
    try testing.expect(p.equivalent(q));
}

test "SM2: SEC1 uncompressed format encoding/decoding" {
    // 生成随机点
    const p = SM2.random();

    // 编码为非压缩格式
    const s = p.toUncompressedSec1();

    // 解码
    const q = try SM2.fromSec1(&s);

    // 验证等价
    try testing.expect(p.equivalent(q));
}

test "SM2: Zero scalar yields neutral element" {
    // 零标量
    const zero_scalar = [_]u8{0} ** 32;

    // 计算 0 * G
    const result = SM2.basePoint.mul(zero_scalar, .big);

    // 验证得到中性元素
    try testing.expectError(error.IdentityElement, result);
}

test "SM2: Non-canonical encoding error handling" {
    // 创建非规范编码 (全FF)
    const non_canonical = [_]u8{0xff} ** 32;

    // 尝试解码
    const result = SM2.Fe.fromBytes(non_canonical, .little);

    // 验证错误
    try testing.expectError(error.NonCanonical, result);
}

test "SM2: Neutral element encoding/decoding" {
    // 中性元素
    const identity = SM2.identityElement;

    // 验证拒绝中性元素
    try testing.expectError(error.IdentityElement, identity.rejectIdentity());

    // 仿射坐标应为 (0, 0)
    const affine = identity.affineCoordinates();
    try testing.expect(affine.x.isZero());
    try testing.expect(affine.y.isZero());

    // 尝试从 (0, 0) 创建点 (应成功并得到中性元素)
    const p = try SM2.fromAffineCoordinates(.{ .x = SM2.Fe.zero, .y = SM2.Fe.zero });
    try testing.expect(p.equivalent(identity));
}

test "SM2: Dual-base scalar multiplication" {
    // 两个标量
    const s1 = [_]u8{0x01} ** 32;
    const s2 = [_]u8{0x02} ** 32;

    // 两个点
    const p1 = SM2.basePoint;
    const p2 = SM2.basePoint.dbl();

    // 计算 s1*P1 + s2*P2
    const pr1 = try SM2.mulDoubleBasePublic(p1, s1, p2, s2, .little);

    // 传统计算方式
    const pr2 = (try p1.mul(s1, .little)).add(try p2.mul(s2, .little));

    // 验证结果相同
    try testing.expect(pr1.equivalent(pr2));
}

test "SM2: Dual-base scalar multiplication (large scalars)" {
    // 两个大标量
    const s1 = [_]u8{0xee} ** 32;
    const s2 = [_]u8{0xdd} ** 32;

    // 两个点
    const p1 = SM2.basePoint;
    const p2 = SM2.basePoint.dbl();

    // 计算 s1*P1 + s2*P2
    const pr1 = try SM2.mulDoubleBasePublic(p1, s1, p2, s2, .little);

    // 传统计算方式
    const pr2 = (try p1.mul(s1, .little)).add(try p2.mul(s2, .little));

    // 验证结果相同
    try testing.expect(pr1.equivalent(pr2));
}

test "SM2: Scalar parity" {
    // 创建标量
    const zero = SM2.scalar.Scalar.zero;
    const one = SM2.scalar.Scalar.one;
    const two = one.dbl();

    // 验证奇偶性
    try testing.expect(!zero.isOdd());
    try testing.expect(one.isOdd());
    try testing.expect(!two.isOdd());
}

test "SM2: Random point curve verification" {
    // 生成随机点
    const point = SM2.random();
    try point.rejectIdentity();

    // 获取仿射坐标
    const affine = point.affineCoordinates();

    // 计算曲线右侧: x³ + a*x + b
    const x3 = affine.x.sq().mul(affine.x);
    const ax = SM2.A.mul(affine.x);
    const right = x3.add(ax).add(SM2.B);

    // 计算左侧: y²
    const left = affine.y.sq();

    // 验证点在曲线上
    try testing.expect(left.equivalent(right));
}

test "SM2: Y coordinate recovery" {
    // 获取基点仿射坐标
    const base = SM2.basePoint;
    const affine = base.affineCoordinates();

    // 恢复Y坐标
    const recovered_y = try SM2.recoverY(affine.x, affine.y.isOdd());

    // 验证恢复的Y坐标正确
    try testing.expect(recovered_y.equivalent(affine.y));
}

test "SM2: Point addition verification" {
    const base = SM2.basePoint;

    // 计算 2G (点加倍)
    const double = base.dbl();

    // 计算 G + G (点加)
    const sum = base.add(base);

    // 获取仿射坐标
    const double_affine = double.affineCoordinates();
    const sum_affine = sum.affineCoordinates();

    // 验证结果相同
    try testing.expect(sum_affine.x.equivalent(double_affine.x));
    try testing.expect(sum_affine.y.equivalent(double_affine.y));
}
