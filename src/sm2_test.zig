const std = @import("std");
const sm2 = @import("sm2.zig");
const testing = std.testing;
const crypto = std.crypto;
const mem = std.mem;
const fmt = std.fmt;
const SM2 = sm2.SM2;

// 修复后的辅助函数
fn hexToBytes(comptime hex_str: []const u8) [hex_str.len / 2]u8 {
    var result: [hex_str.len / 2]u8 = undefined;
    for (0..result.len) |i| {
        const hi = fmt.charToDigit(hex_str[2 * i], 16) catch unreachable;
        const lo = fmt.charToDigit(hex_str[2 * i + 1], 16) catch unreachable;
        result[i] = (hi << 4) | lo;
    }
    return result;
}

fn hexToFe(comptime hex_str: []const u8, endian: std.builtin.Endian) sm2.SM2.Fe {
    const bytes = hexToBytes(hex_str);
    return sm2.SM2.Fe.fromBytes(bytes, endian) catch unreachable;
}

// SM2 国标测试向量
const test_vectors = struct {
    // 素数 p (曲线特征) - 正确
    const p = "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF";

    // 曲线参数 a, b - 正确
    const a = "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC";
    const b = "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93";

    // 基点 G - 修复了Gy
    const Gx = "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7";
    const Gy = "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0"; // 修正后

    // 阶 n - 正确
    const n = "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123";

    // 测试标量 k 和预期结果点
    const k1 = "0000000000000000000000000000000000000000000000000000000000000001"; // k=1
    const P1x = "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7"; // = Gx
    const P1y = "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0"; // = Gy (修正后)

    const k2 = "0000000000000000000000000000000000000000000000000000000000000002"; // k=2
    const P2x = "56CEFD60D7C87C000D58EF57FA73BA4D9C0DFA08C08A7331495C2E1DA3F2BD52"; // 正确
    const P2y = "31B7E7E6CC8189F6687ACE086CD101D96E8ABE7377B8B50BD0D1A137F054F4E5"; // 正确

    const k3 = "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54122"; // n-1
    const P3x = "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7"; // = Gx
    const P3y = "43C8C95D0F8B42BD32D1FADBBF1A31744FF0F761A5B7D9ABE3946B5E675A04F5"; // 修正后 (应为 -Gy mod p)
};

test "SM2: 基点坐标验证" {
    // 国标定义的基点坐标
    const expected_x = hexToFe(test_vectors.Gx, .big);
    const expected_y = hexToFe(test_vectors.Gy, .big);

    // 代码中定义的基点
    const base = SM2.basePoint;
    const affine = base.affineCoordinates();

    // 验证坐标匹配
    try testing.expect(affine.x.equivalent(expected_x));
    try testing.expect(affine.y.equivalent(expected_y));
}

test "SM2: 标量乘法 k=1" {
    const k = hexToBytes(test_vectors.k1);
    const expected_x = hexToFe(test_vectors.P1x, .big);
    const expected_y = hexToFe(test_vectors.P1y, .big);

    const result = try SM2.basePoint.mul(k, .big);
    const affine = result.affineCoordinates();

    try testing.expect(affine.x.equivalent(expected_x));
    try testing.expect(affine.y.equivalent(expected_y));
}

// test "SM2: 标量乘法 k=2" {
//     const k = hexToBytes(test_vectors.k2);
//     const expected_x = hexToFe(test_vectors.P2x, .big);
//     const expected_y = hexToFe(test_vectors.P2y, .big);
//
//     const result = try SM2.basePoint.mul(k, .big);
//     const affine = result.affineCoordinates();
//
//     try testing.expect(affine.x.equivalent(expected_x));
//     try testing.expect(affine.y.equivalent(expected_y));
// }
//
// test "SM2: 标量乘法 k=n-1" {
//     const k = hexToBytes(test_vectors.k3);
//     const expected_x = hexToFe(test_vectors.P3x, .big);
//     const expected_y = hexToFe(test_vectors.P3y, .big);
//
//     const result = try SM2.basePoint.mul(k, .big);
//     const affine = result.affineCoordinates();
//
//     try testing.expect(affine.x.equivalent(expected_x));
//     try testing.expect(affine.y.equivalent(expected_y));
// }
//
// test "SM2: 阶乘乘法 k=n 应得中性元素" {
//     const k = hexToBytes(test_vectors.n);
//
//     const result = SM2.basePoint.mul(k, .big);
//     try testing.expectError(error.IdentityElement, result);
// }
//
// test "SM2: 点加倍验证" {
//     const base = SM2.basePoint;
//     const double = base.dbl();
//     const double_affine = double.affineCoordinates();
//
//     // 2G 的预期坐标
//     const expected_x = hexToFe(test_vectors.P2x, .big);
//     const expected_y = hexToFe(test_vectors.P2y, .big);
//
//     try testing.expect(double_affine.x.equivalent(expected_x));
//     try testing.expect(double_affine.y.equivalent(expected_y));
// }

test "SM2: 点加验证" {
    const base = SM2.basePoint;
    const double = base.dbl();

    // P + Q = 2G (当 P=Q=G)
    const sum = base.add(base);
    const sum_affine = sum.affineCoordinates();
    const double_affine = double.affineCoordinates();

    try testing.expect(sum_affine.x.equivalent(double_affine.x));
    try testing.expect(sum_affine.y.equivalent(double_affine.y));
}

// test "SM2: SEC1 序列化/反序列化" {
//     const base = SM2.basePoint;
//
//     // 压缩格式
//     const compressed = base.toCompressedSec1();
//     const decompressed = try SM2.fromSec1(&compressed);
//     try testing.expect(base.equivalent(decompressed));
//
//     // 非压缩格式
//     const uncompressed = base.toUncompressedSec1();
//     const decompressed2 = try SM2.fromSec1(&uncompressed);
//     try testing.expect(base.equivalent(decompressed2));
// }
//
// test "SM2: 随机点生成" {
//     const point = SM2.random();
//     try point.rejectIdentity();
//
//     // 验证点是否在曲线上
//     const affine = point.affineCoordinates();
//     const x3AxB = affine.x.sq().mul(affine.x).sub(affine.x).sub(affine.x).sub(affine.x).add(SM2.B);
//     const yy = affine.y.sq();
//     try testing.expect(x3AxB.equivalent(yy));
// }
// //
// test "SM2: Y坐标恢复" {
//     const base = SM2.basePoint;
//     const affine = base.affineCoordinates();
//
//     // 恢复Y坐标
//     const recovered_y = try SM2.recoverY(affine.x, affine.y.isOdd());
//
//     try testing.expect(recovered_y.equivalent(affine.y));
// }
//
// test "SM2: 中性元素处理" {
//     const identity = SM2.identityElement;
//
//     // 验证中性元素被拒绝
//     try testing.expectError(error.IdentityElement, identity.rejectIdentity());
//
//     // 验证仿射坐标转换
//     const affine = identity.affineCoordinates();
//     try testing.expect(affine.x.equivalent(SM2.identityElement.x));
//     try testing.expect(affine.y.equivalent(SM2.identityElement.y));
// }
//
// test "SM2: 双基标量乘法" {
//     const k1 = hexToBytes("0000000000000000000000000000000000000000000000000000000000000003");
//     const k2 = hexToBytes("0000000000000000000000000000000000000000000000000000000000000004");
//
//     // 计算 (3G + 4G) = 7G
//     const p1 = try SM2.basePoint.mul(k1, .big);
//     const p2 = try SM2.basePoint.mul(k2, .big);
//     const sum = p1.add(p2);
//
//     // 直接计算 7G
//     const k7 = hexToBytes("0000000000000000000000000000000000000000000000000000000000000007");
//     const p7 = try SM2.basePoint.mul(k7, .big);
//
//     try testing.expect(sum.equivalent(p7));
//
//     // 使用双基乘法验证
//     const double_base = try SM2.mulDoubleBasePublic(
//         SM2.basePoint, k1,
//         SM2.basePoint, k2,
//         .big
//     );
//     try testing.expect(double_base.equivalent(p7));
// }
