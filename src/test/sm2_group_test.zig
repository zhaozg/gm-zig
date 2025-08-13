const std = @import("std");
const fmt = std.fmt;
const testing = std.testing;
const crypto = std.crypto;
const mem = std.mem;

const SM2 = @import("../sm2/group.zig").SM2;

// SM2 GMT 标准测试向量
const test_vectors = struct {
    // 素数 p
    const p = "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF";

    // 曲线参数 a, b
    const a = "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC";
    const b = "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93";

    // 基点 G
    const Gx = "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7";
    const Gy = "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0";

    // 阶 n
    const n = "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123";

    // 测试向量: k * G 的预期结果
    const k1 = "0000000000000000000000000000000000000000000000000000000000000001";
    const P1x = "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7";
    const P1y = "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0";

    const k2 = "0000000000000000000000000000000000000000000000000000000000000002";
    const P2x = "56CEFD60D7C87C000D58EF57FA73BA4D9C0DFA08C08A7331495C2E1DA3F2BD52";
    const P2y = "31B7E7E6CC8189F6687ACE086CD101D96E8ABE7377B8B50BD0D1A137F054F4E5";

    const k3 = "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54122"; // n-1
    const P3x = "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7";
    const P3y = "43C8C95D0F8B42BD32D1FADBBF1A31744FF0F761A5B7D9ABE3946B5E675A04F5";

    // 倍点测试向量
    const double1x = "56CEFD60D7C87C000D58EF57FA73BA4D9C0DFA08C08A7331495C2E1DA3F2BD52";
    const double1y = "31B7E7E6CC8189F6687ACE086CD101D96E8ABE7377B8B50BD0D1A137F054F4E5";

    const double2x = "7D29778500BB5D73CDD8E03FBDFED36D5F8C449F4F9628B7A70A4EED4D1A0F3C";
    const double2y = "02A8A31F7D1E4C1D6E8F0A0F1C4D8CEE9B19B9A6A0F8B1D9E6A0F8B1D9E6A0F8";
};

// 辅助函数: 十六进制字符串转字节数组
fn hexToBytes(comptime hex_str: []const u8) [hex_str.len / 2]u8 {
    var result: [hex_str.len / 2]u8 = undefined;
    for (0..result.len) |i| {
        const hi = fmt.charToDigit(hex_str[2 * i], 16) catch unreachable;
        const lo = fmt.charToDigit(hex_str[2 * i + 1], 16) catch unreachable;
        result[i] = (hi << 4) | lo;
    }
    return result;
}

// 辅助函数: 十六进制字符串转Fe
fn hexToFe(comptime hex_str: []const u8, endian: std.builtin.Endian) SM2.Fe {
    const bytes = hexToBytes(hex_str);
    return SM2.Fe.fromBytes(bytes, endian) catch unreachable;
}

test "SM2: ECDH 密钥交换" {
    // 生成随机私钥
    const dha = SM2.scalar.random(.little);
    const dhb = SM2.scalar.random(.little);

    // 计算公钥
    const dhA = try SM2.basePoint.mul(dha, .little);
    const dhB = try SM2.basePoint.mul(dhb, .little);

    // 计算共享密钥
    const shareda = try dhA.mul(dhb, .little);
    const sharedb = try dhB.mul(dha, .little);

    // 验证共享密钥相同
    try testing.expect(shareda.equivalent(sharedb));
}

test "SM2: 从仿射坐标创建点" {
    // 国标定义的基点坐标
    const x = hexToFe(test_vectors.Gx, .big);
    const y = hexToFe(test_vectors.Gy, .big);

    // 从仿射坐标创建点
    const p = try SM2.fromAffineCoordinates(.{ .x = x, .y = y });

    // 验证点与基点等价
    try testing.expect(p.equivalent(SM2.basePoint));
}

test "SM2: SEC1 压缩格式编码/解码" {
    // 生成随机点
    const p = SM2.random();

    // 编码为压缩格式
    const s = p.toCompressedSec1();

    // 解码
    const q = try SM2.fromSec1(&s);

    // 验证等价
    try testing.expect(p.equivalent(q));
}

test "SM2: SEC1 非压缩格式编码/解码" {
    // 生成随机点
    const p = SM2.random();

    // 编码为非压缩格式
    const s = p.toUncompressedSec1();

    // 解码
    const q = try SM2.fromSec1(&s);

    // 验证等价
    try testing.expect(p.equivalent(q));
}

test "SM2: 标量为零时得到中性元素" {
    // 零标量
    const zero_scalar = [_]u8{0} ** 32;

    // 计算 0 * G
    const result = SM2.basePoint.mul(zero_scalar, .big);

    // 验证得到中性元素
    try testing.expectError(error.IdentityElement, result);
}

test "SM2: 非规范编码错误处理" {
    // 创建非规范编码 (全FF)
    const non_canonical = [_]u8{0xff} ** 32;

    // 尝试解码
    const result = SM2.Fe.fromBytes(non_canonical, .little);

    // 验证错误
    try testing.expectError(error.NonCanonical, result);
}

test "SM2: 中性元素编码/解码" {
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

test "SM2: 双基标量乘法" {
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

test "SM2: 双基标量乘法 (大标量)" {
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


test "SM2: 标量奇偶性" {
    // 创建标量
    const zero = SM2.scalar.Scalar.zero;
    const one = SM2.scalar.Scalar.one;
    const two = one.dbl();

    // 验证奇偶性
    try testing.expect(!zero.isOdd());
    try testing.expect(one.isOdd());
    try testing.expect(!two.isOdd());
}

test "SM2: 随机点曲线验证" {
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

test "SM2: Y坐标恢复" {
    // 获取基点仿射坐标
    const base = SM2.basePoint;
    const affine = base.affineCoordinates();

    // 恢复Y坐标
    const recovered_y = try SM2.recoverY(affine.x, affine.y.isOdd());

    // 验证恢复的Y坐标正确
    try testing.expect(recovered_y.equivalent(affine.y));
}

test "SM2: 点加验证" {
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
