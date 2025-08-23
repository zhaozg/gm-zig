const std = @import("std");
const crypto = std.crypto;
const mem = std.mem;
const sm3 = @import("../sm3.zig");
const SM3 = sm3.SM3;

const builtin = @import("builtin");

/// 编译时检测是否为 Zig 0.15 或更新版本
pub const isZig015OrNewer = blk: {
    // Zig 版本号结构: major.minor.patch
    const version = builtin.zig_version;

    // 0.15.0 或更新版本
    break :blk (version.major == 0 and version.minor >= 15);
};

const Buffer = std.ArrayList(u8);

/// Key Derivation Function (KDF) based on SM3
/// Implements the KDF function as specified in GM/T 0003.4-2012
pub fn kdf(allocator: std.mem.Allocator, z: []const u8, klen: usize) ![]u8 {
    if (klen == 0) return error.InvalidKeyLength;

    const v = SM3.digest_length; // 32 bytes for SM3
    const ct_max = (klen + v - 1) / v; // ceil(klen / v)

    var output = try allocator.alloc(u8, klen);
    errdefer allocator.free(output);

    var offset: usize = 0;
    var ct: u32 = 1;

    while (ct <= ct_max) : (ct += 1) {
        var hasher = SM3.init(.{});
        hasher.update(z);

        // Add counter as big-endian 32-bit integer
        var counter_bytes: [4]u8 = undefined;
        mem.writeInt(u32, &counter_bytes, ct, .big);
        hasher.update(&counter_bytes);

        var hash_result: [SM3.digest_length]u8 = undefined;
        hasher.final(&hash_result);

        const bytes_to_copy = @min(v, klen - offset);
        mem.copyForwards(u8, output[offset..offset + bytes_to_copy], hash_result[0..bytes_to_copy]);
        offset += bytes_to_copy;
    }

    return output;
}

/// Compute user identity hash Z_A = SM3(ENTL_A || ID_A || a || b || x_G || y_G || x_A || y_A)
/// as specified in GM/T 0003.2-2012
pub fn computeUserHash(
    user_id: []const u8,
    public_key_x: [32]u8,
    public_key_y: [32]u8,
) [32]u8 {
    var hasher = SM3.init(.{});

    // ENTL_A: Length of user ID in bits as 16-bit big-endian
    const id_bit_len = user_id.len * 8;
    var id_len_bytes: [2]u8 = undefined;
    mem.writeInt(u16, &id_len_bytes, @intCast(id_bit_len), .big);
    hasher.update(&id_len_bytes);

    // ID_A: User ID
    hasher.update(user_id);

    // SM2 curve parameters
    // a = FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
    const a_bytes = [_]u8{
        0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC,
    };
    hasher.update(&a_bytes);

    // b = 28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
    const b_bytes = [_]u8{
        0x28, 0xE9, 0xFA, 0x9E, 0x9D, 0x9F, 0x5E, 0x34, 0x4D, 0x5A, 0x9E, 0x4B,
        0xCF, 0x65, 0x09, 0xA7, 0xF3, 0x97, 0x89, 0xF5, 0x15, 0xAB, 0x8F, 0x92,
        0xDD, 0xBC, 0xBD, 0x41, 0x4D, 0x94, 0x0E, 0x93,
    };
    hasher.update(&b_bytes);

    // x_G: X coordinate of generator point
    const x_g_bytes = [_]u8{
        0x32, 0xC4, 0xAE, 0x2C, 0x1F, 0x19, 0x81, 0x19, 0x5F, 0x99, 0x04, 0x46,
        0x6A, 0x39, 0xC9, 0x94, 0x8F, 0xE3, 0x0B, 0xBF, 0xF2, 0x66, 0x0B, 0xE1,
        0x71, 0x5A, 0x45, 0x89, 0x33, 0x4C, 0x74, 0xC7,
    };
    hasher.update(&x_g_bytes);

    // y_G: Y coordinate of generator point
    const y_g_bytes = [_]u8{
        0xBC, 0x37, 0x36, 0xA2, 0xF4, 0xF6, 0x77, 0x9C, 0x59, 0xBD, 0xCE, 0xE3,
        0x6B, 0x69, 0x21, 0x53, 0xD0, 0xA9, 0x87, 0x7C, 0xC6, 0x2A, 0x47, 0x40,
        0x02, 0xDF, 0x32, 0xE5, 0x21, 0x39, 0xF0, 0xA0,
    };
    hasher.update(&y_g_bytes);

    // x_A, y_A: User public key coordinates
    hasher.update(&public_key_x);
    hasher.update(&public_key_y);

    return hasher.finalResult();
}

/// Simple ASN.1 DER encoding for SM2 signatures
/// Returns R || S format (64 bytes total)
pub const SignatureEncoding = enum {
    raw, // Raw R || S format (64 bytes)
    der, // ASN.1 DER format
};

/// Encode SM2 signature in DER format
/// Input: r and s as 32-byte arrays
/// Output: DER-encoded signature
pub fn encodeSignatureDER(allocator: std.mem.Allocator, r: [32]u8, s: [32]u8) ![]u8 {

    if (isZig015OrNewer) {
        // Simple DER encoding: SEQUENCE { r INTEGER, s INTEGER }
        var buffer: Buffer = .empty;
        defer buffer.deinit(allocator);

        // Helper function to encode integer
        const encodeInteger = struct {
            fn call(buf: *Buffer, allocat: std.mem.Allocator, value: [32]u8) !void {

                try buf.append(allocat, 0x02); // INTEGER tag

                // Find first non-zero byte
                var start: usize = 0;
                while (start < 32 and value[start] == 0) start += 1;

                // If the number is zero
                if (start == 32) {
                    try buf.append(allocat, 0x01); // length
                    try buf.append(allocat, 0x00); // value
                    return;
                }

                // Check if we need to add padding for positive number
                const need_padding = (value[start] & 0x80) != 0;
                const content_len = 32 - start + @as(usize, if (need_padding) 1 else 0);

                try buf.append(allocat, @intCast(content_len)); // length

                if (need_padding) {
                    try buf.append(allocat, 0x00); // padding byte
                }

                try buf.appendSlice(allocat, value[start..]);
            }
        }.call;

        // Encode r
        var r_buffer: Buffer = .empty;
        defer r_buffer.deinit(allocator);
        try encodeInteger(&r_buffer, allocator, r);

        // Encode s
        var s_buffer: Buffer = .empty;
        defer s_buffer.deinit(allocator);
        try encodeInteger(&s_buffer, allocator, s);

        // Build SEQUENCE
        try buffer.append(allocator, 0x30); // SEQUENCE tag
        const content_length = r_buffer.items.len + s_buffer.items.len;
        try buffer.append(allocator, @intCast(content_length)); // length
        try buffer.appendSlice(allocator, r_buffer.items);
        try buffer.appendSlice(allocator, s_buffer.items);

        return try buffer.toOwnedSlice(allocator);
    } else {
        var buffer = Buffer.init(allocator);
        defer buffer.deinit();

        // Helper function to encode integer
        const encodeInteger = struct {
            fn call(buf: *Buffer, allocat: std.mem.Allocator, value: [32]u8) !void {
                _ = allocat;

                try buf.append(0x02); // INTEGER tag
                // Find first non-zero byte
                var start: usize = 0;
                while (start < 32 and value[start] == 0) start += 1;

                // If the number is zero
                if (start == 32) {
                    try buf.append(0x01); // length
                    try buf.append(0x00); // value
                    return;
                }

                // Check if we need to add padding for positive number
                const need_padding = (value[start] & 0x80) != 0;
                const content_len = 32 - start + @as(usize, if (need_padding) 1 else 0);

                try buf.append(@intCast(content_len)); // length

                if (need_padding) {
                    try buf.append(0x00); // padding byte
                }

                try buf.appendSlice(value[start..]);
            }
        }.call;

        // Encode r
        var r_buffer = Buffer.init(allocator);
        defer r_buffer.deinit();
        try encodeInteger(&r_buffer, allocator, r);

        // Encode s
        var s_buffer = Buffer.init(allocator);
        defer s_buffer.deinit();
        try encodeInteger(&s_buffer, allocator, s);

        // Build SEQUENCE
        try buffer.append(0x30); // SEQUENCE tag
        const content_length = r_buffer.items.len + s_buffer.items.len;
        try buffer.append(@intCast(content_length)); // length
        try buffer.appendSlice(r_buffer.items);
        try buffer.appendSlice(s_buffer.items);

        return try buffer.toOwnedSlice();
    }
}

/// Decode DER-encoded SM2 signature
/// Input: DER-encoded signature
/// Output: r and s as 32-byte arrays
pub fn decodeSignatureDER(der_sig: []const u8) !struct { r: [32]u8, s: [32]u8 } {
    if (der_sig.len < 6) return error.InvalidDERSignature;

    var posx: usize = 0;

    // Check SEQUENCE tag
    if (der_sig[posx] != 0x30) return error.InvalidDERSignature;
    posx += 1;

    // Read sequence length
    const seq_len = der_sig[posx];
    posx += 1;

    if (posx + seq_len != der_sig.len) return error.InvalidDERSignature;

    // Helper function to decode integer
    const decodeInteger = struct {
        fn call(data: []const u8, position: *usize) ![32]u8 {
            var pos = position.*;

            // Check INTEGER tag
            if (pos >= data.len or data[pos] != 0x02) return error.InvalidDERSignature;
            pos += 1;

            // Read length
            if (pos >= data.len) return error.InvalidDERSignature;
            const len = data[pos];
            pos += 1;

            if (pos + len > data.len) return error.InvalidDERSignature;

            var result: [32]u8 = [_]u8{0} ** 32;

            // Skip leading zero padding
            var start_pos = pos;
            while (start_pos < pos + len and data[start_pos] == 0) {
                start_pos += 1;
            }

            const actual_len = pos + len - start_pos;
            if (actual_len > 32) return error.InvalidDERSignature;

            const offset = 32 - actual_len;
            mem.copyForwards(u8, result[offset..], data[start_pos..pos + len]);

            position.* = pos + len;
            return result;
        }
    }.call;

    // Decode r
    const r = try decodeInteger(der_sig, &posx);

    // Decode s
    const s = try decodeInteger(der_sig, &posx);

    return .{ .r = r, .s = s };
}

/// Constant-time comparison of byte arrays
pub fn constantTimeEqual(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;

    var diff: u8 = 0;
    for (a, b) |ai, bi| {
        diff |= ai ^ bi;
    }

    return diff == 0;
}

/// Generate cryptographically secure random bytes
pub fn secureRandom(buffer: []u8) void {
    crypto.random.bytes(buffer);
}

test "KDF basic functionality" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const input = "test input";
    const result = try kdf(allocator, input, 32);
    defer allocator.free(result);

    try testing.expect(result.len == 32);
}

test "User hash computation" {
    const testing = std.testing;

    const user_id = "ALICE123@YAHOO.COM";
    const pub_x = [_]u8{0} ** 32;
    const pub_y = [_]u8{0} ** 32;

    const hash = computeUserHash(user_id, pub_x, pub_y);
    try testing.expect(hash.len == 32);
}

test "DER signature encoding/decoding" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const r = [_]u8{0x01} ++ [_]u8{0x00} ** 31;
    const s = [_]u8{0x02} ++ [_]u8{0x00} ** 31;

    const der_sig = try encodeSignatureDER(allocator, r, s);
    defer allocator.free(der_sig);

    const decoded = try decodeSignatureDER(der_sig);

    try testing.expectEqualSlices(u8, &r, &decoded.r);
    try testing.expectEqualSlices(u8, &decoded.s, &s);
}

test "Constant time equality" {
    const testing = std.testing;

    const a = [_]u8{ 1, 2, 3, 4 };
    const b = [_]u8{ 1, 2, 3, 4 };
    const c = [_]u8{ 1, 2, 3, 5 };

    try testing.expect(constantTimeEqual(&a, &b));
    try testing.expect(!constantTimeEqual(&a, &c));
}
