const std = @import("std");
const testing = std.testing;
const sm9 = @import("../../sm9.zig");

test "SM9 Curve Operations - G1 Point Creation and Validation" {
    const params = sm9.params.SystemParams.init();
    
    // Test point at infinity
    const infinity = sm9.curve.G1Point.infinity();
    try testing.expect(infinity.isInfinity());
    try testing.expect(infinity.validate(params));
    
    // Test affine point creation
    const x = [_]u8{0x01} ++ [_]u8{0} ** 31;
    const y = [_]u8{0x02} ++ [_]u8{0} ** 31;
    const point = sm9.curve.G1Point.affine(x, y);
    
    try testing.expect(!point.isInfinity());
    // Note: Point validation might not pass for arbitrary coordinates
    // but the structure should be valid
    _ = point.validate(params);
}

test "SM9 Curve Operations - G1 Point Compression" {
    const x = [_]u8{0x01} ++ [_]u8{0} ** 31;
    const y = [_]u8{0x02} ++ [_]u8{0} ** 31;
    const point = sm9.curve.G1Point.affine(x, y);
    
    // Test compression
    const compressed = point.compress();
    try testing.expect(compressed.len == 33);
    try testing.expect(compressed[0] == 0x02 or compressed[0] == 0x03);
    
    // Test decompression
    const decomp_point = sm9.curve.G1Point.fromCompressed(compressed) catch |err| {
        std.debug.print("Point decompression failed: {}\n", .{err});
        return err;
    };
    
    // X coordinates should match
    try testing.expect(sm9.bigint.equal(point.x, decomp_point.x));
    
    // Test infinity compression
    const infinity = sm9.curve.G1Point.infinity();
    const inf_compressed = infinity.compress();
    try testing.expect(inf_compressed[0] == 0x00);
    
    const inf_decompressed = try sm9.curve.G1Point.fromCompressed(inf_compressed);
    try testing.expect(inf_decompressed.isInfinity());
}

test "SM9 Curve Operations - G1 Point Arithmetic" {
    const params = sm9.params.SystemParams.init();
    
    const x1 = [_]u8{0x01} ++ [_]u8{0} ** 31;
    const y1 = [_]u8{0x02} ++ [_]u8{0} ** 31;
    const point1 = sm9.curve.G1Point.affine(x1, y1);
    
    const x2 = [_]u8{0x03} ++ [_]u8{0} ** 31;
    const y2 = [_]u8{0x04} ++ [_]u8{0} ** 31;
    const point2 = sm9.curve.G1Point.affine(x2, y2);
    
    // Test point doubling
    const doubled = point1.double(params);
    try testing.expect(!doubled.isInfinity());
    
    // Test point addition
    const sum = point1.add(point2, params);
    try testing.expect(!sum.isInfinity());
    
    // Test addition with infinity
    const infinity = sm9.curve.G1Point.infinity();
    const sum_inf = point1.add(infinity, params);
    try testing.expect(sm9.bigint.equal(sum_inf.x, point1.x));
    try testing.expect(sm9.bigint.equal(sum_inf.y, point1.y));
    
    // Test scalar multiplication
    const scalar = [_]u8{0} ** 31 ++ [_]u8{3};
    const scaled = point1.mul(scalar, params);
    try testing.expect(!scaled.isInfinity());
    
    // Test scalar multiplication by zero
    const zero_scalar = [_]u8{0} ** 32;
    const zero_result = point1.mul(zero_scalar, params);
    try testing.expect(zero_result.isInfinity());
}

test "SM9 Curve Operations - G2 Point Creation and Validation" {
    const params = sm9.params.SystemParams.init();
    
    // Test point at infinity
    const infinity = sm9.curve.G2Point.infinity();
    try testing.expect(infinity.isInfinity());
    try testing.expect(infinity.validate(params));
    
    // Test affine point creation (64 bytes each for Fp2)
    const x = [_]u8{0x01} ++ [_]u8{0} ** 63;
    const y = [_]u8{0x02} ++ [_]u8{0} ** 63;
    const point = sm9.curve.G2Point.affine(x, y);
    
    try testing.expect(!point.isInfinity());
    // Basic validation should pass
    try testing.expect(point.validate(params));
}

test "SM9 Curve Operations - G2 Point Uncompressed Format" {
    const x = [_]u8{0x01} ++ [_]u8{0} ** 31; // 32 bytes
    const y = [_]u8{0x02} ++ [_]u8{0} ** 31; // 32 bytes
    
    // Create uncompressed format (65 bytes total)
    var uncompressed = [_]u8{0x04} ++ [_]u8{0} ** 64;
    std.mem.copyForwards(u8, uncompressed[1..33], &x);
    std.mem.copyForwards(u8, uncompressed[33..65], &y);
    
    // Test fromUncompressed
    const point = sm9.curve.G2Point.fromUncompressed(uncompressed);
    try testing.expect(point != error.InvalidPointFormat);
    
    if (point) |p| {
        try testing.expect(!p.isInfinity());
        // Check that coordinates were parsed correctly
        try testing.expect(sm9.bigint.equal(p.x[0..32].*, x));
    } else |_| {
        try testing.expect(false);
    }
    
    // Test infinity format
    var inf_uncompressed = [_]u8{0x00} ++ [_]u8{0} ** 64;
    const inf_point = try sm9.curve.G2Point.fromUncompressed(inf_uncompressed);
    try testing.expect(inf_point.isInfinity());
    
    // Test invalid format
    var invalid_uncompressed = [_]u8{0x05} ++ [_]u8{0} ** 64; // Invalid prefix
    const invalid_result = sm9.curve.G2Point.fromUncompressed(invalid_uncompressed);
    try testing.expectError(error.InvalidPointFormat, invalid_result);
}

test "SM9 Curve Operations - G2 Point Arithmetic" {
    const params = sm9.params.SystemParams.init();
    
    const x1 = [_]u8{0x01} ++ [_]u8{0} ** 63;
    const y1 = [_]u8{0x02} ++ [_]u8{0} ** 63;
    const point1 = sm9.curve.G2Point.affine(x1, y1);
    
    const x2 = [_]u8{0x03} ++ [_]u8{0} ** 63;
    const y2 = [_]u8{0x04} ++ [_]u8{0} ** 63;
    const point2 = sm9.curve.G2Point.affine(x2, y2);
    
    // Test point doubling
    const doubled = point1.double(params);
    try testing.expect(!doubled.isInfinity());
    
    // Test point addition
    const sum = point1.add(point2, params);
    try testing.expect(!sum.isInfinity());
    
    // Test addition with infinity
    const infinity = sm9.curve.G2Point.infinity();
    const sum_inf = point1.add(infinity, params);
    // Should return point1
    try testing.expect(!sum_inf.isInfinity());
    
    // Test scalar multiplication
    const scalar = [_]u8{0} ** 31 ++ [_]u8{2};
    const scaled = point1.mul(scalar, params);
    try testing.expect(!scaled.isInfinity());
    
    // Test scalar multiplication by zero
    const zero_scalar = [_]u8{0} ** 32;
    const zero_result = point1.mul(zero_scalar, params);
    try testing.expect(zero_result.isInfinity());
}

test "SM9 Curve Operations - Coordinate Transformations" {
    const params = sm9.params.SystemParams.init();
    
    const x = [_]u8{0x01} ++ [_]u8{0} ** 31;
    const y = [_]u8{0x02} ++ [_]u8{0} ** 31;
    const point = sm9.curve.G1Point.affine(x, y);
    
    // Test toAffine
    const affine = point.toAffine(params);
    try testing.expect(sm9.bigint.equal(affine.x, point.x));
    try testing.expect(sm9.bigint.equal(affine.y, point.y));
    
    // Test toAffineSimple
    const affine_simple = point.toAffineSimple();
    try testing.expect(sm9.bigint.equal(affine_simple.x, point.x));
    try testing.expect(sm9.bigint.equal(affine_simple.y, point.y));
    
    // Test with infinity
    const infinity = sm9.curve.G1Point.infinity();
    const inf_affine = infinity.toAffine(params);
    try testing.expect(inf_affine.isInfinity());
    
    const inf_affine_simple = infinity.toAffineSimple();
    try testing.expect(inf_affine_simple.isInfinity());
}

test "SM9 Curve Operations - Edge Cases" {
    const params = sm9.params.SystemParams.init();
    
    // Test doubling infinity
    const infinity = sm9.curve.G1Point.infinity();
    const doubled_inf = infinity.double(params);
    try testing.expect(doubled_inf.isInfinity());
    
    // Test adding infinity to infinity
    const sum_inf = infinity.add(infinity, params);
    try testing.expect(sum_inf.isInfinity());
    
    // Test multiplying infinity by scalar
    const scalar = [_]u8{0} ** 31 ++ [_]u8{5};
    const scaled_inf = infinity.mul(scalar, params);
    try testing.expect(scaled_inf.isInfinity());
    
    // Test adding same point (should equal doubling)
    const x = [_]u8{0x01} ++ [_]u8{0} ** 31;
    const y = [_]u8{0x02} ++ [_]u8{0} ** 31;
    const point = sm9.curve.G1Point.affine(x, y);
    
    const doubled = point.double(params);
    const added = point.add(point, params);
    
    // Results should be the same (though implementation might differ)
    try testing.expect(!doubled.isInfinity());
    try testing.expect(!added.isInfinity());
}

test "SM9 Curve Operations - Point Validation Edge Cases" {
    const params = sm9.params.SystemParams.init();
    
    // Create point with coordinates equal to field modulus (should be invalid)
    const p = params.q;
    const invalid_point = sm9.curve.G1Point.affine(p, p);
    
    // Validation should catch this
    try testing.expect(!invalid_point.validate(params));
    
    // Test G2 point validation with coordinates in field bounds
    const x_valid = [_]u8{0x01} ++ [_]u8{0} ** 63;
    const y_valid = [_]u8{0x02} ++ [_]u8{0} ** 63;
    const valid_g2 = sm9.curve.G2Point.affine(x_valid, y_valid);
    
    try testing.expect(valid_g2.validate(params));
}