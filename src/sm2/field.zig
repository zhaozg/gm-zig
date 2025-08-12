const std = @import("std");
const common = @import("../common.zig");

const Field = common.Field;

pub const Fe = Field(.{
    .fiat = @import("sm2_64.zig"),
    .field_order = 0xfffffffeffffffffffffffffffffffffffffffff00000000ffffffffffffffff,
    .field_bits = 256,
    .saturated_bits = 256,
    .encoded_length = 32,
});
