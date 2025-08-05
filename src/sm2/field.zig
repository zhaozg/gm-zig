const std = @import("std");
const common = @import("../common.zig");

const Field = common.Field;

pub const Fe = Field(.{
    .fiat = @import("sm2_64.zig"),
    .field_order = 115792089210356248756420345214020892766250353991924191454421193933289684991999,
    .field_bits = 256,
    .saturated_bits = 256,
    .encoded_length = 32,
});

