const std = @import("std");
const builtin = @import("builtin");

pub fn Writer(comptime Context: type, comptime WriteError: type, comptime writeFn: fn (context: Context, bytes: []const u8) WriteError!usize) type {
    if (comptime @hasDecl(std.io, "GenericWriter")) {
        // Zig 0.13.0 and earlier
        return std.io.GenericWriter(Context, WriteError, writeFn);
    } else {
        // Zig 0.14.0+
        return std.io.Writer(Context, WriteError, writeFn);
    }
}

// Version detection helper
pub const is_new_zig = !@hasDecl(std.io, "GenericWriter");

// Writer creation helper
pub fn writer(context: anytype, comptime writeFn: anytype) Writer(@TypeOf(context), @TypeOf(@as(@TypeOf(writeFn), undefined)).ReturnType.ErrorSet, writeFn) {
    return .{ .context = context };
}
