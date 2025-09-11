const std = @import("std");
const builtin = @import("builtin");

pub fn Writer(comptime Context: type, comptime WriteError: type, comptime writeFn: fn (context: Context, bytes: []const u8) WriteError!usize) type {
    // Check for Zig version compatibility
    if (comptime builtin.zig_version.minor < 14) {
        @compileError("Zig version 0.14 or newer is required");
    }

    // Zig 0.15+ uses std.io.GenericWriter (the old Writer is deprecated)
    if (comptime builtin.zig_version.minor >= 15) {
        return std.io.GenericWriter(Context, WriteError, writeFn);
    }

    // Zig 0.14.x uses std.io.Writer
    return std.io.Writer(Context, WriteError, writeFn);
}

// Version detection helper - always true for supported versions
pub const is_new_zig = true;

// Writer creation helper
pub fn writer(context: anytype, comptime writeFn: anytype) Writer(@TypeOf(context), @TypeOf(@as(@TypeOf(writeFn), undefined)).ReturnType.ErrorSet, writeFn) {
    return .{ .context = context };
}
