const std = @import("std");
const builtin = @import("builtin");

// Zig version detection
pub const zig_version = builtin.zig_version;
pub const is_zig_015_or_later = zig_version.order(std.SemanticVersion.parse("0.15.0") catch unreachable) != .lt;

// Writer compatibility - provide a consistent Writer type across Zig versions
pub fn Writer(comptime Context: type, comptime WriteError: type, comptime writeFn: fn (context: Context, bytes: []const u8) WriteError!usize) type {
    if (is_zig_015_or_later) {
        // Zig 0.15.0+ - AnyWriter is the preferred generic writer type
        return std.io.AnyWriter;
    } else {
        // Zig 0.14.1 and earlier - use the parameterized Writer type
        return std.io.Writer(Context, WriteError, writeFn);
    }
}

// Helper function to create a writer instance with version compatibility
pub fn writer(comptime Context: type, comptime WriteError: type, comptime writeFn: fn (context: Context, bytes: []const u8) WriteError!usize, context: Context) Writer(Context, WriteError, writeFn) {
    if (is_zig_015_or_later) {
        // For Zig 0.15.0+, create an AnyWriter
        return std.io.AnyWriter{
            .context = @ptrCast(context),
            .writeFn = @ptrCast(@as(*const fn (*anyopaque, []const u8) anyerror!usize, @ptrCast(writeFn))),
        };
    } else {
        // For Zig 0.14.1 and earlier, create a typed Writer
        return Writer(Context, WriteError, writeFn){ .context = context };
    }
}
