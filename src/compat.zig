const std = @import("std");
const builtin = @import("builtin");

// Zig version detection
pub const zig_version = builtin.zig_version;
pub const is_zig_015_or_later = zig_version.order(std.SemanticVersion.parse("0.15.0") catch unreachable) != .lt;

// Writer compatibility - provide a consistent Writer type across Zig versions
pub fn Writer(comptime Context: type, comptime WriteError: type, comptime writeFn: fn (context: Context, bytes: []const u8) WriteError!usize) type {
    if (is_zig_015_or_later) {
        // Zig 0.15.0+ uses AnyWriter for generic writer operations
        return std.io.AnyWriter;
    } else {
        // Zig 0.14.1 and earlier use the parameterized Writer type
        return std.io.Writer(Context, WriteError, writeFn);
    }
}

// Helper function to create a writer instance with version compatibility
pub fn writer(comptime Context: type, comptime WriteError: type, comptime writeFn: fn (context: Context, bytes: []const u8) WriteError!usize, context: Context) Writer(Context, WriteError, writeFn) {
    if (is_zig_015_or_later) {
        // For Zig 0.15.0+, convert to AnyWriter
        const typed_writer = std.io.Writer(Context, WriteError, writeFn){ .context = context };
        return typed_writer.any();
    } else {
        // For Zig 0.14.1 and earlier, return the typed Writer directly
        return std.io.Writer(Context, WriteError, writeFn){ .context = context };
    }
}
