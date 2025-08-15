const std = @import("std");
const builtin = @import("builtin");

/// Cross-version compatible Writer implementation
/// Supports Zig 0.13.0 through 0.15.0+ including development versions
pub fn Writer(comptime Context: type, comptime WriteError: type, comptime writeFn: fn (context: Context, bytes: []const u8) WriteError!usize) type {
    if (comptime @hasDecl(std.io, "GenericWriter")) {
        // Zig 0.13.0 and earlier versions
        return std.io.GenericWriter(Context, WriteError, writeFn);
    } else {
        // Zig 0.14.0+ (including 0.14.1, 0.15.0-dev, and future versions)
        return std.io.Writer(Context, WriteError, writeFn);
    }
}

/// Version detection helper - true for Zig 0.14.0+
pub const is_new_zig = !@hasDecl(std.io, "GenericWriter");

/// Get Zig version information for debugging
pub fn getZigVersionInfo() struct {
    is_014_or_later: bool,
    has_generic_writer: bool,
    has_writer: bool,
} {
    return .{
        .is_014_or_later = is_new_zig,
        .has_generic_writer = @hasDecl(std.io, "GenericWriter"),
        .has_writer = @hasDecl(std.io, "Writer"),
    };
}