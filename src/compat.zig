const std = @import("std");
const builtin = @import("builtin");

pub fn Writer(comptime Context: type, comptime WriteError: type, comptime writeFn: fn (context: Context, bytes: []const u8) WriteError!usize) type {
    if (comptime @hasDecl(std.io, "GenericWriter")) {
        // Zig 0.13.0 and earlier (for backward compatibility)
        return std.io.GenericWriter(Context, WriteError, writeFn);
    } else {
        // Zig 0.14.0+ (including 0.14.1 and 0.15.0-dev)
        return std.io.Writer(Context, WriteError, writeFn);
    }
}

// Version detection helper for debugging/conditional compilation if needed
pub const is_new_zig = !@hasDecl(std.io, "GenericWriter");