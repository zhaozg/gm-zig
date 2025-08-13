const std = @import("std");
const builtin = @import("builtin");

/// Version compatibility utilities for supporting both Zig 0.14.1 and 0.15.0-dev
pub const zig_version = builtin.zig_version;

/// Check if running on Zig 0.15.0 or later
pub const is_zig_015_or_later = zig_version.order(std.SemanticVersion.parse("0.15.0") catch unreachable) != .lt;

/// Helper to create std.io.Writer with version compatibility
/// Handle the API change where std.io.Writer became a type in 0.15.0-dev
pub fn Writer(
    comptime Context: type,
    comptime Error: type,
    comptime writeFn: fn (context: Context, bytes: []const u8) Error!usize,
) type {
    return if (is_zig_015_or_later)
        // For Zig 0.15.0+: Use std.io.GenericWriter (likely replacement)
        std.io.GenericWriter(Context, Error, writeFn)
    else
        // For Zig 0.14.1: Use std.io.Writer as function
        std.io.Writer(Context, Error, writeFn);
}

/// Helper to get default PRNG with version compatibility
/// std.Random.DefaultPrng might have changed between versions
pub fn DefaultPrng() type {
    return std.Random.DefaultPrng;
}

/// Helper to get timestamp with version compatibility
/// std.time.nanoTimestamp might have changed between versions  
pub fn nanoTimestamp() i128 {
    return std.time.nanoTimestamp();
}