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

/// Cross-version compatible ArrayList initialization
/// In Zig 0.15.0-dev, ArrayList.init was removed and replaced with direct initialization
pub fn arrayListInit(comptime T: type, allocator: std.mem.Allocator) std.ArrayList(T) {
    const ArrayListType = std.ArrayList(T);
    
    // Check if the old init method exists (Zig 0.14.1 and earlier)
    if (comptime @hasDecl(ArrayListType, "init")) {
        return ArrayListType.init(allocator);
    } else {
        // Zig 0.15.0-dev+ - use new initialization pattern
        return ArrayListType{
            .items = &[_]T{},
            .capacity = 0,
            .allocator = allocator,
        };
    }
}

/// Version detection helper - true for Zig 0.14.0+
pub const is_new_zig = !@hasDecl(std.io, "GenericWriter");

/// Version detection helper - true for Zig 0.15.0-dev+
pub const is_zig_015_dev = comptime blk: {
    // Try to detect 0.15.0-dev by checking if ArrayList.init exists
    const TestList = std.ArrayList(u8);
    break :blk !@hasDecl(TestList, "init");
};

/// Get Zig version information for debugging
pub fn getZigVersionInfo() struct {
    is_014_or_later: bool,
    is_015_dev_or_later: bool,
    has_generic_writer: bool,
    has_writer: bool,
    arraylist_has_init: bool,
} {
    const TestList = std.ArrayList(u8);
    return .{
        .is_014_or_later = is_new_zig,
        .is_015_dev_or_later = is_zig_015_dev,
        .has_generic_writer = @hasDecl(std.io, "GenericWriter"),
        .has_writer = @hasDecl(std.io, "Writer"),
        .arraylist_has_init = @hasDecl(TestList, "init"),
    };
}