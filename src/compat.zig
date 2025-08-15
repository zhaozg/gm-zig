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
        // Zig 0.15.0-dev+ - use new initialization pattern without allocator field
        return ArrayListType{
            .items = &[_]T{},
            .capacity = 0,
        };
    }
}

/// Cross-version compatible ArrayList.append
pub fn arrayListAppend(comptime T: type, list: *std.ArrayList(T), allocator: std.mem.Allocator, item: T) !void {
    // Try the new API first (Zig 0.15.0-dev+), then fall back to old API
    if (comptime is_zig_015_dev) {
        // Zig 0.15.0-dev+ - requires allocator parameter
        try list.append(allocator, item);
    } else {
        // Zig 0.14.1 and earlier - no allocator parameter
        try list.append(item);
    }
}

/// Cross-version compatible ArrayList.appendSlice
pub fn arrayListAppendSlice(comptime T: type, list: *std.ArrayList(T), allocator: std.mem.Allocator, items: []const T) !void {
    // Try the new API first (Zig 0.15.0-dev+), then fall back to old API
    if (comptime is_zig_015_dev) {
        // Zig 0.15.0-dev+ - requires allocator parameter
        try list.appendSlice(allocator, items);
    } else {
        // Zig 0.14.1 and earlier - no allocator parameter
        try list.appendSlice(items);
    }
}

/// Cross-version compatible ArrayList.deinit
pub fn arrayListDeinit(comptime T: type, list: *std.ArrayList(T), allocator: std.mem.Allocator) void {
    // Try the new API first (Zig 0.15.0-dev+), then fall back to old API
    if (comptime is_zig_015_dev) {
        // Zig 0.15.0-dev+ - requires allocator parameter
        list.deinit(allocator);
    } else {
        // Zig 0.14.1 and earlier - no allocator parameter
        list.deinit();
    }
}

/// Cross-version compatible ArrayList.toOwnedSlice
pub fn arrayListToOwnedSlice(comptime T: type, list: *std.ArrayList(T), allocator: std.mem.Allocator) ![]T {
    // Try the new API first (Zig 0.15.0-dev+), then fall back to old API
    if (comptime is_zig_015_dev) {
        // Zig 0.15.0-dev+ - requires allocator parameter
        return try list.toOwnedSlice(allocator);
    } else {
        // Zig 0.14.1 and earlier - no allocator parameter
        return try list.toOwnedSlice();
    }
}

/// Cross-version compatible Allocator.alignedAlloc
pub fn alignedAlloc(allocator: std.mem.Allocator, comptime T: type, alignment: comptime_int, n: usize) ![]T {
    // Use the same version detection as ArrayList - check for Zig 0.15.0-dev+
    if (comptime is_zig_015_dev) {
        // Zig 0.15.0-dev+ - alignedAlloc expects ?mem.Alignment enum
        // Map common alignment values explicitly to avoid enum conversion issues
        const alignment_enum = switch (alignment) {
            1 => @as(std.mem.Alignment, @enumFromInt(1)),
            2 => @as(std.mem.Alignment, @enumFromInt(2)),
            4 => @as(std.mem.Alignment, @enumFromInt(4)),
            8 => @as(std.mem.Alignment, @enumFromInt(8)),
            16 => @as(std.mem.Alignment, @enumFromInt(16)),
            32 => @as(std.mem.Alignment, @enumFromInt(32)),
            64 => @as(std.mem.Alignment, @enumFromInt(64)),
            128 => @as(std.mem.Alignment, @enumFromInt(128)),
            256 => @as(std.mem.Alignment, @enumFromInt(256)),
            else => {
                // For unsupported alignment values, fall back to regular allocation
                return try allocator.alloc(T, n);
            },
        };
        return try allocator.alignedAlloc(T, alignment_enum, n);
    } else {
        // Zig 0.14.1 and earlier - alignedAlloc expects ?u29
        return try allocator.alignedAlloc(T, alignment, n);
    }
}

/// Cross-version compatible free for aligned allocations
/// Note: For aligned allocations, the same allocator should be used for both alloc and free
pub fn alignedFree(allocator: std.mem.Allocator, buffer: anytype) void {
    allocator.free(buffer);
}

/// Version detection helper - true for Zig 0.14.0+
pub const is_new_zig = !@hasDecl(std.io, "GenericWriter");

/// Version detection helper - true for Zig 0.15.0-dev+
pub const is_zig_015_dev = blk: {
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
    has_mem_alignment: bool,
} {
    const TestList = std.ArrayList(u8);
    return .{
        .is_014_or_later = is_new_zig,
        .is_015_dev_or_later = is_zig_015_dev,
        .has_generic_writer = @hasDecl(std.io, "GenericWriter"),
        .has_writer = @hasDecl(std.io, "Writer"),
        .arraylist_has_init = @hasDecl(TestList, "init"),
        .has_mem_alignment = @hasDecl(std.mem, "Alignment"),
    };
}