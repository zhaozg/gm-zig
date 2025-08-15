const std = @import("std");
const testing = std.testing;
const compat = @import("../compat.zig");

test "compat version detection" {
    const version_info = compat.getZigVersionInfo();
    
    std.debug.print("Zig version info: is_014_or_later={}, is_015_dev_or_later={}, has_generic_writer={}, has_writer={}, arraylist_has_init={}, has_mem_alignment={}\n", .{
        version_info.is_014_or_later,
        version_info.is_015_dev_or_later,
        version_info.has_generic_writer,
        version_info.has_writer,
        version_info.arraylist_has_init,
        version_info.has_mem_alignment,
    });
    
    // Should have either GenericWriter or Writer (but not both in the same version)
    try testing.expect(version_info.has_generic_writer or version_info.has_writer);
    
    // The version flags should be consistent
    try testing.expect(version_info.is_014_or_later == (!version_info.has_generic_writer));
}

test "compat Writer creation" {
    const TestContext = struct {
        buffer: std.ArrayList(u8),
        allocator: std.mem.Allocator,
        
        const Self = @This();
        const WriteError = std.mem.Allocator.Error;
        
        fn write(self: *Self, bytes: []const u8) WriteError!usize {
            try compat.arrayListAppendSlice(u8, &self.buffer, self.allocator, bytes);
            return bytes.len;
        }
    };
    
    var context = TestContext{
        .buffer = compat.arrayListInit(u8, testing.allocator),
        .allocator = testing.allocator,
    };
    defer compat.arrayListDeinit(u8, &context.buffer, testing.allocator);
    
    // Test that Writer can be created and used
    const WriterType = compat.Writer(*TestContext, TestContext.WriteError, TestContext.write);
    var writer = WriterType{ .context = &context };
    
    try writer.writeAll("Hello, World!");
    try testing.expectEqualStrings("Hello, World!", context.buffer.items);
}

test "compat ArrayList toOwnedSlice" {
    var list = compat.arrayListInit(u8, testing.allocator);
    defer compat.arrayListDeinit(u8, &list, testing.allocator);
    
    try compat.arrayListAppend(u8, &list, testing.allocator, 0x01);
    try compat.arrayListAppend(u8, &list, testing.allocator, 0x02);
    try compat.arrayListAppend(u8, &list, testing.allocator, 0x03);
    
    const owned = try compat.arrayListToOwnedSlice(u8, &list, testing.allocator);
    defer testing.allocator.free(owned);
    
    try testing.expectEqual(@as(usize, 3), owned.len);
    try testing.expectEqual(@as(u8, 0x01), owned[0]);
    try testing.expectEqual(@as(u8, 0x02), owned[1]);
    try testing.expectEqual(@as(u8, 0x03), owned[2]);
}

test "compat alignedAlloc" {
    // Let's try to understand what's going wrong by simplifying the test
    std.debug.print("Testing alignedAlloc compatibility...\n", .{});
    
    const buffer = try compat.alignedAlloc(testing.allocator, u8, 16, 64);
    std.debug.print("Allocated buffer: ptr={*}, len={}\n", .{ buffer.ptr, buffer.len });
    
    defer {
        std.debug.print("About to free buffer...\n", .{});
        testing.allocator.free(buffer);
        std.debug.print("Buffer freed successfully.\n", .{});
    }
    
    try testing.expectEqual(@as(usize, 64), buffer.len);
    
    // Check that the pointer is properly aligned
    const ptr_addr = @intFromPtr(buffer.ptr);
    std.debug.print("Buffer address: 0x{x}, alignment check: {} % 16 = {}\n", .{ ptr_addr, ptr_addr, ptr_addr % 16 });
    try testing.expectEqual(@as(usize, 0), ptr_addr % 16);
    
    // Test that we can write to the buffer
    for (buffer, 0..) |*byte, i| {
        byte.* = @intCast(i % 256);
    }
    
    // Verify the data
    for (buffer, 0..) |byte, i| {
        try testing.expectEqual(@as(u8, @intCast(i % 256)), byte);
    }
    
    std.debug.print("All alignedAlloc tests passed.\n", .{});
}