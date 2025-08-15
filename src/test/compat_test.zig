const std = @import("std");
const testing = std.testing;
const compat = @import("../compat.zig");

test "compat version detection" {
    const version_info = compat.getZigVersionInfo();
    
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
    
    var buffer = compat.arrayListInit(u8, testing.allocator);
    defer compat.arrayListDeinit(u8, &buffer, testing.allocator);
    
    var context = TestContext{ .buffer = buffer, .allocator = testing.allocator };
    
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