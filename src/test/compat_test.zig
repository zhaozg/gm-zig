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
        
        const Self = @This();
        const WriteError = std.mem.Allocator.Error;
        
        fn write(self: *Self, bytes: []const u8) WriteError!usize {
            try self.buffer.appendSlice(bytes);
            return bytes.len;
        }
    };
    
    var buffer = std.ArrayList(u8).init(testing.allocator);
    defer buffer.deinit();
    
    var context = TestContext{ .buffer = buffer };
    
    // Test that Writer can be created and used
    const WriterType = compat.Writer(*TestContext, TestContext.WriteError, TestContext.write);
    var writer = WriterType{ .context = &context };
    
    try writer.writeAll("Hello, World!");
    try testing.expectEqualStrings("Hello, World!", context.buffer.items);
}