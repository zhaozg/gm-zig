// Updated to handle Zig 0.15.0+ Writer API

const std = @import("std");

// Define a new type using std.io.AnyWriter
const MyWriter = std.io.AnyWriter;

// Create a writer function that uses std.io.AnyWriter
fn createWriter() MyWriter {
    const allocator = std.heap.page_allocator;
    const writer = MyWriter.init(allocator);
    // Additional writer setup can go here if needed
    return writer;
}

// Example usage of MyWriter
fn main() void {
    const writer = createWriter();
    // Use the writer for your operations
}