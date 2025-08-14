const std = @import("std");
const root = @import("./root.zig");
const sm3 = root.sm3;
const sm4 = root.sm4;
const sm2 = root.sm2;

pub const panic = customPanic;
fn customPanic(msg: []const u8, error_return_trace: ?*std.builtin.StackTrace, ret_addr: ?usize) noreturn {
    _ = msg;
    _ = error_return_trace;
    _ = ret_addr;
    while (true) {}
}

// 自定义内存分配器
const allocator: std.mem.Allocator = .{
    .ptr = undefined,
    .vtable = &std.heap.WasmAllocator.vtable,
};

const builtin = @import("builtin");
pub const io_mode = .disabled;

///导出一个addPoi函数供wasm调用
export fn version() i32 {
    return 0;
}

export fn alloc(size: usize) [*]u8 {
    const ptr = allocator.alloc(u8, size) catch @panic("allocation failed");
    return ptr.ptr;
}
export fn free(ptr: [*]u8, size: usize) void {
    const slice = ptr[0..size];
    allocator.free(slice);
}

// 导出给 WASM 调用的函数
export fn sm3hash(input_ptr: [*]const u8, input_len: usize, output_ptr: [*]u8) void {
    // 处理输入切片
    const input = input_ptr[0..input_len];
    // 处理输出缓冲区
    const output: [32]u8 = sm3.hash(input);
    std.mem.copyForwards(u8, output_ptr[0..32], &output);
}

export fn sm3hmac(key_ptr: [*]const u8, key_len: usize,
                 input_ptr: [*]const u8, input_len: usize, output_ptr: [*]u8) void {
    // 处理输入切片
    const input = input_ptr[0..input_len];
    // 处理输出缓冲区
    const output: [32]u8 = sm3.hmac(key_ptr[0..key_len], input);
    std.mem.copyForwards(u8, output_ptr[0..32], &output);
}

export fn sm4cbc(key_ptr: [*]const u8, iv_ptr: [*]const u8, encrypt: bool,
                 input_ptr: [*]const u8, input_len: usize, output_ptr: [*]u8) void {
    // 处理输入切片
    const input = input_ptr[0..input_len];
    // 处理输出缓冲区
    const output: []u8 = output_ptr[0..input_len];

    var ctx = sm4.SM4_CBC.init(key_ptr[0..16], iv_ptr[0..16]);
    if (encrypt) {
        ctx.encrypt(input, output);
    } else {
        ctx.decrypt(input, output);
    }
}

pub fn main() !void { }
