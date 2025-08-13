const std = @import("std");
const root = @import("./root.zig");
const sm3 = root.sm3;
const sm4 = root.sm4;
const sm2 = root.sm2;

const builtin = @import("builtin");
pub const io_mode = .disabled;

///导出一个addPoi函数供wasm调用
export fn addPoi(a: i32, b: i32) i32 {
    return a + b;
}

// 使用固定缓冲区简化示例（实际生产环境应使用分配器）
var input_buffer: [1024 * 1024]u8 = undefined; // 1MB 输入缓冲区
var output_buffer: [32]u8 = undefined;         // 固定32字节输出

// 获取输入缓冲区的指针和长度
export fn getInputBufferPtr() [*]u8 {
    return &input_buffer;
}

// 执行哈希计算
export fn sm3Hash(input_len: usize) void {
    const data = input_buffer[0..input_len];
    sm3.SM3.hash(data, &output_buffer, .{});
}

// 获取结果缓冲区的指针
export fn getOutputBufferPtr() [*]const u8 {
    return &output_buffer;
}
///导出一个全局变量
export var lllaaa: i64 = 114514;

pub fn main() !void {
}
