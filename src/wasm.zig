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

export fn sm2genKeyPair(priKey: [*]u8, pubKey: [*]u8) void {
    var priKeySlice: [32]u8 = undefined;
    for (0..32) |i| {
        priKeySlice[i] = priKey[i];
    }

    const key_pair = sm2.signature.KeyPair.fromPrivateKey(priKeySlice) catch @panic("key generation failed");
    // Verify public key is valid (not identity element)
    key_pair.public_key.rejectIdentity() catch @panic("invalid public key");

    std.mem.copyForwards(u8, priKey[0..32], &key_pair.private_key);
    const uncompressed = key_pair.getPublicKeyUncompressed();
    std.mem.copyForwards(u8, pubKey[0..65], &uncompressed);
}

// export fn sm2sign(priKey: [*]const u8, msg: [*]const u8, msg_len: usize, signature: [*]u8) void {
//     var priKeySlice: [32]u8 = undefined;
//     for (0..32) |i| {
//         priKeySlice[i] = priKey[i];
//     }
//
//     const key_pair = sm2.signature.KeyPair.fromPrivateKey(priKeySlice) catch return;
//     // Verify public key is valid (not identity element)
//     key_pair.public_key.rejectIdentity() catch return;
//
//     const msgSlice = msg[0..msg_len];
//
//     const options = sm2.signature.SignatureOptions{};
//     const sig = try sm2.signature.sign(msgSlice, key_pair.private_key, key_pair.public_key, options);
//     std.mem.copyForwards(u8, signature[0..sig.len], &sig);
// }
//
// export fn sm2verify(pubKey: [*]const u8, msg: [*]const u8, msg_len: usize, signature: [*]const u8, sig_len: usize) bool {
//     const pubKeySlice = pubKey[0..65];
//     const msgSlice = msg[0..msg_len];
//     const sigSlice = signature[0..sig_len];
//     const options = sm2.signature.SignatureOptions{};
//
//     const public_key = sm2.signature.KeyPair.fromUncompressed(pubKeySlice) catch return false;
//     // Verify public key is valid (not identity element)
//     public_key.rejectIdentity() catch return false;
//
//
//     // But both should verify
//     const valid = try sm2.signature.verify(msgSlice, sigSlice, public_key, options);
//     return valid;
// }
//
pub fn main() !void { }
