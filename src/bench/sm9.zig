const std = @import("std");
const root = @import("../root.zig");
const sm9 = root.sm9;
const bn = sm9.bn;

const Context = struct {
    allocator: std.mem.Allocator,
    sign_master: sm9.SignMaster,
    encrypt_master: sm9.EncryptMaster,
    sign_key: bn.G1,
    encrypt_key: bn.G2,
    message: [32]u8 = @splat(0x5a),
    signature: sm9.Signature,
    ciphertext: sm9.Ciphertext,
    nonce: bn.Fp = 0x123456789abcdef,

    fn init(allocator: std.mem.Allocator) !Context {
        const sign_master = sm9.standard.signMaster(1);
        const encrypt_master = sm9.standard.encryptMaster(2);
        const sign_key = try sm9.standard.signUserKey(allocator, sign_master, "bench@example.com");
        const encrypt_key = try sm9.standard.encryptUserKey(allocator, encrypt_master, "bench@example.com");
        var self = Context{
            .allocator = allocator,
            .sign_master = sign_master,
            .encrypt_master = encrypt_master,
            .sign_key = sign_key,
            .encrypt_key = encrypt_key,
            .signature = undefined,
            .ciphertext = undefined,
        };
        self.signature = try sm9.standard.sign(allocator, &self.message, sign_key, sign_master.public_key, self.nonce);
        self.ciphertext = try sm9.standard.encrypt(allocator, &self.message, "bench@example.com", encrypt_master.public_key, self.nonce);
        return self;
    }

    fn deinit(self: *Context) void {
        self.allocator.free(self.ciphertext.C2);
    }
};

var ctx: ?Context = null;

fn get(allocator: std.mem.Allocator) *Context {
    if (ctx == null) ctx = Context.init(allocator) catch unreachable;
    return &ctx.?;
}

pub fn benchSm9Pairing(allocator: std.mem.Allocator) void {
    _ = allocator;
    _ = sm9.pairing.pairing(bn.P1, bn.P2);
}

pub fn benchSm9KeyExtractSign(allocator: std.mem.Allocator) void {
    const c = get(allocator);
    _ = sm9.standard.signUserKey(allocator, c.sign_master, "bench@example.com") catch return;
}

pub fn benchSm9Sign(allocator: std.mem.Allocator) void {
    const c = get(allocator);
    _ = sm9.standard.sign(allocator, &c.message, c.sign_key, c.sign_master.public_key, c.nonce) catch return;
}

pub fn benchSm9Verify(allocator: std.mem.Allocator) void {
    const c = get(allocator);
    _ = sm9.standard.verify(allocator, &c.message, c.signature, "bench@example.com", c.sign_master.public_key) catch return;
}

pub fn benchSm9Encrypt(allocator: std.mem.Allocator) void {
    const c = get(allocator);
    const ct = sm9.standard.encrypt(allocator, &c.message, "bench@example.com", c.encrypt_master.public_key, c.nonce) catch return;
    allocator.free(ct.C2);
}

pub fn benchSm9Decrypt(allocator: std.mem.Allocator) void {
    const c = get(allocator);
    const pt = sm9.standard.decrypt(allocator, c.ciphertext, "bench@example.com", c.encrypt_key) catch return;
    allocator.free(pt);
}
