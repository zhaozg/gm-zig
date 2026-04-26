const std = @import("std");
const builtin = @import("builtin");

/// CSPRNG random number generator module.
/// Provides cryptographically secure random bytes using system entropy.
/// For WASM targets, falls back to Web Crypto API via wasmRng.

/// Fill buffer with cryptographically secure random bytes.
/// Uses system CSPRNG on native targets, Web Crypto API on WASM.
pub fn bytes(io: std.Io, buffer: []u8) void {
    if (builtin.os.tag == .freestanding) {
        // WASM target: use Web Crypto API via wasmRng
        const wasmRng = @import("wasmRng.zig");
        wasmRng.random(buffer);
    } else {
        std.Io.random(io, buffer);
    }
}


test "random.bytes fills buffer" {
    var buf: [32]u8 = undefined;
    bytes(std.testing.io, &buf);

    // Verify buffer is not all zeros (extremely unlikely for CSPRNG)
    var all_zero = true;
    for (buf) |byte| {
        if (byte != 0) {
            all_zero = false;
            break;
        }
    }
    try std.testing.expect(!all_zero);
}

test "random.bytes produces different values" {
    var buf1: [32]u8 = undefined;
    var buf2: [32]u8 = undefined;
    bytes(std.testing.io, &buf1);
    bytes(std.testing.io, &buf2);

    // Verify two consecutive calls produce different results
    var same = true;
    for (buf1, buf2) |b1, b2| {
        if (b1 != b2) {
            same = false;
            break;
        }
    }
    try std.testing.expect(!same);
}
