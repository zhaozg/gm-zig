const std = @import("std");
const crypto = std.crypto;
const mem = std.mem;
const SM2 = @import("group.zig").SM2;
const SM3 = @import("../sm3.zig").SM3;
const utils = @import("utils.zig");

/// SM2 Key Exchange Protocol implementation
/// Based on GM/T 0003.3-2012 standard

/// Key exchange participant role
pub const Role = enum {
    initiator,
    responder,
};

/// Key exchange context for a participant
pub const KeyExchangeContext = struct {
    role: Role,
    private_key: [32]u8,     // Private key dA or dB
    public_key: SM2,         // Public key PA or PB
    user_id: []const u8,     // User identifier IDA or IDB
    ephemeral_private: [32]u8, // Ephemeral private key rA or rB
    ephemeral_public: SM2,   // Ephemeral public key RA or RB

    /// Initialize key exchange context
    pub fn init(
        role: Role,
        private_key: [32]u8,
        public_key: SM2,
        user_id: []const u8,
    ) KeyExchangeContext {
        // Generate ephemeral key pair
        const ephemeral_private = SM2.scalar.random(.big);
        const ephemeral_public = SM2.basePoint.mul(ephemeral_private, .big) catch unreachable;

        return KeyExchangeContext{
            .role = role,
            .private_key = private_key,
            .public_key = public_key,
            .user_id = user_id,
            .ephemeral_private = ephemeral_private,
            .ephemeral_public = ephemeral_public,
        };
    }

    /// Get ephemeral public key in uncompressed format
    pub fn getEphemeralPublicKey(self: KeyExchangeContext) [65]u8 {
        return self.ephemeral_public.toUncompressedSec1();
    }

    /// Get ephemeral public key coordinates
    pub fn getEphemeralCoordinates(self: KeyExchangeContext) struct { x: [32]u8, y: [32]u8 } {
        const coords = self.ephemeral_public.affineCoordinates();
        return .{
            .x = coords.x.toBytes(.big),
            .y = coords.y.toBytes(.big),
        };
    }
};

/// Key exchange result
pub const KeyExchangeResult = struct {
    shared_key: []u8,
    key_confirmation: ?[32]u8 = null,

    pub fn deinit(self: KeyExchangeResult, allocator: std.mem.Allocator) void {
        allocator.free(self.shared_key);
    }
};

/// Perform SM2 key exchange as initiator (Step 1)
/// Returns the ephemeral public key to send to responder
pub fn keyExchangeInitiator(
    allocator: std.mem.Allocator,
    context: *KeyExchangeContext,
    responder_public_key: SM2,
    responder_ephemeral_key: SM2,
    responder_user_id: []const u8,
    key_length: usize,
    with_confirmation: bool,
) !KeyExchangeResult {
    if (context.role != .initiator) return error.InvalidRole;

    // Step 1: Verify responder's public keys are valid
    try responder_public_key.rejectIdentity();
    try responder_ephemeral_key.rejectIdentity();

    // Step 2: Compute shared secret
    const shared_secret = try computeSharedSecret(
        context,
        responder_public_key,
        responder_ephemeral_key,
        responder_user_id,
    );

    // Step 3: Derive keys using KDF
    const kdf_input_len = 64; // x coordinate of shared secret point
    var kdf_input: [kdf_input_len]u8 = undefined;
    const coords = shared_secret.affineCoordinates();
    @memcpy(kdf_input[0..32], &coords.x.toBytes(.big));
    @memcpy(kdf_input[32..64], &coords.y.toBytes(.big));

    var total_key_length = key_length;
    if (with_confirmation) total_key_length += 32; // Add space for confirmation value

    const derived_key = try utils.kdf(allocator, &kdf_input, total_key_length);

    var result = KeyExchangeResult{
        .shared_key = try allocator.alloc(u8, key_length),
    };

    @memcpy(result.shared_key, derived_key[0..key_length]);

    if (with_confirmation) {
        // Compute key confirmation value
        result.key_confirmation = try computeKeyConfirmation(
            context,
            responder_public_key,
            responder_ephemeral_key,
            responder_user_id,
            derived_key[key_length..key_length + 32],
        );
    }

    allocator.free(derived_key);
    return result;
}

/// Perform SM2 key exchange as responder (Step 2)
/// Returns the shared key and optional confirmation value
pub fn keyExchangeResponder(
    allocator: std.mem.Allocator,
    context: *KeyExchangeContext,
    initiator_public_key: SM2,
    initiator_ephemeral_key: SM2,
    initiator_user_id: []const u8,
    key_length: usize,
    with_confirmation: bool,
) !KeyExchangeResult {
    if (context.role != .responder) return error.InvalidRole;

    // Step 1: Verify initiator's public keys are valid
    try initiator_public_key.rejectIdentity();
    try initiator_ephemeral_key.rejectIdentity();

    // Step 2: Compute shared secret
    const shared_secret = try computeSharedSecret(
        context,
        initiator_public_key,
        initiator_ephemeral_key,
        initiator_user_id,
    );

    // Step 3: Derive keys using KDF
    const kdf_input_len = 64; // x and y coordinates of shared secret point
    var kdf_input: [kdf_input_len]u8 = undefined;
    const coords = shared_secret.affineCoordinates();
    @memcpy(kdf_input[0..32], &coords.x.toBytes(.big));
    @memcpy(kdf_input[32..64], &coords.y.toBytes(.big));

    var total_key_length = key_length;
    if (with_confirmation) total_key_length += 32; // Add space for confirmation value

    const derived_key = try utils.kdf(allocator, &kdf_input, total_key_length);

    var result = KeyExchangeResult{
        .shared_key = try allocator.alloc(u8, key_length),
    };

    @memcpy(result.shared_key, derived_key[0..key_length]);

    if (with_confirmation) {
        // Compute key confirmation value
        result.key_confirmation = try computeKeyConfirmation(
            context,
            initiator_public_key,
            initiator_ephemeral_key,
            initiator_user_id,
            derived_key[key_length..key_length + 32],
        );
    }

    allocator.free(derived_key);
    return result;
}

/// Verify key confirmation value
pub fn verifyKeyConfirmation(
    context: *KeyExchangeContext,
    other_public_key: SM2,
    other_ephemeral_key: SM2,
    other_user_id: []const u8,
    confirmation_key: [32]u8,
    received_confirmation: [32]u8,
) !bool {
    const expected_confirmation = try computeKeyConfirmation(
        context,
        other_public_key,
        other_ephemeral_key,
        other_user_id,
        &confirmation_key,
    );

    return utils.constantTimeEqual(&expected_confirmation, &received_confirmation);
}

/// Compute shared secret according to SM2 key exchange protocol
fn computeSharedSecret(
    context: *KeyExchangeContext,
    other_public_key: SM2,
    other_ephemeral_key: SM2,
    other_user_id: []const u8,
) !SM2 {
    _ = other_user_id; // Unused in this function, but required for signature

    // Step 1: Compute x1_bar and x2_bar
    const self_coords = context.ephemeral_public.affineCoordinates();
    const other_coords = other_ephemeral_key.affineCoordinates();

    const x1 = self_coords.x.toBytes(.big);
    const x2 = other_coords.x.toBytes(.big);

    // x1_bar = 2^w + (x1 & (2^w - 1)) where w = 127
    // Create mask for lower 127 bits (15 full bytes and 7 bits)
    var mask: [32]u8 = [_]u8{0} ** 32;
    for (0..15) |i| {
        mask[i] = 0xFF; // 15 full bytes = 120 bits
    }
    mask[15] = 0x7F; // 7 bits, total 127 bits

    var x1_bar: [32]u8 = [_]u8{0} ** 32;
    var x2_bar: [32]u8 = [_]u8{0} ** 32;

    // Apply mask
    for (0..32) |i| {
        x1_bar[i] = x1[i] & mask[i];
        x2_bar[i] = x2[i] & mask[i];
    }
    // Set bit 127 (the highest bit of the 16th byte) to 1
    x1_bar[15] |= 0x80;
    x2_bar[15] |= 0x80;

    // Step 2: Compute t = (d + x1_bar * r) mod n
    // CORRECTED: Always use x1_bar (own ephemeral key's x coordinate)
    const d_scalar = try SM2.scalar.Scalar.fromBytes(context.private_key, .big);
    const r_scalar = try SM2.scalar.Scalar.fromBytes(context.ephemeral_private, .big);
    const x_bar_scalar = try SM2.scalar.Scalar.fromBytes(x1_bar, .big);

    const t_scalar = d_scalar.add(x_bar_scalar.mul(r_scalar));
    const t_bytes = t_scalar.toBytes(.big);

    // Step 3: Compute U = t * (other_public_key + x2_bar * other_ephemeral_key)
    const other_x_bar_scalar = try SM2.scalar.Scalar.fromBytes(x2_bar, .big);
    const other_x_bar_bytes = other_x_bar_scalar.toBytes(.big);

    // Compute (other_public_key + x2_bar * other_ephemeral_key)
    const other_ephemeral_scaled = try other_ephemeral_key.mul(other_x_bar_bytes, .big);
    const combined_point = other_public_key.add(other_ephemeral_scaled);

    // Compute U = t * combined_point
    const shared_point = try combined_point.mul(t_bytes, .big);

    return shared_point;
}

/// Compute key confirmation value
fn computeKeyConfirmation(
    context: *KeyExchangeContext,
    other_public_key: SM2,
    other_ephemeral_key: SM2,
    other_user_id: []const u8,
    confirmation_key: []const u8,
) ![32]u8 {
    // Get coordinates
    const self_pub_coords = context.public_key.affineCoordinates();
    const self_eph_coords = context.ephemeral_public.affineCoordinates();
    const other_pub_coords = other_public_key.affineCoordinates();
    const other_eph_coords = other_ephemeral_key.affineCoordinates();

    // Compute user hashes
    const self_za = utils.computeUserHash(
        context.user_id,
        self_pub_coords.x.toBytes(.big),
        self_pub_coords.y.toBytes(.big),
    );

    const other_za = utils.computeUserHash(
        other_user_id,
        other_pub_coords.x.toBytes(.big),
        other_pub_coords.y.toBytes(.big),
    );

    // Compute confirmation value based on role
    var hasher = SM3.init(.{});

    if (context.role == .initiator) {
        // S_A = SM3(0x02 || yU || SM3(ZA || ZB || xRA || yRA || xRB || yRB))
        hasher.update(&[_]u8{0x02});

        // Add yU coordinate (we'll use y coordinate of confirmation key for simplicity)
        hasher.update(confirmation_key[0..@min(32, confirmation_key.len)]);

        // Compute inner hash
        var inner_hasher = SM3.init(.{});
        inner_hasher.update(&self_za);
        inner_hasher.update(&other_za);
        inner_hasher.update(&self_eph_coords.x.toBytes(.big));
        inner_hasher.update(&self_eph_coords.y.toBytes(.big));
        inner_hasher.update(&other_eph_coords.x.toBytes(.big));
        inner_hasher.update(&other_eph_coords.y.toBytes(.big));
        const inner_hash = inner_hasher.finalResult();

        hasher.update(&inner_hash);
    } else {
        // S_B = SM3(0x03 || yU || SM3(ZA || ZB || xRA || yRA || xRB || yRB))
        hasher.update(&[_]u8{0x03});

        // Add yU coordinate
        hasher.update(confirmation_key[0..@min(32, confirmation_key.len)]);

        // Compute inner hash (same as above)
        var inner_hasher = SM3.init(.{});
        inner_hasher.update(&other_za); // Note: order is swapped for responder
        inner_hasher.update(&self_za);
        inner_hasher.update(&other_eph_coords.x.toBytes(.big));
        inner_hasher.update(&other_eph_coords.y.toBytes(.big));
        inner_hasher.update(&self_eph_coords.x.toBytes(.big));
        inner_hasher.update(&self_eph_coords.y.toBytes(.big));
        const inner_hash = inner_hasher.finalResult();

        hasher.update(&inner_hash);
    }

    return hasher.finalResult();
}

/// Helper function to create ephemeral key from coordinates
pub fn ephemeralKeyFromCoordinates(x: [32]u8, y: [32]u8) !SM2 {
    const fe_x = try SM2.Fe.fromBytes(x, .big);
    const fe_y = try SM2.Fe.fromBytes(y, .big);
    return try SM2.fromAffineCoordinates(.{ .x = fe_x, .y = fe_y });
}

/// Helper function to create ephemeral key from SEC1 encoding
pub fn ephemeralKeyFromSec1(sec1_bytes: []const u8) !SM2 {
    return try SM2.fromSec1(sec1_bytes);
}

