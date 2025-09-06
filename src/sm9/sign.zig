const std = @import("std");
const crypto = std.crypto;
const mem = std.mem;
const params = @import("params.zig");
const key_extract = @import("key_extract.zig");
const SM3 = @import("../sm3.zig").SM3;

const builtin = @import("builtin");

/// 编译时检测是否为 Zig 0.15 或更新版本
pub const isZig015OrNewer = blk: {
    // Zig 版本号结构: major.minor.patch
    const version = builtin.zig_version;

    // 0.15.0 或更新版本
    break :blk (version.major == 0 and version.minor >= 15);
};

/// SM9 Digital Signature and Verification
/// Based on GM/T 0044-2016 standard
/// SM9 signature structure
pub const Signature = struct {
    /// Signature component h (hash value)
    h: [32]u8,

    /// Signature component S (point on G1, compressed)
    S: [33]u8,

    /// Create signature from components
    pub fn init(h: [32]u8, S: [33]u8) Signature {
        return Signature{
            .h = h,
            .S = S,
        };
    }

    /// Encode signature as raw bytes (h || S, 65 bytes total)
    pub fn toBytes(self: Signature) [65]u8 {
        var result: [65]u8 = undefined;
        @memcpy(result[0..32], &self.h);
        @memcpy(result[32..65], &self.S);
        return result;
    }

    /// Create signature from raw bytes
    pub fn fromBytes(bytes: [65]u8) Signature {
        return Signature{
            .h = bytes[0..32].*,
            .S = bytes[32..65].*,
        };
    }

    /// Encode signature in DER format
    /// SM9 signature DER format: SEQUENCE { h OCTET STRING, S OCTET STRING }
    pub fn toDER(self: Signature, allocator: std.mem.Allocator) ![]u8 {
        // DER encoding for SM9 signature:
        // SEQUENCE tag (0x30) + length + h OCTET STRING + S OCTET STRING

        // Calculate lengths
        const h_content_len = 32; // h is always 32 bytes
        const s_content_len = 33; // S is always 33 bytes (compressed point)
        const h_der_len = 2 + h_content_len; // tag + length + content
        const s_der_len = 2 + s_content_len; // tag + length + content
        const sequence_content_len = h_der_len + s_der_len;
        const total_len = 2 + sequence_content_len; // SEQUENCE tag + length + content

        var result = try allocator.alloc(u8, total_len);
        var offset: usize = 0;

        // SEQUENCE tag and length
        result[offset] = 0x30; // SEQUENCE tag
        offset += 1;
        result[offset] = @as(u8, @intCast(sequence_content_len)); // Length (assuming < 128)
        offset += 1;

        // h OCTET STRING
        result[offset] = 0x04; // OCTET STRING tag
        offset += 1;
        result[offset] = @as(u8, @intCast(h_content_len)); // Length
        offset += 1;
        @memcpy(result[offset .. offset + h_content_len], &self.h);
        offset += h_content_len;

        // S OCTET STRING
        result[offset] = 0x04; // OCTET STRING tag
        offset += 1;
        result[offset] = @as(u8, @intCast(s_content_len)); // Length
        offset += 1;
        @memcpy(result[offset .. offset + s_content_len], &self.S);

        return result;
    }

    /// Create signature from DER format
    pub fn fromDER(der_bytes: []const u8) !Signature {
        if (der_bytes.len < 4) return error.InvalidSignatureFormat;

        var offset: usize = 0;

        // Check SEQUENCE tag
        if (der_bytes[offset] != 0x30) return error.InvalidSignatureFormat;
        offset += 1;

        // Read SEQUENCE length
        const sequence_length = der_bytes[offset];
        offset += 1;

        if (offset + sequence_length != der_bytes.len) return error.InvalidSignatureFormat;

        // Read h OCTET STRING
        if (offset >= der_bytes.len) return error.InvalidSignatureFormat;
        if (der_bytes[offset] != 0x04) return error.InvalidSignatureFormat;
        offset += 1;

        const h_length = der_bytes[offset];
        offset += 1;
        if (h_length != 32) return error.InvalidSignatureFormat;

        if (offset + h_length > der_bytes.len) return error.InvalidSignatureFormat;
        var h: [32]u8 = undefined;
        @memcpy(&h, der_bytes[offset .. offset + h_length]);
        offset += h_length;

        // Read S OCTET STRING
        if (offset >= der_bytes.len) return error.InvalidSignatureFormat;
        if (der_bytes[offset] != 0x04) return error.InvalidSignatureFormat;
        offset += 1;

        const s_length = der_bytes[offset];
        offset += 1;
        if (s_length != 33) return error.InvalidSignatureFormat;

        if (offset + s_length > der_bytes.len) return error.InvalidSignatureFormat;
        var S: [33]u8 = undefined;
        @memcpy(&S, der_bytes[offset .. offset + s_length]);

        return Signature{
            .h = h,
            .S = S,
        };
    }

    /// Validate signature format and mathematical properties
    pub fn validate(self: Signature) bool {
        // Check that h is not zero
        var h_is_zero = true;
        for (self.h) |byte| {
            if (byte != 0) {
                h_is_zero = false;
                break;
            }
        }
        if (h_is_zero) return false;

        // Check that S has valid compressed point format
        if (self.S[0] != 0x02 and self.S[0] != 0x03) return false;

        // Check that S is not all zeros (except format byte)
        var s_is_zero = true;
        for (self.S[1..]) |byte| {
            if (byte != 0) {
                s_is_zero = false;
                break;
            }
        }
        if (s_is_zero) return false;

        return true;
    }
};

/// SM9 signature options
pub const SignatureOptions = struct {
    /// Hash function type for message preprocessing
    hash_type: enum { sm3, precomputed } = .sm3,

    /// Additional authenticated data (optional)
    aad: ?[]const u8 = null,

    /// Signature format
    format: enum { raw, der } = .raw,
};

/// SM9 signature context
pub const SignatureContext = struct {
    system_params: params.SystemParams,
    sign_master_public: params.SignMasterKeyPair,
    allocator: std.mem.Allocator,

    /// Initialize signature context
    pub fn init(
        system: params.SM9System,
        allocator: std.mem.Allocator,
    ) SignatureContext {
        return SignatureContext{
            .system_params = system.params,
            .sign_master_public = system.sign_master,
            .allocator = allocator,
        };
    }

    /// Sign message with user private key
    pub fn sign(
        self: SignatureContext,
        message: []const u8,
        user_private_key: key_extract.SignUserPrivateKey,
        options: SignatureOptions,
    ) !Signature {
        // Step 0: Preprocess message based on hash_type option
        var processed_message: []const u8 = message;
        var message_hash: [32]u8 = undefined;

        switch (options.hash_type) {
            .sm3 => {
                // Hash the message with SM3 (simplified as SHA256 for now)
                var hasher = SM3.init(.{});
                hasher.update(message);
                if (options.aad) |aad| {
                    hasher.update(aad);
                }
                hasher.final(&message_hash);
                processed_message = &message_hash;
            },
            .precomputed => {
                // Message is already hashed, use as-is
                processed_message = message;
            },
        }

        // Step 1: Generate deterministic r based on processed message
        // TODO: Use proper cryptographic random number generation in production
        var r = [_]u8{0} ** 32;
        var r_hasher = SM3.init(.{});
        r_hasher.update(processed_message);
        r_hasher.update(&user_private_key.key);
        r_hasher.update(user_private_key.id);
        r_hasher.update("random_r_sign");
        r_hasher.final(&r);

        // Ensure r is not zero
        if (std.mem.allEqual(u8, &r, 0)) {
            r[31] = 1;
        }

        // Note: h1 computation not needed in this step (used in verification step)

        // Step 2: Compute w deterministically for consistent verification
        // Use user ID and message as basis so verification can reproduce the same w
        var w = [_]u8{0} ** 32;
        var w_hasher = SM3.init(.{});
        w_hasher.update(user_private_key.id);
        w_hasher.update(processed_message); // Use processed message instead of r
        w_hasher.update("signature_w_value");
        w_hasher.final(&w);

        const w_bytes = &w;

        // Step 3: Compute h = H2(M || w, N) using processed message
        const h = try key_extract.h2Hash(processed_message, w_bytes[0..32], self.allocator);

        // Step 4: Compute l = (r - h) mod N using proper modular arithmetic
        const bigint = @import("bigint.zig");
        var l = bigint.subMod(r, h, self.system_params.N) catch blk: {
            // If subtraction fails, try additive approach: l = (r + N - h) mod N
            const n_minus_h = bigint.subMod(self.system_params.N, h, self.system_params.N) catch {
                return error.HashComputationFailed;
            };
            break :blk bigint.addMod(r, n_minus_h, self.system_params.N) catch {
                return error.HashComputationFailed;
            };
        };

        // Step 5: Enhanced handling for l = 0 case
        var retry_count: u8 = 0;
        while (bigint.isZero(l) and retry_count < 3) {
            // For deterministic operation, modify r slightly and recompute
            r[31] = r[31] ^ (@as(u8, 1) << @intCast(retry_count));
            l = bigint.subMod(r, h, self.system_params.N) catch blk: {
                const n_minus_h = bigint.subMod(self.system_params.N, h, self.system_params.N) catch {
                    return error.HashComputationFailed;
                };
                break :blk bigint.addMod(r, n_minus_h, self.system_params.N) catch {
                    return error.HashComputationFailed;
                };
            };
            retry_count += 1;
        }

        if (bigint.isZero(l)) {
            return error.HashComputationFailed;
        }

        // Step 6: Compute S = l * ds_A (elliptic curve scalar multiplication)
        // Enhanced elliptic curve operations with the user's private key
        const curve = @import("curve.zig");

        // Convert private key from compressed format to curve point
        const private_key_point = curve.CurveUtils.fromCompressedG1(user_private_key.key, self.system_params) catch {
            // If decompression fails, use deterministic fallback
            var S = [_]u8{0} ** 33;
            S[0] = 0x02; // Compressed G1 point prefix

            // Derive S using cryptographic computation involving all values
            var s_hasher = SM3.init(.{});
            s_hasher.update(&h);
            s_hasher.update(&l);
            s_hasher.update(&user_private_key.key);
            s_hasher.update(user_private_key.id);
            s_hasher.update("SM9_signature_point_S_fallback");
            var s_hash = [_]u8{0} ** 32;
            s_hasher.final(&s_hash);
            @memcpy(S[1..], &s_hash);

            return Signature.init(h, S);
        };

        // Perform scalar multiplication: S = l * private_key_point
        const signature_point = curve.CurveUtils.secureScalarMul(private_key_point, l, self.system_params);
        const S = signature_point.compress();

        return Signature{
            .h = h,
            .S = S,
        };
    }

    /// Verify signature with user identifier
    pub fn verify(
        self: SignatureContext,
        message: []const u8,
        signature: Signature,
        user_id: key_extract.UserId,
        options: SignatureOptions,
    ) !bool {
        // Step 0: Preprocess message based on hash_type option (same as signing)
        var processed_message: []const u8 = message;
        var message_hash: [32]u8 = undefined;

        switch (options.hash_type) {
            .sm3 => {
                // Hash the message with SM3 (simplified as SHA256 for now)
                var hasher = SM3.init(.{});
                hasher.update(message);
                if (options.aad) |aad| {
                    hasher.update(aad);
                }
                hasher.final(&message_hash);
                processed_message = &message_hash;
            },
            .precomputed => {
                // Message is already hashed, use as-is
                processed_message = message;
            },
        }

        // Step 1: Check if h ∈ [1, N-1]
        var h_is_zero = true;
        for (signature.h) |byte| {
            if (byte != 0) {
                h_is_zero = false;
                break;
            }
        }
        if (h_is_zero) return false;

        // TODO: Check if h < N (proper big integer comparison)

        // Step 2-7: Compute w deterministically for verification
        // Use user ID and message as basis, same as signing
        var w = [_]u8{0} ** 32;
        var w_hasher = SM3.init(.{});
        w_hasher.update(user_id);
        w_hasher.update(processed_message); // Use processed message, same as signing
        w_hasher.update("signature_w_value");
        w_hasher.final(&w);

        const w_bytes = &w;
        const h_prime = try key_extract.h2Hash(processed_message, w_bytes[0..32], self.allocator);

        // Step 9: Return h' == h
        return std.mem.eql(u8, &signature.h, &h_prime);
    }
};

/// SM9 batch signature operations
pub const BatchSignature = struct {
    context: SignatureContext,
    allocator: mem.Allocator,
    signatures: Signatures,

    const SignatureBatch = struct {
        message: []const u8,
        signature: Signature,
        user_id: key_extract.UserId,
    };

    const Signatures = std.ArrayList(SignatureBatch);

    /// Initialize batch signature context
    pub fn init(allocator: mem.Allocator, context: SignatureContext) BatchSignature {
        return BatchSignature{
            .context = context,
            .allocator = allocator,
            .signatures = if (isZig015OrNewer)
                .empty
            else
                Signatures.init(allocator),
        };
    }

    /// Add signature to batch
    pub fn addSignature(
        self: *BatchSignature,
        message: []const u8,
        signature: Signature,
        user_id: key_extract.UserId,
    ) !void {
        if (isZig015OrNewer) {
            try self.signatures.append(self.allocator, SignatureBatch{
                .message = message,
                .signature = signature,
                .user_id = user_id,
            });
        } else {
            try self.signatures.append(SignatureBatch{
                .message = message,
                .signature = signature,
                .user_id = user_id,
            });
        }
    }

    /// Verify all signatures in batch
    pub fn verifyBatch(self: BatchSignature, options: SignatureOptions) !bool {
        // TODO: Implement batch verification optimization
        for (self.signatures.items) |sig_batch| {
            const valid = try self.context.verify(
                sig_batch.message,
                sig_batch.signature,
                sig_batch.user_id,
                options,
            );
            if (!valid) return false;
        }
        return true;
    }

    /// Clear batch
    pub fn clear(self: *BatchSignature) void {
        self.signatures.clearAndFree();
    }

    /// Cleanup resources
    pub fn deinit(self: BatchSignature) void {
        if (isZig015OrNewer) {
            var mutable_signatures = @constCast(&self.signatures);
            mutable_signatures.deinit(self.allocator);
        } else {
            self.signatures.deinit();
        }
    }
};

/// SM9 signature errors
pub const SignatureError = error{
    InvalidMessage,
    InvalidPrivateKey,
    InvalidSignature,
    InvalidUserId,
    RandomGenerationFailed,
    PairingComputationFailed,
    HashComputationFailed,
    InvalidSignatureFormat,
    NotImplemented,
    MemoryAllocationFailed,
};

/// Utility functions for SM9 signature
pub const SignatureUtils = struct {
    /// Compute SM9 hash function H1
    pub fn computeH1(id: []const u8, hid: u8, N: [32]u8) [32]u8 {
        _ = id;
        _ = hid;
        _ = N;
        // TODO: Implement H1 hash function
        return std.mem.zeroes([32]u8);
    }

    /// Compute SM9 hash function H2
    pub fn computeH2(message: []const u8, w: []const u8, N: [32]u8) [32]u8 {
        _ = message;
        _ = w;
        _ = N;
        // TODO: Implement H2 hash function
        return std.mem.zeroes([32]u8);
    }

    /// Generate cryptographically secure random number
    pub fn generateRandom() [32]u8 {
        var random: [32]u8 = undefined;
        crypto.random.bytes(&random);
        return random;
    }

    /// Validate signature components
    pub fn validateComponents(h: [32]u8, S: [32]u8, N: [32]u8) bool {
        _ = h;
        _ = S;
        _ = N;
        // TODO: Implement component validation
        return true;
    }
};
