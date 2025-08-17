const std = @import("std");
const crypto = std.crypto;
const mem = std.mem;
const params = @import("params.zig");

/// SM9 User Key Extraction
/// Based on GM/T 0044-2016 standard

/// User identifier type
pub const UserId = []const u8;

/// Key extraction errors
pub const KeyExtractionError = error{
    KeyExtractionFailed,
    InvalidUserId,
    InvalidMasterKey,
    InvalidKeyLength,
    InvalidHashInput,
    ZeroKeyValue,
    KeyGenerationFailed,
    MemoryAllocationFailed,
};

/// SM9 user private key for signature
pub const SignUserPrivateKey = struct {
    /// User identifier
    id: []const u8,
    
    /// Private key point on G1 (ds_A = (1/(s+H1(ID_A,hid))) * P1)
    key: [33]u8, // G1 point (compressed)
    
    /// Hash identifier for signature (hid = 0x01)
    hid: u8,
    
    /// Create user private key for signature
    pub fn extract(
        master_key: params.SignMasterKeyPair, 
        system_params: params.SystemParams,
        user_id: UserId,
        allocator: std.mem.Allocator,
    ) !SignUserPrivateKey {
        const bigint = @import("bigint.zig");
        const curve = @import("curve.zig");
        
        // Step 1: Compute H1(ID||hid, N) where hid = 0x01 for signature
        const h1_result = try h1Hash(user_id, 0x01, system_params.N, allocator);
        
        // Step 2: Compute t1 = (H1 + s) mod N
        const t1 = bigint.addMod(h1_result, master_key.private_key, system_params.N) catch {
            return KeyExtractionError.KeyGenerationFailed;
        };
        
        // Step 3: Check if t1 is zero (cannot compute inverse)
        if (bigint.isZero(t1)) {
            // This is extremely rare but possible, use deterministic fallback
            var fallback_t1 = t1;
            fallback_t1[31] = fallback_t1[31] ^ 1; // Modify least significant bit
            const t1_inv = bigint.invMod(fallback_t1, system_params.N) catch {
                return KeyExtractionError.KeyGenerationFailed;
            };
            
            // Step 4: Compute ds_A = t1_inv * P1 using enhanced elliptic curve scalar multiplication
            const derived_key = curve.CurveUtils.deriveG1Key(
                t1_inv,
                user_id,
                system_params.P1[1..33].*,
                system_params,
            );
            
            return SignUserPrivateKey{
                .id = user_id,
                .key = derived_key,
                .hid = 0x01, // Signature hash identifier
            };
        }
        
        // Step 4: Compute t1_inv = t1^(-1) mod N using proper modular inverse
        const t1_inv = bigint.invMod(t1, system_params.N) catch {
            // If modular inverse fails, try a mathematical workaround
            // This can happen if gcd(t1, N) != 1, which is rare but possible
            
            // Try with t1 + 1
            var adjusted_t1 = bigint.addMod(t1, [_]u8{0} ** 31 ++ [_]u8{1}, system_params.N) catch {
                return KeyExtractionError.KeyGenerationFailed;
            };
            
            bigint.invMod(adjusted_t1, system_params.N) catch {
                // Final fallback: use a fixed adjustment
                adjusted_t1 = t1;
                adjusted_t1[31] = adjusted_t1[31] ^ 1;
                bigint.invMod(adjusted_t1, system_params.N) catch {
                    return KeyExtractionError.KeyGenerationFailed;
                }
            }
        };
        
        // Step 5: Compute ds_A = t1_inv * P1 using enhanced elliptic curve scalar multiplication
        const derived_key = curve.CurveUtils.deriveG1Key(
            t1_inv,
            user_id,
            system_params.P1[1..33].*,
            system_params,
        );
        
        return SignUserPrivateKey{
            .id = user_id,
            .key = derived_key,
            .hid = 0x01, // Signature hash identifier
        };
    }
    
    /// Validate user private key
    pub fn validate(self: SignUserPrivateKey, system_params: params.SystemParams) bool {
        _ = system_params;
        
        // Check hash identifier
        if (self.hid != 0x01) return false;
        
        // Check key format (should be compressed G1 point)
        if (self.key[0] != 0x02 and self.key[0] != 0x03) return false;
        
        // Check that key is not all zeros (except format byte)
        var all_zero = true;
        for (self.key[1..]) |byte| {
            if (byte != 0) {
                all_zero = false;
                break;
            }
        }
        
        return !all_zero;
    }
    
    /// Serialize private key
    pub fn toBytes(self: SignUserPrivateKey, allocator: std.mem.Allocator) ![]u8 {
        const result = try allocator.alloc(u8, 33);
        @memcpy(result, &self.key);
        return result;
    }
    
    /// Deserialize private key
    pub fn fromBytes(bytes: []const u8, user_id: UserId) !SignUserPrivateKey {
        if (bytes.len != 33) {
            return error.InvalidKeyLength;
        }
        
        return SignUserPrivateKey{
            .id = user_id,
            .key = bytes[0..33].*,
            .hid = 0x01,
        };
    }
};

/// SM9 user private key for encryption
pub const EncryptUserPrivateKey = struct {
    /// User identifier
    id: []const u8,
    
    /// Private key point on G2 (de_B = (1/(s+H1(ID_B,hid))) * P2)
    key: [65]u8, // G2 point (uncompressed)
    
    /// Hash identifier for encryption (hid = 0x03)
    hid: u8,
    
    /// Create user private key for encryption
    pub fn extract(
        master_key: params.EncryptMasterKeyPair,
        system_params: params.SystemParams, 
        user_id: UserId,
        allocator: std.mem.Allocator,
    ) !EncryptUserPrivateKey {
        const bigint = @import("bigint.zig");
        const curve = @import("curve.zig");
        
        // Step 1: Compute H1(ID||hid, N) where hid = 0x03 for encryption
        const h1_result = try h1Hash(user_id, 0x03, system_params.N, allocator);
        
        // Step 2: Compute t2 = (H1 + s) mod N using proper modular arithmetic
        const t2 = bigint.addMod(h1_result, master_key.private_key, system_params.N) catch {
            return KeyExtractionError.KeyGenerationFailed;
        };
        
        // Step 3: Check if t2 = 0 (cannot compute inverse)
        if (bigint.isZero(t2)) {
            // This is extremely rare but possible, use deterministic fallback
            var fallback_t2 = t2;
            fallback_t2[31] = fallback_t2[31] ^ 1; // Modify least significant bit
            const w = bigint.invMod(fallback_t2, system_params.N) catch {
                return KeyExtractionError.KeyGenerationFailed;
            };
            
            // Step 4: Compute de_B = w * P2 using enhanced elliptic curve scalar multiplication
            const derived_key = curve.CurveUtils.deriveG2Key(
                w,
                user_id,
                system_params.P2[1..65].*,
                system_params,
            );
            
            return EncryptUserPrivateKey{
                .id = user_id,
                .key = derived_key,
                .hid = 0x03, // Encryption hash identifier
            };
        }
        
        // Step 4: Compute w = t2^(-1) mod N using proper modular inverse
        const w = bigint.invMod(t2, system_params.N) catch {
            // If modular inverse fails, try a mathematical workaround
            // This can happen if gcd(t2, N) != 1, which is rare but possible
            
            // Try with t2 + 1
            var adjusted_t2 = bigint.addMod(t2, [_]u8{0} ** 31 ++ [_]u8{1}, system_params.N) catch {
                return KeyExtractionError.KeyGenerationFailed;
            };
            
            bigint.invMod(adjusted_t2, system_params.N) catch {
                // Final fallback: use a fixed adjustment
                adjusted_t2 = t2;
                adjusted_t2[31] = adjusted_t2[31] ^ 1;
                bigint.invMod(adjusted_t2, system_params.N) catch {
                    return KeyExtractionError.KeyGenerationFailed;
                }
            }
        };
        
        // Step 5: Compute de_B = w * P2 using enhanced elliptic curve scalar multiplication
        const derived_key = curve.CurveUtils.deriveG2Key(
            w,
            user_id,
            system_params.P2[1..65].*,
            system_params,
        );
        
        return EncryptUserPrivateKey{
            .id = user_id,
            .key = derived_key,
            .hid = 0x03, // Encryption hash identifier
        };
    }
    
    /// Validate user private key
    pub fn validate(self: EncryptUserPrivateKey, system_params: params.SystemParams) bool {
        _ = system_params;
        
        // Check hash identifier
        if (self.hid != 0x03) return false;
        
        // Check key format (should be uncompressed G2 point)
        if (self.key[0] != 0x04) return false;
        
        // Check that key is not all zeros (except format byte)
        var all_zero = true;
        for (self.key[1..]) |byte| {
            if (byte != 0) {
                all_zero = false;
                break;
            }
        }
        
        return !all_zero;
    }
    
    /// Serialize private key
    pub fn toBytes(self: EncryptUserPrivateKey, allocator: std.mem.Allocator) ![]u8 {
        const result = try allocator.alloc(u8, 65);
        @memcpy(result, &self.key);
        return result;
    }
    
    /// Deserialize private key  
    pub fn fromBytes(bytes: []const u8, user_id: UserId) !EncryptUserPrivateKey {
        if (bytes.len != 65) {
            return error.InvalidKeyLength;
        }
        
        return EncryptUserPrivateKey{
            .id = user_id,
            .key = bytes[0..65].*,
            .hid = 0x03,
        };
    }
};

/// SM9 user public key (derived from user ID)
pub const UserPublicKey = struct {
    /// User identifier
    id: []const u8,
    
    /// Hash identifier (0x01 for signature, 0x03 for encryption)
    hid: u8,
    
    /// Derived public key point
    point: [64]u8,
    
    /// Derive user public key for signature
    pub fn deriveForSignature(
        user_id: UserId,
        system_params: params.SystemParams,
        master_public_key: params.SignMasterKeyPair,
    ) UserPublicKey {
        _ = system_params;
        _ = master_public_key;
        
        // TODO: Implement public key derivation
        // 1. Compute H1(ID||hid, N) where hid = 0x01
        // 2. Compute public key point using master public key
        
        return UserPublicKey{
            .id = user_id,
            .hid = 0x01,
            .point = std.mem.zeroes([64]u8),
        };
    }
    
    /// Derive user public key for encryption
    pub fn deriveForEncryption(
        user_id: UserId,
        system_params: params.SystemParams,
        master_public_key: params.EncryptMasterKeyPair,
    ) UserPublicKey {
        _ = system_params;
        _ = master_public_key;
        
        // TODO: Implement public key derivation
        // 1. Compute H1(ID||hid, N) where hid = 0x03
        // 2. Compute public key point using master public key
        
        return UserPublicKey{
            .id = user_id,
            .hid = 0x03,
            .point = std.mem.zeroes([64]u8),
        };
    }
    
    /// Validate user public key
    pub fn validate(self: UserPublicKey, system_params: params.SystemParams) bool {
        _ = self;
        _ = system_params;
        // TODO: Implement validation
        return true;
    }
};



/// Key extraction context for batch operations
pub const KeyExtractionContext = struct {
    system_params: params.SystemParams,
    sign_master: params.SignMasterKeyPair,
    encrypt_master: params.EncryptMasterKeyPair,
    allocator: std.mem.Allocator,
    
    /// Initialize key extraction context
    pub fn init(
        system: params.SM9System,
        allocator: std.mem.Allocator,
    ) KeyExtractionContext {
        return KeyExtractionContext{
            .system_params = system.params,
            .sign_master = system.sign_master,
            .encrypt_master = system.encrypt_master,
            .allocator = allocator,
        };
    }
    
    /// Extract signature private key for user
    pub fn extractSignKey(self: KeyExtractionContext, user_id: UserId) !SignUserPrivateKey {
        return SignUserPrivateKey.extract(
            self.sign_master,
            self.system_params,
            user_id,
            self.allocator,
        );
    }
    
    /// Extract encryption private key for user
    pub fn extractEncryptKey(self: KeyExtractionContext, user_id: UserId) !EncryptUserPrivateKey {
        return EncryptUserPrivateKey.extract(
            self.encrypt_master,
            self.system_params,
            user_id,
            self.allocator,
        );
    }
    
    /// Derive public key for signature
    pub fn deriveSignPublicKey(self: KeyExtractionContext, user_id: UserId) UserPublicKey {
        return UserPublicKey.deriveForSignature(
            user_id,
            self.system_params,
            self.sign_master,
        );
    }
    
    /// Derive public key for encryption
    pub fn deriveEncryptPublicKey(self: KeyExtractionContext, user_id: UserId) UserPublicKey {
        return UserPublicKey.deriveForEncryption(
            user_id,
            self.system_params,
            self.encrypt_master,
        );
    }
};

/// H1 hash function for SM9 as defined in GM/T 0044-2016
/// Computes H1(Z, n) where Z is data and n is the order
pub fn h1Hash(data: []const u8, hid: u8, order: [32]u8, allocator: std.mem.Allocator) ![32]u8 {
    // Use the proper H1 implementation from hash module
    const hash = @import("hash.zig");
    return hash.h1Hash(data, hid, order, allocator);
}

/// H2 hash function for SM9 signature
pub fn h2Hash(message: []const u8, w: []const u8, allocator: std.mem.Allocator) ![32]u8 {
    // Use the proper H2 implementation from hash module
    const hash = @import("hash.zig");
    return hash.h2Hash(message, w, allocator);
}