const std = @import("std");
const crypto = std.crypto;
const mem = std.mem;

/// SM9 Main Interface Module
/// Provides unified access to all SM9 cryptographic operations
/// Based on GM/T 0044-2016 standard

// Import all SM9 submodules
pub const params = @import("params.zig");
pub const key_extract = @import("key_extract.zig");
pub const sign = @import("sign.zig");
pub const encrypt = @import("encrypt.zig");

// Re-export commonly used types for convenience
pub const SystemParams = params.SystemParams;
pub const SM9System = params.SM9System;
pub const SignMasterKeyPair = params.SignMasterKeyPair;
pub const EncryptMasterKeyPair = params.EncryptMasterKeyPair;

pub const SignUserPrivateKey = key_extract.SignUserPrivateKey;
pub const EncryptUserPrivateKey = key_extract.EncryptUserPrivateKey;
pub const UserPublicKey = key_extract.UserPublicKey;
pub const KeyExtractionContext = key_extract.KeyExtractionContext;

pub const Signature = sign.Signature;
pub const SignatureContext = sign.SignatureContext;
pub const SignatureOptions = sign.SignatureOptions;
pub const BatchSignature = sign.BatchSignature;

pub const Ciphertext = encrypt.Ciphertext;
pub const EncryptionContext = encrypt.EncryptionContext;
pub const EncryptionOptions = encrypt.EncryptionOptions;
pub const KeyEncapsulation = encrypt.KeyEncapsulation;
pub const KEMContext = encrypt.KEMContext;

/// SM9 comprehensive context for all operations
pub const SM9Context = struct {
    /// System parameters and master keys
    system: SM9System,
    
    /// Key extraction context
    key_extraction: KeyExtractionContext,
    
    /// Signature context
    signature: SignatureContext,
    
    /// Encryption context
    encryption: EncryptionContext,
    
    /// Memory allocator
    allocator: std.mem.Allocator,
    
    /// Initialize SM9 context with default parameters
    pub fn init(allocator: std.mem.Allocator) SM9Context {
        const system = SM9System.init();
        return SM9Context{
            .system = system,
            .key_extraction = KeyExtractionContext.init(system, allocator),
            .signature = SignatureContext.init(system, allocator),
            .encryption = EncryptionContext.init(system, allocator),
            .allocator = allocator,
        };
    }
    
    /// Initialize SM9 context with custom system parameters
    pub fn initWithParams(
        allocator: std.mem.Allocator,
        system_params: SystemParams,
    ) !SM9Context {
        const system = try SM9System.initWithParams(system_params);
        return SM9Context{
            .system = system,
            .key_extraction = KeyExtractionContext.init(system, allocator),
            .signature = SignatureContext.init(system, allocator),
            .encryption = EncryptionContext.init(system, allocator),
            .allocator = allocator,
        };
    }
    
    /// Extract user private key for signature
    pub fn extractSignKey(self: SM9Context, user_id: []const u8) !SignUserPrivateKey {
        return self.key_extraction.extractSignKey(user_id);
    }
    
    /// Extract user private key for encryption
    pub fn extractEncryptKey(self: SM9Context, user_id: []const u8) !EncryptUserPrivateKey {
        return self.key_extraction.extractEncryptKey(user_id);
    }
    
    /// Derive user public key for signature
    pub fn deriveSignPublicKey(self: SM9Context, user_id: []const u8) UserPublicKey {
        return self.key_extraction.deriveSignPublicKey(user_id);
    }
    
    /// Derive user public key for encryption
    pub fn deriveEncryptPublicKey(self: SM9Context, user_id: []const u8) UserPublicKey {
        return self.key_extraction.deriveEncryptPublicKey(user_id);
    }
    
    /// Sign message with user private key
    pub fn signMessage(
        self: SM9Context,
        message: []const u8,
        user_private_key: SignUserPrivateKey,
        options: SignatureOptions,
    ) !Signature {
        return self.signature.sign(message, user_private_key, options);
    }
    
    /// Verify signature with user identifier
    pub fn verifySignature(
        self: SM9Context,
        message: []const u8,
        signature: Signature,
        user_id: []const u8,
        options: SignatureOptions,
    ) !bool {
        return self.signature.verify(message, signature, user_id, options);
    }
    
    /// Encrypt message for user
    pub fn encryptMessage(
        self: SM9Context,
        message: []const u8,
        user_id: []const u8,
        options: EncryptionOptions,
    ) !Ciphertext {
        return self.encryption.encrypt(message, user_id, options);
    }
    
    /// Decrypt ciphertext with user private key
    pub fn decryptMessage(
        self: SM9Context,
        ciphertext: Ciphertext,
        user_private_key: EncryptUserPrivateKey,
        options: EncryptionOptions,
    ) ![]u8 {
        return self.encryption.decrypt(ciphertext, user_private_key, options);
    }
    
    /// Validate entire SM9 system
    pub fn validate(self: SM9Context) bool {
        return self.system.validate();
    }
};

/// SM9 errors (consolidated from all modules)
pub const SM9Error = error{
    // Parameter errors
    InvalidCurveType,
    InvalidPrivateKey,
    InvalidPublicKey,
    ParameterGenerationFailed,
    
    // Key extraction errors
    InvalidUserId,
    InvalidMasterKey,
    InvalidHashInput,
    ZeroKeyValue,
    KeyGenerationFailed,
    InvalidKeyLength,
    
    // Signature errors
    InvalidMessage,
    InvalidSignature,
    RandomGenerationFailed,
    PairingComputationFailed,
    HashComputationFailed,
    InvalidSignatureFormat,
    
    // Encryption errors
    InvalidCiphertext,
    InvalidCiphertextLength,
    KDFComputationFailed,
    AuthenticationFailed,
    
    // General errors
    NotImplemented,
    MemoryAllocationFailed,
};

/// SM9 utility functions
pub const Utils = struct {
    /// Convert bytes to hex string
    pub fn bytesToHex(bytes: []const u8, allocator: std.mem.Allocator) ![]u8 {
        const hex_chars = "0123456789abcdef";
        var result = try allocator.alloc(u8, bytes.len * 2);
        
        for (bytes, 0..) |byte, i| {
            result[i * 2] = hex_chars[byte >> 4];
            result[i * 2 + 1] = hex_chars[byte & 0x0F];
        }
        
        return result;
    }
    
    /// Convert hex string to bytes
    pub fn hexToBytes(hex: []const u8, allocator: std.mem.Allocator) ![]u8 {
        if (hex.len % 2 != 0) return error.InvalidHexLength;
        
        var result = try allocator.alloc(u8, hex.len / 2);
        
        for (0..result.len) |i| {
            const high = try charToNibble(hex[i * 2]);
            const low = try charToNibble(hex[i * 2 + 1]);
            result[i] = (high << 4) | low;
        }
        
        return result;
    }
    
    fn charToNibble(c: u8) !u8 {
        return switch (c) {
            '0'...'9' => c - '0',
            'a'...'f' => c - 'a' + 10,
            'A'...'F' => c - 'A' + 10,
            else => error.InvalidHexCharacter,
        };
    }
    
    /// Generate cryptographically secure random bytes
    pub fn generateRandomBytes(length: usize, allocator: std.mem.Allocator) ![]u8 {
        const bytes = try allocator.alloc(u8, length);
        crypto.random.bytes(bytes);
        return bytes;
    }
    
    /// Secure zero memory
    pub fn secureZero(bytes: []u8) void {
        crypto.utils.secureZero(u8, bytes);
    }
    
    /// Constant-time byte comparison
    pub fn constantTimeEqual(a: []const u8, b: []const u8) bool {
        if (a.len != b.len) return false;
        
        var result: u8 = 0;
        for (a, b) |x, y| {
            result |= x ^ y;
        }
        
        return result == 0;
    }
};

/// SM9 test vectors and validation
pub const TestVectors = struct {
    /// Default test user ID
    pub const test_user_id = "alice@example.com";
    
    /// Test message
    pub const test_message = "SM9 test message for cryptographic validation";
    
    /// Validate SM9 implementation with test vectors
    pub fn validateImplementation(allocator: std.mem.Allocator) !bool {
        var context = SM9Context.init(allocator);
        
        // Test key extraction
        const sign_key = context.extractSignKey(test_user_id) catch return false;
        const encrypt_key = context.extractEncryptKey(test_user_id) catch return false;
        
        // Test signature
        const signature = context.signMessage(
            test_message,
            sign_key,
            SignatureOptions{},
        ) catch return false;
        
        const verify_result = context.verifySignature(
            test_message,
            signature,
            test_user_id,
            SignatureOptions{},
        ) catch return false;
        
        if (!verify_result) return false;
        
        // Test encryption
        const ciphertext = context.encryptMessage(
            test_message,
            test_user_id,
            EncryptionOptions{},
        ) catch return false;
        defer ciphertext.deinit();
        
        const decrypted = context.decryptMessage(
            ciphertext,
            encrypt_key,
            EncryptionOptions{},
        ) catch return false;
        defer allocator.free(decrypted);
        
        return mem.eql(u8, test_message, decrypted);
    }
};