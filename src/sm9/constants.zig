const std = @import("std");

/// SM9 Constants and Configuration
/// Centralizes all magic numbers, strings, and configuration values used throughout SM9 implementation
/// Based on GM/T 0044-2016 Chinese National Standard
/// Point compression format identifiers
pub const PointFormat = struct {
    /// Compressed point with even y-coordinate
    pub const COMPRESSED_EVEN: u8 = 0x02;
    /// Compressed point with odd y-coordinate
    pub const COMPRESSED_ODD: u8 = 0x03;
    /// Uncompressed point format
    pub const UNCOMPRESSED: u8 = 0x04;
    /// Point at infinity marker
    pub const INFINITY: u8 = 0x00;
};

/// Hash function identifiers (HID) from GM/T 0044-2016
pub const HashIdentifier = struct {
    /// HID for signature key derivation
    pub const SIGNATURE: u8 = 0x01;
    /// HID for encryption key derivation
    pub const ENCRYPTION: u8 = 0x03;
};

/// Standard field and curve sizes
pub const FieldSize = struct {
    /// Size of field elements in bytes (256-bit)
    pub const FIELD_ELEMENT_BYTES: usize = 32;
    /// Size of compressed G1 point (1 + 32 bytes)
    pub const G1_COMPRESSED_BYTES: usize = 33;
    /// Size of uncompressed G2 point (1 + 64 bytes)
    pub const G2_UNCOMPRESSED_BYTES: usize = 65;
    /// Size of signature (h + S = 32 + 33 bytes)
    pub const SIGNATURE_BYTES: usize = 65;
    /// Size of SM3 hash output
    pub const SM3_HASH_BYTES: usize = 32;
    /// Size of Fp12 element in GT
    pub const GT_ELEMENT_BYTES: usize = 384;
};

/// Algorithm limits and bounds
pub const Limits = struct {
    /// Maximum counter value for hash iteration (GM/T 0044-2016 compliance)
    pub const MAX_HASH_COUNTER: u32 = 256;
    /// Extended counter range for complex hash computations
    pub const EXTENDED_HASH_COUNTER: u32 = 256;
    /// Maximum modular reduction iterations
    pub const MAX_MODULAR_REDUCTION_ITERATIONS: u32 = 300;
    /// Maximum key derivation function output length
    pub const MAX_KDF_OUTPUT_LENGTH: usize = 0x40000000; // 1GB limit
};

/// Standard string constants used in SM9 operations
pub const Strings = struct {
    /// Domain separation for H2 hash function
    pub const H2_DOMAIN_SEPARATOR: []const u8 = "SM9H2";
    /// KDF function identifier
    pub const KDF_IDENTIFIER: []const u8 = "SM9_KDF_FUNCTION";
    /// Point decompression marker for deterministic y-coordinate derivation
    pub const POINT_Y_DERIVATION_MARKER: []const u8 = "SM9_POINT_Y_DERIVATION";
    /// Library version identifier
    pub const LIBRARY_VERSION: []const u8 = "GM-Zig-SM9-v1.0.0";
};

/// BN256 curve parameters for SM9 (GM/T 0044-2016 standard)
pub const BN256Params = struct {
    /// Prime field order q
    pub const FIELD_ORDER: [32]u8 = [_]u8{ 0xB6, 0x40, 0x00, 0x00, 0x02, 0xA3, 0xA6, 0xF1, 0xD6, 0x03, 0xAB, 0x4F, 0xF5, 0x8E, 0xC7, 0x45, 0x21, 0xF2, 0x93, 0x4B, 0x1A, 0x7A, 0xEE, 0xDB, 0xE5, 0x6F, 0x9B, 0x27, 0xE3, 0x51, 0x45, 0x7D };

    /// Group order N
    pub const GROUP_ORDER: [32]u8 = [_]u8{ 0xB6, 0x40, 0x00, 0x00, 0x02, 0xA3, 0xA6, 0xF1, 0xD6, 0x03, 0xAB, 0x4F, 0xF5, 0x8E, 0xC7, 0x44, 0x49, 0xF2, 0x93, 0x4B, 0x18, 0xEA, 0x8B, 0xEE, 0xE5, 0x6E, 0xE1, 0x9C, 0xD6, 0x9E, 0xCF, 0x25 };

    /// Curve coefficient b = 3 for equation y² = x³ + b
    pub const CURVE_B: [32]u8 = [_]u8{0} ** 31 ++ [_]u8{3};

    /// Hash function output length (256 bits for SM3)
    pub const HASH_OUTPUT_LENGTH: u16 = 256;

    /// Standard G1 generator x-coordinate
    pub const G1_GENERATOR_X: [32]u8 = [_]u8{0} ** 31 ++ [_]u8{2};

    /// Standard G2 generator coordinate (simplified for validation)
    pub const G2_GENERATOR_COORD: [32]u8 = [_]u8{0} ** 31 ++ [_]u8{1};
};

/// Error message templates for consistent error reporting
pub const ErrorMessages = struct {
    pub const INVALID_INPUT: []const u8 = "Invalid input parameter";
    pub const INVALID_LENGTH: []const u8 = "Invalid length parameter";
    pub const HASH_COMPUTATION_FAILED: []const u8 = "Hash computation failed";
    pub const FIELD_ELEMENT_GENERATION_FAILED: []const u8 = "Field element generation failed";
    pub const MODULAR_REDUCTION_FAILED: []const u8 = "Modular reduction failed";
    pub const POINT_NOT_ON_CURVE: []const u8 = "Point is not on curve";
    pub const INVALID_POINT_FORMAT: []const u8 = "Invalid point format";
    pub const NOT_QUADRATIC_RESIDUE: []const u8 = "Value is not a quadratic residue";
    pub const DIVISION_BY_ZERO: []const u8 = "Division by zero";
    pub const INVALID_SIGNATURE: []const u8 = "Invalid signature format";
    pub const VERIFICATION_FAILED: []const u8 = "Signature verification failed";
    pub const ENCRYPTION_FAILED: []const u8 = "Encryption operation failed";
    pub const DECRYPTION_FAILED: []const u8 = "Decryption operation failed";
    pub const KEY_GENERATION_FAILED: []const u8 = "Key generation failed";
    pub const PAIRING_COMPUTATION_FAILED: []const u8 = "Pairing computation failed";
    pub const KDF_COMPUTATION_FAILED: []const u8 = "KDF computation failed";
    pub const RANDOM_GENERATION_FAILED: []const u8 = "Random number generation failed";
    pub const MEMORY_ALLOCATION_FAILED: []const u8 = "Memory allocation failed";
    pub const NOT_IMPLEMENTED: []const u8 = "Feature not implemented";
};

/// Test vectors and validation constants
pub const TestConstants = struct {
    /// Default test user ID
    pub const TEST_USER_ID: []const u8 = "alice@example.com";
    /// Test message for validation
    pub const TEST_MESSAGE: []const u8 = "SM9 test message for cryptographic validation";
    /// Minimum valid field element (1) - GM/T 0044-2016 compliant
    pub const MIN_FIELD_ELEMENT: [32]u8 = [_]u8{0} ** 31 ++ [_]u8{1};
};

/// Performance and optimization constants
pub const Performance = struct {
    /// Recommended buffer size for batch operations
    pub const BATCH_BUFFER_SIZE: usize = 8192;
    /// Maximum batch size for signature operations
    pub const MAX_BATCH_SIZE: usize = 1000;
    /// Memory pool initial size
    pub const MEMORY_POOL_SIZE: usize = 1024 * 1024; // 1MB
};

/// Security policy constants
pub const Security = struct {
    /// Minimum entropy for random number generation (bytes)
    pub const MIN_RANDOM_ENTROPY: usize = 32;
    /// Maximum allowed message size for encryption (bytes)
    pub const MAX_MESSAGE_SIZE: usize = 1024 * 1024 * 100; // 100MB
    /// Secure memory wipe pattern
    pub const SECURE_WIPE_PATTERN: u8 = 0x00;
    /// Constant-time operation flag
    pub const CONSTANT_TIME_REQUIRED: bool = true;
};

/// Utility functions for working with constants
pub const Utils = struct {
    /// Check if a value matches any point format identifier
    pub fn isValidPointFormat(format: u8) bool {
        return format == PointFormat.COMPRESSED_EVEN or
            format == PointFormat.COMPRESSED_ODD or
            format == PointFormat.UNCOMPRESSED or
            format == PointFormat.INFINITY;
    }

    /// Check if a hash identifier is valid
    pub fn isValidHashIdentifier(hid: u8) bool {
        return hid == HashIdentifier.SIGNATURE or
            hid == HashIdentifier.ENCRYPTION;
    }

    /// Get error message for error type
    pub fn getErrorMessage(err: anyerror) []const u8 {
        return switch (err) {
            error.InvalidInput => ErrorMessages.INVALID_INPUT,
            error.InvalidLength => ErrorMessages.INVALID_LENGTH,
            error.HashComputationFailed => ErrorMessages.HASH_COMPUTATION_FAILED,
            error.FieldElementGenerationFailed => ErrorMessages.FIELD_ELEMENT_GENERATION_FAILED,
            error.ModularReductionFailed => ErrorMessages.MODULAR_REDUCTION_FAILED,
            error.PointNotOnCurve => ErrorMessages.POINT_NOT_ON_CURVE,
            error.InvalidPointFormat => ErrorMessages.INVALID_POINT_FORMAT,
            error.NotQuadraticResidue => ErrorMessages.NOT_QUADRATIC_RESIDUE,
            error.DivisionByZero => ErrorMessages.DIVISION_BY_ZERO,
            error.InvalidSignature => ErrorMessages.INVALID_SIGNATURE,
            error.NotImplemented => ErrorMessages.NOT_IMPLEMENTED,
            else => "Unknown error",
        };
    }
};
