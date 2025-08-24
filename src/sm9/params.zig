const std = @import("std");
const crypto = std.crypto;
const mem = std.mem;
const curve = @import("curve.zig");

/// SM9 Algorithm Parameters and Master Key Generation
/// Based on GM/T 0044-2016 standard

/// SM9 curve types
pub const CurveType = enum {
    bn256, // Default BN256 curve for SM9
};

/// SM9 system parameters following GM/T 0044-2016 standard
pub const SystemParams = struct {
    /// Curve type identifier
    curve: CurveType,

    /// Generator points for signature and encryption
    P1: [33]u8, // Generator of G1 for signature (compressed point)
    P2: [65]u8, // Generator of G2 for encryption (compressed point)

    /// Pairing-friendly curve parameters
    q: [32]u8,  // Prime field order
    N: [32]u8,  // Order of G1 and G2

    /// Hash function identifiers
    v: u16,      // Hash function output length indicator

    /// Initialize default SM9 system parameters according to GM/T 0044-2016
    pub fn init() SystemParams {
        // SM9 BN256 curve parameters from GM/T 0044-2016 standard
        // Prime field order q = 0xB640000002A3A6F1D603AB4FF58EC74521F2934B1A7AEEDBE56F9B27E351457D
        const q_bytes = [32]u8{
            0xB6, 0x40, 0x00, 0x00, 0x02, 0xA3, 0xA6, 0xF1,
            0xD6, 0x03, 0xAB, 0x4F, 0xF5, 0x8E, 0xC7, 0x45,
            0x21, 0xF2, 0x93, 0x4B, 0x1A, 0x7A, 0xEE, 0xDB,
            0xE5, 0x6F, 0x9B, 0x27, 0xE3, 0x51, 0x45, 0x7D
        };

        // Group order N = 0xB640000002A3A6F1D603AB4FF58EC74449F2934B18EA8BEEE56EE19CD69ECF25
        const N_bytes = [32]u8{
            0xB6, 0x40, 0x00, 0x00, 0x02, 0xA3, 0xA6, 0xF1,
            0xD6, 0x03, 0xAB, 0x4F, 0xF5, 0x8E, 0xC7, 0x44,
            0x49, 0xF2, 0x93, 0x4B, 0x18, 0xEA, 0x8B, 0xEE,
            0xE5, 0x6E, 0xE1, 0x9C, 0xD6, 0x9E, 0xCF, 0x25
        };

        // G1 generator P1 (compressed format)
        var P1_bytes = [_]u8{0x02} ++ [_]u8{0} ** 32; // 0x02 prefix for compressed point
        const P1_x = [32]u8{
            0x93, 0xDE, 0x05, 0x1D, 0x62, 0xBF, 0x71, 0x8F,
            0xF5, 0xED, 0x07, 0x04, 0x48, 0x7D, 0x01, 0xD6,
            0xE1, 0xE4, 0x08, 0x6D, 0x49, 0xD5, 0xA0, 0x16,
            0x95, 0x85, 0x8D, 0x34, 0x41, 0x7E, 0x2A, 0x25
        };
        std.mem.copyForwards(u8, P1_bytes[1..], &P1_x);

        // G2 generator P2 (compressed format)
        var P2_bytes = [_]u8{0x04} ++ [_]u8{0} ** 64; // 0x04 prefix for uncompressed point in G2
        const P2_x = [32]u8{
            0x85, 0xAE, 0xF3, 0xD0, 0x78, 0x64, 0x0C, 0x98,
            0x59, 0x7B, 0x60, 0x27, 0xB4, 0x41, 0xA0, 0x1F,
            0xF1, 0xDD, 0x2C, 0x19, 0x0F, 0x5E, 0x93, 0xC4,
            0x54, 0x80, 0x6C, 0x11, 0xD8, 0x06, 0xC7, 0x8D
        };
        const P2_y = [32]u8{
            0x37, 0x27, 0xA0, 0x08, 0x7B, 0xEA, 0x6F, 0xD2,
            0x58, 0x41, 0x12, 0x92, 0x1F, 0x95, 0xD0, 0x19,
            0x83, 0x73, 0x9C, 0x2B, 0x4D, 0x07, 0x33, 0xF0,
            0x1B, 0xA7, 0x97, 0x91, 0xE5, 0xE5, 0xC7, 0x84
        };
        std.mem.copyForwards(u8, P2_bytes[1..33], &P2_x);
        std.mem.copyForwards(u8, P2_bytes[33..65], &P2_y);

        return SystemParams{
            .curve = .bn256,
            .P1 = P1_bytes,
            .P2 = P2_bytes,
            .q = q_bytes,
            .N = N_bytes,
            .v = 256, // 256-bit hash output for SM3
        };
    }

    /// Validate system parameters
    pub fn validate(self: SystemParams) bool {
        // Check curve type
        if (self.curve != .bn256) return false;

        // Check hash output length
        if (self.v != 256) return false;

        // Verify P1 is not zero point (first byte should be 0x02 or 0x03 for compressed)
        if (self.P1[0] != 0x02 and self.P1[0] != 0x03) return false;

        // Verify P2 is not zero point (first byte should be 0x04 for uncompressed)
        if (self.P2[0] != 0x04) return false;

        // Check that q and N are not zero
        var q_zero = true;
        var N_zero = true;
        for (self.q) |byte| {
            if (byte != 0) q_zero = false;
        }
        for (self.N) |byte| {
            if (byte != 0) N_zero = false;
        }

        return !q_zero and !N_zero;
    }
};

/// SM9 master key pair for signature
pub const SignMasterKeyPair = struct {
    /// Master private key for signature (randomly selected from [1, N-1])
    private_key: [32]u8,

    /// Master public key for signature (P_pub-s = s * P2)
    public_key: [65]u8, // G2 point (uncompressed)

    /// Generate new signature master key pair
    pub fn generate(params: SystemParams) SignMasterKeyPair {
        // Generate random private key s ∈ [1, N-1]
        var private_key = [_]u8{0} ** 32;
        var public_key = [_]u8{0} ** 65;

        // 安全随机生成私钥
        while (true) {
            std.crypto.random.bytes(&private_key);
            if (!isZero(private_key) and isLessThan(private_key, params.N)) break;
        }

        // Compute public key P_pub-s = s * P2
        const base_g2 = curve.G2Point.fromUncompressed(params.P2) catch curve.G2Point.infinity();
        const pub_g2 = curve.CurveUtils.scalarMultiplyG2(base_g2, private_key, params);
        public_key = pub_g2.compress();

        return SignMasterKeyPair{
            .private_key = private_key,
            .public_key = public_key,
        };
    }

    /// Create master key pair from existing private key
    pub fn fromPrivateKey(params: SystemParams, private_key: [32]u8) !SignMasterKeyPair {
        // Validate private key is in range [1, N-1]
        if (isZero(private_key) or !isLessThan(private_key, params.N)) {
            return ParameterError.InvalidPrivateKey;
        }

        // Compute public key P_pub-s = s * P2
        const base_g2 = curve.G2Point.fromUncompressed(params.P2) catch curve.G2Point.infinity();
        const pub_g2 = curve.CurveUtils.scalarMultiplyG2(base_g2, private_key, params);
        const public_key = pub_g2.compress();

        return SignMasterKeyPair{
            .private_key = private_key,
            .public_key = public_key,
        };
    }

    /// Validate master key pair
    pub fn validate(self: SignMasterKeyPair, params: SystemParams) bool {
        // Check private key is not zero and less than N
        if (isZero(self.private_key) or !isLessThan(self.private_key, params.N)) {
            return false;
        }

        // Check public key format (should start with 0x04 for uncompressed G2 point)
        if (self.public_key[0] != 0x04) {
            return false;
        }

        // TODO: Verify that public_key = private_key * P2
        return true;
    }
};

/// SM9 master key pair for encryption
pub const EncryptMasterKeyPair = struct {
    /// Master private key for encryption (randomly selected from [1, N-1])
    private_key: [32]u8,

    /// Master public key for encryption (P_pub-e = s * P1)
    public_key: [33]u8, // G1 point (compressed)

    /// Generate new encryption master key pair
    pub fn generate(params: SystemParams) EncryptMasterKeyPair {
        // Generate random private key s ∈ [1, N-1]
        var private_key = [_]u8{0} ** 32;
        var public_key = [_]u8{0} ** 33;

        // 安全随机生成私钥
        while (true) {
            std.crypto.random.bytes(&private_key);
            if (!isZero(private_key) and isLessThan(private_key, params.N)) break;
        }

        // Compute public key P_pub-e = s * P1
        const base_g1 = curve.G1Point.fromCompressed(params.P1) catch curve.G1Point.infinity();
        const pub_g1 = curve.CurveUtils.scalarMultiplyG1(base_g1, private_key, params);
        public_key = pub_g1.compress();

        return EncryptMasterKeyPair{
            .private_key = private_key,
            .public_key = public_key,
        };
    }

    /// Create master key pair from existing private key
    pub fn fromPrivateKey(params: SystemParams, private_key: [32]u8) !EncryptMasterKeyPair {
        // Validate private key is in range [1, N-1]
        if (isZero(private_key) or !isLessThan(private_key, params.N)) {
            return ParameterError.InvalidPrivateKey;
        }

        // Compute public key P_pub-e = s * P1
        const base_g1 = curve.G1Point.fromCompressed(params.P1) catch curve.G1Point.infinity();
        const pub_g1 = curve.CurveUtils.scalarMultiplyG1(base_g1, private_key, params);
        const public_key = pub_g1.compress();

        return EncryptMasterKeyPair{
            .private_key = private_key,
            .public_key = public_key,
        };
    }

    /// Validate master key pair
    pub fn validate(self: EncryptMasterKeyPair, params: SystemParams) bool {
        // Check private key is not zero and less than N
        if (isZero(self.private_key) or !isLessThan(self.private_key, params.N)) {
            return false;
        }

        // Check public key format (should start with 0x02 or 0x03 for compressed G1 point)
        if (self.public_key[0] != 0x02 and self.public_key[0] != 0x03) {
            return false;
        }

        // TODO: Verify that public_key = private_key * P1
        return true;
    }
};

/// SM9 parameter generation errors
pub const ParameterError = error{
    InvalidCurveType,
    InvalidPrivateKey,
    InvalidPublicKey,
    ParameterGenerationFailed,
};

/// Utility function to check if a 32-byte array is zero
pub fn isZero(bytes: [32]u8) bool {
    for (bytes) |byte| {
        if (byte != 0) return false;
    }
    return true;
}

/// Utility function to check if a < b for 32-byte big-endian integers
pub fn isLessThan(a: [32]u8, b: [32]u8) bool {
    var i: usize = 0;
    while (i < 32) : (i += 1) {
        if (a[i] < b[i]) return true;
        if (a[i] > b[i]) return false;
    }
    return false; // a == b
}

/// Generate complete SM9 system with both master key pairs
pub const SM9System = struct {
    params: SystemParams,
    sign_master: SignMasterKeyPair,
    encrypt_master: EncryptMasterKeyPair,

    /// Initialize new SM9 system with default parameters
    pub fn init() SM9System {
        const params = SystemParams.init();
        return SM9System{
            .params = params,
            .sign_master = SignMasterKeyPair.generate(params),
            .encrypt_master = EncryptMasterKeyPair.generate(params),
        };
    }

    /// Initialize SM9 system with custom parameters
    pub fn initWithParams(params: SystemParams) !SM9System {
        if (!params.validate()) {
            return ParameterError.ParameterGenerationFailed;
        }

        return SM9System{
            .params = params,
            .sign_master = SignMasterKeyPair.generate(params),
            .encrypt_master = EncryptMasterKeyPair.generate(params),
        };
    }

    /// Validate complete SM9 system
    pub fn validate(self: SM9System) bool {
        return self.params.validate() and
               self.sign_master.validate(self.params) and
               self.encrypt_master.validate(self.params);
    }
};
