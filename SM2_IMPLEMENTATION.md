# SM2 Algorithm Implementation

This document describes the comprehensive SM2 cryptographic algorithm implementation added to the GM-Zig library.

## Overview

The implementation provides complete SM2 cryptographic functionality as specified in the Chinese National Standards (GM/T):

- **GM/T 0003.2-2012**: SM2 Digital Signature Algorithm
- **GM/T 0003.3-2012**: SM2 Key Exchange Protocol  
- **GM/T 0003.4-2012**: SM2 Public Key Encryption Algorithm

## Module Structure

```
src/sm2/
├── signature.zig      # Digital signature algorithm
├── key_exchange.zig   # Key exchange protocol
├── encryption.zig     # Public key encryption
└── utils.zig         # Utility functions (KDF, DER encoding, etc.)

src/
├── sm2_signature_test.zig     # Signature tests
├── sm2_key_exchange_test.zig  # Key exchange tests
└── sm2_encryption_test.zig    # Encryption tests
```

## API Reference

### Digital Signature (`sm2.signature`)

#### Key Generation

```zig
const key_pair = sm2.signature.generateKeyPair();
// Or from existing private key:
const key_pair = try sm2.signature.KeyPair.fromPrivateKey(private_key);
```

#### Signing

```zig
const options = sm2.signature.SignatureOptions{
    .user_id = "alice@example.com",
    .hash_type = .sm3,
};

const signature = try sm2.signature.sign(
    message, 
    key_pair.private_key, 
    key_pair.public_key, 
    options
);
```

#### Verification

```zig
const is_valid = try sm2.signature.verify(
    message, 
    signature, 
    key_pair.public_key, 
    options
);
```

#### Signature Formats

```zig
// Raw bytes (64 bytes: R || S)
const raw_bytes = signature.toBytes();
const sig_from_bytes = sm2.signature.Signature.fromBytes(raw_bytes);

// ASN.1 DER encoding
const der_bytes = try signature.toDER(allocator);
defer allocator.free(der_bytes);
const sig_from_der = try sm2.signature.Signature.fromDER(der_bytes);
```

### Key Exchange (`sm2.key_exchange`)

#### Setup

```zig
// Alice (initiator)
var alice_ctx = sm2.key_exchange.KeyExchangeContext.init(
    .initiator, alice_private, alice_public, "alice@company.com"
);

// Bob (responder)  
var bob_ctx = sm2.key_exchange.KeyExchangeContext.init(
    .responder, bob_private, bob_public, "bob@company.com"
);
```

#### Key Exchange

```zig
const key_length = 32;
const with_confirmation = true;

// Alice computes shared key
const alice_result = try sm2.key_exchange.keyExchangeInitiator(
    allocator, &alice_ctx, bob_public, bob_ctx.ephemeral_public, 
    "bob@company.com", key_length, with_confirmation
);
defer alice_result.deinit(allocator);

// Bob computes shared key
const bob_result = try sm2.key_exchange.keyExchangeResponder(
    allocator, &bob_ctx, alice_public, alice_ctx.ephemeral_public,
    "alice@company.com", key_length, with_confirmation
);
defer bob_result.deinit(allocator);

// Shared keys should be equal
assert(std.mem.eql(u8, alice_result.shared_key, bob_result.shared_key));
```

### Public Key Encryption (`sm2.encryption`)

#### Encryption

```zig
const public_key = try sm2.encryption.publicKeyFromPrivateKey(private_key);

// Encrypt with C1C3C2 format (standard)
const ciphertext = try sm2.encryption.encrypt(
    allocator, message, public_key, .c1c3c2
);
defer ciphertext.deinit(allocator);

// Or use convenience function
const encrypted_bytes = try sm2.encryption.encryptWithFormat(
    allocator, message, public_key, .c1c3c2
);
defer allocator.free(encrypted_bytes);
```

#### Decryption

```zig
const decrypted = try sm2.encryption.decrypt(allocator, ciphertext, private_key);
defer allocator.free(decrypted);

// Or use convenience function
const decrypted2 = try sm2.encryption.decryptWithFormat(
    allocator, encrypted_bytes, private_key, .c1c3c2
);
defer allocator.free(decrypted2);
```

#### Ciphertext Formats

```zig
// C1C3C2 format: C1 || C3 || C2 (standard)
const ciphertext_std = try encrypt(allocator, message, public_key, .c1c3c2);

// C1C2C3 format: C1 || C2 || C3 (alternative)
const ciphertext_alt = try encrypt(allocator, message, public_key, .c1c2c3);
```

### Utilities (`sm2.utils`)

#### Key Derivation Function (KDF)

```zig
const shared_secret = "shared secret data";
const derived_key = try sm2.utils.kdf(allocator, shared_secret, 32);
defer allocator.free(derived_key);
```

#### User Identity Hash

```zig
const user_hash = sm2.utils.computeUserHash(
    "alice@example.com", 
    public_key_x, 
    public_key_y
);
```

#### ASN.1 DER Encoding

```zig
const der_bytes = try sm2.utils.encodeSignatureDER(allocator, r, s);
defer allocator.free(der_bytes);

const decoded = try sm2.utils.decodeSignatureDER(der_bytes);
```

## Security Features

- **Cryptographically Secure Random Numbers**: All random number generation uses `std.crypto.random`
- **Constant-Time Operations**: Critical comparisons use constant-time implementations
- **Point Validation**: All elliptic curve points are validated before use
- **MAC Authentication**: Encryption includes SM3-based message authentication
- **Standard Compliance**: Strict adherence to GM/T specifications

## Error Handling

All functions return appropriate error types:

```zig
// Common errors
error.IdentityElement        // Invalid elliptic curve point
error.InvalidEncoding        // Malformed input data
error.NonCanonical          // Non-canonical field element
error.InvalidMAC            // Authentication failure
error.InvalidPrivateKey     // Invalid private key
error.EmptyMessage          // Empty input message
```

## Testing

Run comprehensive tests:

```bash
zig build test
```

Test files include:
- Standard test vectors
- Edge cases and error conditions
- Cross-format compatibility
- Performance benchmarks
- Security validation

## Performance

The implementation is optimized for performance:
- Uses existing high-performance elliptic curve operations
- SIMD-optimized SM3 hash function
- Efficient memory management
- Minimal allocations in critical paths

## Usage Example

See `src/main.zig` for a complete demonstration of all SM2 algorithms.

```bash
zig build run
```

This will run performance tests for SM3/SM4 and demonstrate all SM2 functionality including signatures, key exchange, and encryption.

## Standards Compliance

This implementation strictly follows the Chinese National Standards:

- **GM/T 0003.1-2012**: SM2 Elliptic Curve Public Key Cryptography Algorithm (curve operations)
- **GM/T 0003.2-2012**: SM2 Digital Signature Algorithm  
- **GM/T 0003.3-2012**: SM2 Key Exchange Protocol
- **GM/T 0003.4-2012**: SM2 Public Key Encryption Algorithm

All algorithms use the standard SM2 curve parameters and are compatible with other GM/T-compliant implementations.