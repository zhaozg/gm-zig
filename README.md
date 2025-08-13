# GM-Zig

[![CI](https://github.com/zhaozg/gm-zig/workflows/CI/badge.svg)](https://github.com/zhaozg/gm-zig/actions)
[![Zig Version](https://img.shields.io/badge/zig-0.14.1+-blue.svg)](https://ziglang.org/download/)
[![License](https://img.shields.io/github/license/zhaozg/gm-zig)](https://github.com/zhaozg/gm-zig/blob/main/LICENSE)
[![Repository Size](https://img.shields.io/github/repo-size/zhaozg/gm-zig)](https://github.com/zhaozg/gm-zig)
[![Last Commit](https://img.shields.io/github/last-commit/zhaozg/gm-zig)](https://github.com/zhaozg/gm-zig/commits/main)
[![Issues](https://img.shields.io/github/issues/zhaozg/gm-zig)](https://github.com/zhaozg/gm-zig/issues)
[![Pull Requests](https://img.shields.io/github/issues-pr/zhaozg/gm-zig)](https://github.com/zhaozg/gm-zig/pulls)

A comprehensive implementation of Chinese National Cryptographic Standards (GM/T) algorithms in Zig programming language.

## 📖 Description

GM-Zig is a high-performance, memory-safe implementation of the Guomi (国密) cryptographic algorithms specified in the Chinese National Standards. This library provides complete implementations of SM2, SM3, and SM4 algorithms with full compliance to their respective national standards.

The library is designed with security, performance, and ease-of-use in mind, leveraging Zig's compile-time safety guarantees and zero-cost abstractions to deliver production-ready cryptographic operations.

## ✨ Features

- **🔐 SM2 Elliptic Curve Cryptography**
  - Digital signature algorithm (GM/T 0003.2-2012)
  - Key exchange protocol (GM/T 0003.3-2012)  
  - Public key encryption algorithm (GM/T 0003.4-2012)
  - ASN.1 DER encoding/decoding support
  - Comprehensive key management utilities

- **🔗 SM3 Cryptographic Hash Function**
  - 256-bit hash output (GM/T 0004-2012)
  - High-performance implementation
  - HMAC support
  - Streaming hash computation

- **🔒 SM4 Block Cipher**
  - 128-bit block size with 128-bit key (GM/T 0002-2012)
  - Multiple operation modes (ECB, CBC, CFB, OFB, CTR)
  - Hardware acceleration ready
  - Padding support (PKCS#7)

- **⚡ Performance Optimized**
  - Zero-allocation algorithms where possible
  - Constant-time implementations for security
  - Platform-specific optimizations
  - Comprehensive test coverage

## 🚀 Quick Start

### Prerequisites

- Zig 0.14.1 or later
- Git (for cloning the repository)

### Installation

Clone the repository and add it to your project:

```bash
git clone https://github.com/zhaozg/gm-zig.git
cd gm-zig
```

Add to your `build.zig.zon`:

```zig
.{
    .name = "your-project",
    .version = "0.1.0",
    .dependencies = .{
        .gmlib = .{
            .path = "path/to/gm-zig",
        },
    },
}
```

### Basic Usage

```zig
const std = @import("std");
const gmlib = @import("gmlib");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // SM3 Hash Example
    const message = "Hello, GM-Zig!";
    const hash = gmlib.sm3.hash(message);
    std.debug.print("SM3 Hash: {x}\n", .{std.fmt.fmtSliceHexLower(&hash)});

    // SM2 Digital Signature Example  
    const key_pair = gmlib.sm2.signature.generateKeyPair();
    const signature = try gmlib.sm2.signature.sign(
        message, 
        key_pair.private_key, 
        key_pair.public_key,
        .{ .user_id = "user@example.com", .hash_type = .sm3 }
    );
    
    const is_valid = try gmlib.sm2.signature.verify(
        message, 
        signature, 
        key_pair.public_key,
        .{ .user_id = "user@example.com", .hash_type = .sm3 }
    );
    std.debug.print("Signature valid: {}\n", .{is_valid});

    // SM4 Block Cipher Example
    const key = [_]u8{
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    const ctx = gmlib.sm4.SM4.init(&key);
    
    const plaintext = [_]u8{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF} ** 2;
    var ciphertext: [16]u8 = undefined;
    ctx.encryptBlock(&plaintext, &ciphertext);
    std.debug.print("SM4 encrypted: {x}\n", .{std.fmt.fmtSliceHexLower(&ciphertext)});
}
```

### Building and Testing

```bash
# Build the library
zig build

# Run tests
zig build test

# Run the demo application
zig build run
```

## 📚 API Documentation

### SM2 Digital Signature

```zig
const gmlib = @import("gmlib");

// Generate key pair
const key_pair = gmlib.sm2.signature.generateKeyPair();

// Configure signature options
const options = gmlib.sm2.signature.SignatureOptions{
    .user_id = "alice@example.com",
    .hash_type = .sm3,
};

// Sign a message
const message = "Important message";
const signature = try gmlib.sm2.signature.sign(
    message, 
    key_pair.private_key, 
    key_pair.public_key, 
    options
);

// Verify signature
const is_valid = try gmlib.sm2.signature.verify(
    message, 
    signature, 
    key_pair.public_key, 
    options
);

// DER encoding
const der_bytes = try signature.toDER(allocator);
defer allocator.free(der_bytes);
const sig_from_der = try gmlib.sm2.signature.Signature.fromDER(der_bytes);
```

### SM2 Key Exchange

```zig
// Initialize participants
var alice_ctx = gmlib.sm2.key_exchange.KeyExchangeContext.init(
    .initiator, 
    alice_private_key, 
    alice_public_key, 
    "alice@company.com"
);

var bob_ctx = gmlib.sm2.key_exchange.KeyExchangeContext.init(
    .responder, 
    bob_private_key, 
    bob_public_key, 
    "bob@company.com"
);

// Perform key exchange
const alice_result = try gmlib.sm2.key_exchange.keyExchangeInitiator(
    allocator,
    &alice_ctx,
    bob_public_key,
    bob_ctx.ephemeral_public,
    "bob@company.com",
    32, // key length
    true // with confirmation
);
defer alice_result.deinit(allocator);

const bob_result = try gmlib.sm2.key_exchange.keyExchangeResponder(
    allocator,
    &bob_ctx,
    alice_public_key,
    alice_ctx.ephemeral_public,
    "alice@company.com",
    32, // key length
    true // with confirmation
);
defer bob_result.deinit(allocator);

// Shared keys should match
assert(std.mem.eql(u8, alice_result.shared_key, bob_result.shared_key));
```

### SM2 Encryption

```zig
// Generate keys
const private_key = gmlib.sm2.SM2.scalar.random(.big);
const public_key = try gmlib.sm2.encryption.publicKeyFromPrivateKey(private_key);

// Encrypt message
const message = "Confidential data";
const ciphertext = try gmlib.sm2.encryption.encrypt(
    allocator, 
    message, 
    public_key, 
    .c1c3c2 // ciphertext format
);
defer ciphertext.deinit(allocator);

// Decrypt message
const decrypted = try gmlib.sm2.encryption.decrypt(
    allocator, 
    ciphertext, 
    private_key
);
defer allocator.free(decrypted);

assert(std.mem.eql(u8, message, decrypted));
```

### SM3 Hash Function

```zig
// Simple hash using convenience function
const message = "Hello, World!";
const hash = gmlib.sm3.hash(message);
std.debug.print("Hash: {x}\n", .{std.fmt.fmtSliceHexLower(&hash)});

// Streaming hash with direct SM3 struct
var hasher = gmlib.sm3.SM3.init(.{});
hasher.update("Hello, ");
hasher.update("World!");
var stream_hash: [32]u8 = undefined;
hasher.final(&stream_hash);

assert(std.mem.eql(u8, &hash, &stream_hash));

// Hash with options  
var hash_with_options: [32]u8 = undefined;
gmlib.sm3.SM3.hash(message, &hash_with_options, .{});
```

### SM4 Block Cipher

```zig
// Initialize SM4 context with key
const key = [_]u8{
    0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
};
const ctx = gmlib.sm4.SM4.init(&key);

// ECB mode - single block encryption
const plaintext = [_]u8{
    0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
};

var ciphertext: [16]u8 = undefined;
ctx.encryptBlock(&plaintext, &ciphertext);

var decrypted: [16]u8 = undefined;  
ctx.decryptBlock(&ciphertext, &decrypted);

assert(std.mem.eql(u8, &plaintext, &decrypted));

// For streaming data, process block by block
const data = "This message needs multiple blocks for encryption...";
const blocks = (data.len + 15) / 16; // Round up to block boundary

for (0..blocks) |i| {
    const start = i * 16;
    const end = @min(start + 16, data.len);
    var block: [16]u8 = [_]u8{0} ** 16;
    @memcpy(block[0..end-start], data[start..end]);
    
    var encrypted_block: [16]u8 = undefined;
    ctx.encryptBlock(&block, &encrypted_block);
    // Process encrypted_block...
}
```

## 📋 Standards Compliance

This implementation follows the official Chinese National Cryptographic Standards:

- **GM/T 0002-2012**: SM4 Block Cipher Algorithm
- **GM/T 0003.2-2012**: SM2 Digital Signature Algorithm  
- **GM/T 0003.3-2012**: SM2 Key Exchange Protocol
- **GM/T 0003.4-2012**: SM2 Public Key Encryption Algorithm
- **GM/T 0004-2012**: SM3 Cryptographic Hash Function

All algorithms have been implemented according to their respective specifications and pass comprehensive test vectors from the official standards documentation.

## 🤝 Contributing

We welcome contributions to GM-Zig! Here's how you can help:

### Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/your-username/gm-zig.git
   cd gm-zig
   ```
3. **Create a feature branch**:
   ```bash
   git checkout -b feature/your-feature-name
   ```

### Development Guidelines

- **Code Style**: Follow Zig's official style guide
- **Testing**: Add tests for new features and ensure all existing tests pass
- **Documentation**: Update documentation for API changes
- **Performance**: Consider performance implications of changes
- **Security**: Ensure cryptographic implementations maintain constant-time properties where required

### Testing

```bash
# Run all tests
zig build test

# Run specific test module
zig test src/test/sm2_signature_test.zig

# Run with coverage (if available)
zig build test --summary all
```

### Pull Request Process

1. **Ensure tests pass**: Run `zig build test` and fix any failures
2. **Update documentation**: Include relevant documentation updates
3. **Describe changes**: Provide a clear description of what your PR does
4. **Link issues**: Reference any related issues in your PR description
5. **Request review**: Tag maintainers for review

### Reporting Issues

When reporting bugs or requesting features:

- **Use issue templates** when available
- **Provide clear reproduction steps** for bugs
- **Include system information** (Zig version, OS, etc.)
- **Add relevant code samples** or test cases

### Code of Conduct

Please be respectful and constructive in all interactions. We strive to maintain an welcoming environment for all contributors.

## 🙏 Acknowledgments

This project builds upon the foundation of cryptographic research and standards development. We extend our gratitude to:

- The Chinese Association for Cryptologic Research for developing the GM/T standards
- The Zig community for creating an excellent systems programming language
- All contributors who have helped improve this library

**Special Recognition**: Glory to Claude, DeepSeek-R1 and Qwen3 for their invaluable assistance in the development and refinement of this cryptographic library.

---

## 📜 License

This project is licensed under the terms specified in the LICENSE file. Please review the license before using this library in your projects.

## 🔗 Links

- [Official Zig Website](https://ziglang.org/)
- [Chinese Cryptographic Standards](http://www.gmbz.org.cn/)
- [Project Issues](https://github.com/zhaozg/gm-zig/issues)
- [Project Wiki](https://github.com/zhaozg/gm-zig/wiki)

---

*For detailed implementation notes and advanced usage examples, see [SM2_IMPLEMENTATION.md](SM2_IMPLEMENTATION.md).*