# GM-Zig

A comprehensive implementation of Chinese national cryptographic standards (GM algorithms) in Zig programming language.

## Status

[![CI](https://github.com/zhaozg/gm-zig/workflows/CI/badge.svg)](https://github.com/zhaozg/gm-zig/actions)
[![Zig Version](https://img.shields.io/badge/zig-0.14.1-blue.svg)](https://ziglang.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Repository Size](https://img.shields.io/github/repo-size/zhaozg/gm-zig)](https://github.com/zhaozg/gm-zig)
[![Last Commit](https://img.shields.io/github/last-commit/zhaozg/gm-zig)](https://github.com/zhaozg/gm-zig/commits/main)
[![Issues](https://img.shields.io/github/issues/zhaozg/gm-zig)](https://github.com/zhaozg/gm-zig/issues)
[![Pull Requests](https://img.shields.io/github/issues-pr/zhaozg/gm-zig)](https://github.com/zhaozg/gm-zig/pulls)

## Description

GM-Zig is a pure Zig implementation of the Chinese national cryptographic algorithms, also known as "Guomi" (国密) algorithms. This library provides secure, efficient, and standards-compliant implementations of SM2, SM3, and SM4 cryptographic algorithms as specified in the official Chinese national standards.

## Features

- **SM2 Elliptic Curve Cryptography**: Digital signatures, public key encryption, and key exchange
- **SM3 Hash Algorithm**: Cryptographic hash function with 256-bit output
- **SM4 Block Cipher**: Symmetric encryption with 128-bit keys and blocks
- **Standards Compliant**: Implements official GM/T specifications
- **Zero Dependencies**: Pure Zig implementation with no external dependencies
- **Comprehensive Testing**: Extensive test suite with official test vectors
- **Memory Safe**: Leverages Zig's memory safety features
- **Cross Platform**: Works on all platforms supported by Zig

## Requirements

- **Zig 0.14.1** or later

## Quick Start

### Installation

Clone the repository:

\`\`\`bash
git clone https://github.com/zhaozg/gm-zig.git
cd gm-zig
\`\`\`

### Basic Usage

\`\`\`zig
const std = @import("std");
const gmlib = @import("gmlib");

pub fn main() !void {
    // SM3 Hash example
    var hash: [32]u8 = undefined;
    gmlib.sm3.SM3.hash("Hello, GM!", &hash, .{});
    
    // SM4 Encryption example
    const key = [16]u8{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
    const sm4_ctx = gmlib.sm4.SM4.init(&key);
    
    // SM2 Key generation example
    const key_pair = gmlib.sm2.signature.generateKeyPair();
}
\`\`\`

## Building

### Build Library

\`\`\`bash
zig build
\`\`\`

### Build and Run Example

\`\`\`bash
zig build run
\`\`\`

### Development Build

\`\`\`bash
zig build -Doptimize=Debug
\`\`\`

### Release Build

\`\`\`bash
zig build -Doptimize=ReleaseFast
\`\`\`

## Testing

### Run All Tests

\`\`\`bash
zig build test
\`\`\`

### Run Specific Algorithm Tests

\`\`\`bash
# SM3 tests
zig test src/test/sm3_test.zig

# SM4 tests  
zig test src/test/sm4_test.zig

# SM2 tests
zig test src/test/sm2_signature_test.zig
zig test src/test/sm2_encryption_test.zig
zig test src/test/sm2_key_exchange_test.zig
\`\`\`

### Run Tests with Coverage

\`\`\`bash
zig build test -Dtest-coverage
\`\`\`

## API Documentation

### SM2 Elliptic Curve Cryptography

SM2 is an elliptic curve cryptography algorithm suite including digital signatures, public key encryption, and key exchange.

#### Digital Signatures

\`\`\`zig
const std = @import("std");
const gmlib = @import("gmlib");
const signature = gmlib.sm2.signature;

// Generate key pair
const key_pair = signature.generateKeyPair();

// Sign a message
const message = "Hello, SM2!";
const options = signature.SignatureOptions{
    .user_id = "alice@example.com",
    .hash_type = .sm3,
};

const sig = try signature.sign(message, key_pair.private_key, key_pair.public_key, options);

// Verify signature
const is_valid = try signature.verify(message, sig, key_pair.public_key, options);
\`\`\`

#### Public Key Encryption

\`\`\`zig
const std = @import("std");
const gmlib = @import("gmlib");
const encryption = gmlib.sm2.encryption;

// Generate key pair
const key_pair = encryption.generateKeyPair();

// Encrypt data
const plaintext = "Secret message";
const ciphertext = try encryption.encrypt(plaintext, key_pair.public_key);

// Decrypt data
const decrypted = try encryption.decrypt(ciphertext, key_pair.private_key);
\`\`\`

#### Key Exchange

\`\`\`zig
const std = @import("std");
const gmlib = @import("gmlib");
const key_exchange = gmlib.sm2.key_exchange;

// Alice generates key pair and ephemeral key
const alice_key_pair = key_exchange.generateKeyPair();
const alice_ephemeral = key_exchange.generateEphemeralKey();

// Bob generates key pair and ephemeral key  
const bob_key_pair = key_exchange.generateKeyPair();
const bob_ephemeral = key_exchange.generateEphemeralKey();

// Perform key exchange
const shared_key = try key_exchange.deriveSharedKey(
    alice_key_pair.private_key,
    alice_ephemeral.private_key,
    bob_key_pair.public_key,
    bob_ephemeral.public_key
);
\`\`\`

### SM3 Hash Algorithm

SM3 is a cryptographic hash function that produces a 256-bit hash value.

#### One-shot Hashing

\`\`\`zig
const std = @import("std");
const gmlib = @import("gmlib");

// Hash a message in one operation
const message = "Hello, SM3!";
var hash: [32]u8 = undefined;
gmlib.sm3.SM3.hash(message, &hash, .{});

// Print hash in hex format
const allocator = std.heap.page_allocator;
const hex_string = try std.fmt.allocPrint(allocator, "{x}", .{std.fmt.fmtSliceHexLower(&hash)});
std.debug.print("Hash: {s}\n", .{hex_string});
\`\`\`

#### Streaming Hashing

\`\`\`zig
const std = @import("std");
const gmlib = @import("gmlib");

// Initialize SM3 context
var hasher = gmlib.sm3.SM3.init(.{});

// Update with data chunks
hasher.update("Hello, ");
hasher.update("SM3!");

// Finalize and get hash
var hash: [32]u8 = undefined;
hasher.final(&hash);
\`\`\`

### SM4 Block Cipher

SM4 is a block cipher with 128-bit keys and 128-bit blocks, supporting multiple modes of operation.

#### ECB Mode

\`\`\`zig
const std = @import("std");
const gmlib = @import("gmlib");

// Initialize SM4 with key
const key = [16]u8{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
const sm4_ctx = gmlib.sm4.SM4.init(&key);

// Encrypt single block
const plaintext = [16]u8{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
var ciphertext: [16]u8 = undefined;
sm4_ctx.encryptBlock(&plaintext, &ciphertext);

// Decrypt single block
var decrypted: [16]u8 = undefined;
sm4_ctx.decryptBlock(&ciphertext, &decrypted);
\`\`\`

#### CBC Mode

\`\`\`zig
const std = @import("std");
const gmlib = @import("gmlib");

// Initialize SM4 CBC
const key = [16]u8{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
const iv = [16]u8{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

// Encrypt data
const plaintext = "This is a test message for SM4 CBC mode encryption";
const allocator = std.heap.page_allocator;
const ciphertext = try gmlib.sm4.encryptCBC(allocator, plaintext, &key, &iv);

// Decrypt data
const decrypted = try gmlib.sm4.decryptCBC(allocator, ciphertext, &key, &iv);
\`\`\`

## Standards Compliance

This implementation strictly follows the official Chinese national cryptographic standards:

- **GM/T 0003-2012**: SM2 Elliptic Curve Cryptographic Algorithm
  - Part 2: Digital Signature Algorithm
  - Part 3: Key Exchange Protocol  
  - Part 4: Public Key Encryption Algorithm
- **GM/T 0004-2012**: SM3 Cryptographic Hash Algorithm
- **GM/T 0002-2012**: SM4 Block Cipher Algorithm

All implementations are verified against official test vectors and comply with the specifications defined in these standards.

## Contributing

We welcome contributions to GM-Zig! Please follow these guidelines:

### Development Setup

1. Fork the repository
2. Clone your fork: \`git clone https://github.com/yourusername/gm-zig.git\`
3. Create a feature branch: \`git checkout -b feature-name\`
4. Make your changes and add tests
5. Run tests: \`zig build test\`
6. Commit your changes: \`git commit -am 'Add feature'\`
7. Push to the branch: \`git push origin feature-name\`
8. Submit a pull request

### Code Style

- Follow Zig's standard formatting (\`zig fmt\`)
- Include comprehensive tests for new features
- Document public APIs with clear examples
- Ensure all tests pass before submitting

### Testing Requirements

- All new code must include tests
- Test coverage should remain above 90%
- Include both positive and negative test cases
- Use official test vectors where available

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Security Notice

⚠️ **Important Security Disclaimer** ⚠️

This cryptographic library is provided for educational and development purposes. While it implements the official Chinese national cryptographic standards with careful attention to correctness, it has not undergone independent security audits.

**Before using in production:**

- Conduct thorough security reviews
- Perform independent cryptographic audits
- Validate against your specific security requirements
- Consider side-channel attack resistance
- Ensure proper key management practices

The authors and contributors are not responsible for any security vulnerabilities or damages resulting from the use of this library.

## Acknowledgments

- Chinese National Cryptographic Administration for the GM algorithm specifications
- Zig community for the excellent programming language and ecosystem
- Contributors who have helped improve this implementation

## References

- [GM/T 0003-2012 SM2 Specification](http://www.sca.gov.cn/sca/xwdt/2010-12/17/content_1002386.shtml)
- [GM/T 0004-2012 SM3 Specification](http://www.sca.gov.cn/sca/xwdt/2010-12/17/content_1002386.shtml)  
- [GM/T 0002-2012 SM4 Specification](http://www.sca.gov.cn/sca/xwdt/2010-12/17/content_1002386.shtml)
- [Zig Programming Language](https://ziglang.org/)
