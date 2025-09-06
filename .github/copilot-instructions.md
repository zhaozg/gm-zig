# GM-Zig Cryptographic Library

GM-Zig is a high-performance implementation of Chinese National Cryptographic Standards (GM/T) algorithms in Zig. It provides complete implementations of SM2, SM3, SM4, and SM9 algorithms with full standards compliance and comprehensive security features.

Always reference these instructions first and fallback to search or bash commands only when you encounter unexpected information that does not match the info here.

## Working Effectively

### Prerequisites and Installation
- **CRITICAL**: Zig 0.14.1 or later is REQUIRED. The project will not build with Zig 0.13.0 or earlier.
- Git (for cloning the repository)

### Installing Zig 0.14.1
```bash
# Download Zig 0.14.1 from official source
curl -s "https://ziglang.org/download/index.json" | jq -r '.["0.14.1"]."x86_64-linux".tarball'
wget https://ziglang.org/download/0.14.1/zig-x86_64-linux-0.14.1.tar.xz -O zig-0.14.1.tar.xz
tar -xf zig-0.14.1.tar.xz
sudo mv zig-x86_64-linux-0.14.1 /usr/local/zig
sudo ln -sf /usr/local/zig/zig /usr/local/bin/zig

# Verify installation
zig version  # Should output: 0.14.1
```

### Building and Testing the Repository
- Bootstrap and build the repository:
  - `zig build` -- takes ~15 seconds. NEVER CANCEL. Set timeout to 30+ minutes for safety.
  - `zig build -Doptimize=ReleaseFast` -- optimized build, takes ~13 seconds. Provides 10x+ performance improvement.
  - `zig build -Dtarget=wasm32-freestanding` -- WASM build, takes ~4 seconds.
- Test the repository:
  - `zig build test` -- takes ~10 seconds. NEVER CANCEL. Set timeout to 30+ minutes.
  - `zig test src/test.zig` -- core tests (119 tests), takes ~7 seconds.
  - `zig test src/testsm9.zig` -- SM9 specific tests (14 tests), takes ~3 seconds.
  - Combined CI tests: `zig test src/test.zig && zig test src/testsm9.zig` -- takes ~13 seconds total.
- Run the demo application:
  - `zig build run` -- runs demo with performance tests, takes ~7 seconds (debug) or ~0.5 seconds (optimized).

### Build File Fix Required
**IMPORTANT**: The build.zig.zon file may have a syntax error. If you see `error: expected enum literal`, fix it by changing:
```zig
.name = "gmlib",  # Change this to:
.name = .gmlib,   # Use enum literal format
```

## Validation

### CRITICAL Build and Test Timing Expectations
- **NEVER CANCEL BUILDS OR TESTS** - All operations complete quickly but set generous timeouts
- Build: 15 seconds (debug), 13 seconds (optimized), 4 seconds (WASM) - NEVER CANCEL, use 30+ minute timeout
- Tests: 10-13 seconds total - NEVER CANCEL, use 30+ minute timeout  
- Demo run: 7 seconds (debug), 0.5 seconds (optimized)

### Manual Validation Scenarios
After making changes, ALWAYS run through these validation scenarios:

1. **Core Build Validation**:
   ```bash
   zig build                    # Must complete successfully
   zig build -Doptimize=ReleaseFast  # Must complete successfully
   zig build test               # All tests must pass
   ```

2. **Cryptographic Function Validation**:
   ```bash
   zig build run                # Demo must run completely and show:
   ```
   - SM3 hash performance metrics (18+ MB/s debug, 240+ MB/s optimized)
   - SM2 digital signature creation and verification (must show "true")
   - SM2 key exchange with matching shared keys
   - SM2 encryption/decryption roundtrip success
   - All DER encoding roundtrips must succeed

3. **Code Quality Validation**:
   ```bash
   zig fmt --check src/         # Will show files with formatting issues
   # NOTE: Some files have formatting issues - this is expected
   ```

### CI Validation
The GitHub Actions CI runs:
1. `zig version` - Verify Zig installation
2. `zig test src/test.zig` - Core tests (119 tests)  
3. `zig test src/testsm9.zig` - SM9 tests (14 tests)
4. `zig build` - Build project
5. `zig build test` - Build and run tests

Always run these exact commands locally before committing to ensure CI will pass.

## Common Tasks

### Repository Structure
```
gm-zig/
├── build.zig               # Main build configuration
├── build.zig.zon          # Dependencies and package info
├── src/
│   ├── root.zig           # Library root - exports sm2, sm3, sm4, sm9
│   ├── main.zig           # Demo application entry point
│   ├── wasm.zig           # WASM-specific entry point
│   ├── sm2.zig sm3.zig sm4.zig sm9.zig  # Algorithm implementations
│   ├── sm2/               # SM2 implementation modules
│   ├── sm9/               # SM9 implementation modules  
│   ├── test.zig           # Main test suite runner
│   ├── testsm9.zig        # SM9-specific test runner
│   └── test/              # Individual test modules
├── README.md              # Comprehensive project documentation
├── SM2_IMPLEMENTATION.md  # SM2 technical details
├── SM9_IMPLEMENTATION.md  # SM9 technical details
└── .github/workflows/ci.yml  # CI configuration
```

### Key Algorithm Status
- **SM2 Elliptic Curve Cryptography**: ✅ Production ready - digital signatures, key exchange, encryption
- **SM3 Cryptographic Hash Function**: ✅ Production ready - 256-bit hash with HMAC support
- **SM4 Block Cipher**: ✅ Production ready - 128-bit block cipher with multiple modes
- **SM9 Identity-Based Cryptography**: ✅ Complete implementation - Phase 4 complete with all algorithms

### Performance Notes
- Use `zig build -Doptimize=ReleaseFast` for performance testing
- SM3 hash performance: ~19 MB/s (debug) vs ~243 MB/s (optimized)
- Total demo runtime: ~7 seconds (debug) vs ~0.5 seconds (optimized)
- Memory-safe with zero-allocation algorithms where possible
- Constant-time implementations to prevent timing attacks

### Testing Infrastructure
- **Total Tests**: 133 tests (119 core + 14 SM9)
- **Test Categories**: 
  - SM2: Group operations, signatures, encryption, key exchange
  - SM3: Hash functions and performance
  - SM4: Block cipher operations  
  - SM9: Field operations, curves, security, parameters
- **Test Execution**: All tests pass reliably with deterministic results
- **Individual Test Modules**: Cannot be run standalone - must use test runners

### Known Issues and Limitations
- Code formatting: Some files have formatting issues (expected, not blocking)
- Individual test files cannot be run directly due to import paths
- Project requires exact Zig version 0.14.1+ (will not work with 0.13.0)
- WASM builds work but cannot interact with UI in test environments

### Troubleshooting
- **Build fails with "Zig version 0.14 or newer is required"**: Install Zig 0.14.1+
- **Build fails with "expected enum literal"**: Fix build.zig.zon name field format
- **Individual tests fail with import errors**: Use `zig build test` or test runners instead
- **Performance seems slow**: Use optimized builds with `-Doptimize=ReleaseFast`

## Development Workflow
1. Always verify Zig version: `zig version` (must be 0.14.1+)
2. Build: `zig build` (15 seconds, never cancel)
3. Test: `zig build test` (10 seconds, never cancel) 
4. Validate: `zig build run` (must complete successfully)
5. For performance work: Use `zig build -Doptimize=ReleaseFast`
6. Before committing: Run CI commands locally to ensure they pass

Remember: This is a cryptographic library implementing Chinese national standards. Security and correctness are paramount. Always run complete validation scenarios after making changes.