# GM-Zig Enhanced Development Guide

This guide supplements the existing `.github/copilot-instructions.md` with additional configurations and tooling to make GitHub Copilot even smarter when working with the GM-Zig cryptographic library.

## 🤖 Enhanced Copilot Configuration

### Model Context Protocol (MCP) Servers

The repository now includes MCP server configurations in `.github/mcp-config.json` that provide Copilot with enhanced context about:

- **Cryptographic Domain Knowledge**: Understanding of Chinese National Standards (GM/T)
- **Algorithm-Specific Context**: SM2, SM3, SM4, and SM9 implementation details
- **Security-Critical Code Patterns**: Constant-time implementations, secure memory handling
- **Performance Optimization Patterns**: Memory-efficient algorithms, Zig-specific optimizations

### VS Code Integration

Complete VS Code workspace configuration is provided in `.vscode/`:

- **Workspace Settings**: Optimized for Zig development with proper formatting, extensions, and debugging
- **Tasks**: Pre-configured build, test, and validation tasks
- **Launch Configurations**: Ready-to-use debugging setups for both library and tests
- **Extension Recommendations**: Essential extensions for cryptographic library development

## 🛠️ Development Environment Setup

### Quick Setup

Run the automated setup script:

```bash
./scripts/setup-dev-env.sh
```

This script will:
- ✅ Verify Zig installation (0.14.1+ or 0.15.x)
- ✅ Check system dependencies
- ✅ Fix common build issues (e.g., build.zig.zon enum literal)
- ✅ Set up development aliases and git hooks
- ✅ Establish performance baseline
- ✅ Validate the complete development environment

### Manual Setup Steps

If you prefer manual setup:

1. **Verify Zig Installation**:
   ```bash
   zig version  # Should be 0.14.1+ or 0.15.x
   ```

2. **Install Dependencies**:
   ```bash
   sudo apt-get install -y jq gdb  # For JSON processing and debugging
   ```

3. **Fix Build Configuration** (if needed):
   ```bash
   # Fix enum literal in build.zig.zon if you see "expected enum literal" error
   sed -i 's/\.name = "gmlib"/\.name = .gmlib/' build.zig.zon
   ```

4. **Validate Environment**:
   ```bash
   zig build && zig build test && zig build run
   ```

## 🚀 Enhanced Development Workflow

### Alias Commands

After running the setup script, you'll have convenient aliases:

```bash
gmzig-build         # Standard build
gmzig-build-fast    # Optimized build (10x+ performance)
gmzig-test          # Run all 219 tests
gmzig-run           # Run demo with performance metrics
gmzig-fmt           # Format all code
gmzig-fmt-check     # Check formatting (CI requirement)
gmzig-clean         # Clean build artifacts
gmzig-perf          # Run performance benchmarks
gmzig-validate      # Full validation pipeline
```

### VS Code Tasks

Use `Ctrl+Shift+P` → "Tasks: Run Task" to access:

- **zig: build** - Standard debug build
- **zig: build optimized** - High-performance build
- **zig: build wasm** - WebAssembly build
- **zig: test** - Run complete test suite
- **zig: run demo** - Execute demo application
- **zig: format** / **zig: format check** - Code formatting
- **zig: validate** - Complete validation pipeline
- **performance: benchmark** - Performance data collection

### Debugging Configuration

Launch configurations are pre-configured for:

- **Debug GM-Zig Demo** - Debug the main application
- **Debug GM-Zig Optimized** - Debug optimized builds
- **Debug GM-Zig Tests** - Debug test failures

## 📊 Performance Monitoring

### Automated Performance Tracking

The repository includes comprehensive performance monitoring:

- **CI Integration**: Automatic performance data collection on each build
- **Historical Tracking**: Performance trends over time
- **Regression Detection**: Automatic alerts for performance degradation

### Manual Performance Analysis

```bash
# Collect current performance data
./scripts/collect-performance-data.sh

# Analyze performance trends
zig build analyze

# Generate detailed reports
zig build analyze -- --format json
```

## 🔒 Security-First Development

### Code Patterns Copilot Understands

With the enhanced MCP configuration, Copilot is now aware of:

1. **Constant-Time Operations**:
   ```zig
   // Copilot will suggest constant-time implementations
   pub fn constantTimeCompare(a: []const u8, b: []const u8) bool {
       // Implementation that prevents timing attacks
   }
   ```

2. **Secure Memory Management**:
   ```zig
   // Copilot understands secure memory clearing patterns
   defer crypto.utils.secureZero(sensitive_data);
   ```

3. **Error Handling for Cryptographic Operations**:
   ```zig
   // Copilot will suggest proper error handling
   const signature = sm2.sign(message, private_key) catch |err| switch (err) {
       error.InvalidKey => return error.CryptographicFailure,
       else => return err,
   };
   ```

### Validation Hooks

Pre-commit hooks automatically check:
- ✅ Code formatting compliance
- ✅ Build success
- ✅ Basic test validation

## 📈 Performance Optimization Guidelines

### Copilot-Enhanced Patterns

The MCP configuration helps Copilot suggest:

1. **Memory-Efficient Algorithms**:
   - Arena allocators for temporary computations
   - Stack-based operations where possible
   - Minimal heap allocations in hot paths

2. **Zig-Specific Optimizations**:
   - Compile-time computations with `comptime`
   - SIMD operations where applicable
   - Proper use of `inline` for performance-critical functions

3. **Cryptographic Optimizations**:
   - Montgomery reduction for modular arithmetic
   - Precomputed tables for elliptic curve operations
   - Constant-time conditional operations

## 🧪 Testing Strategy

### Comprehensive Test Coverage

The 219-test suite covers:

- **Unit Tests**: Individual algorithm components
- **Integration Tests**: Cross-algorithm workflows
- **Compliance Tests**: GM/T standard validation
- **Security Tests**: Constant-time verification
- **Performance Tests**: Benchmark validation
- **Robustness Tests**: Edge case handling

### Test Development Patterns

Copilot now understands common test patterns:

```zig
test "SM2 signature roundtrip" {
    const allocator = testing.allocator;
    const keypair = try SM2.generateKeyPair(allocator);
    defer keypair.deinit();
    
    const message = "test message";
    const signature = try SM2.sign(message, keypair.private_key);
    const is_valid = try SM2.verify(message, signature, keypair.public_key);
    
    try testing.expect(is_valid);
}
```

## 🔧 Troubleshooting

### Common Issues and Solutions

1. **Build Failures**:
   ```bash
   # Clean and rebuild
   gmzig-clean && gmzig-build
   ```

2. **Test Timeouts**:
   ```bash
   # Some tests may take longer - this is expected
   # Use build test instead of direct zig test
   gmzig-test
   ```

3. **Performance Issues**:
   ```bash
   # Always use optimized builds for performance testing
   gmzig-build-fast
   ```

4. **Formatting Errors**:
   ```bash
   # Auto-fix formatting
   gmzig-fmt
   ```

## 📚 Additional Resources

### Documentation Structure

- `README.md` - Project overview and quick start
- `.github/copilot-instructions.md` - Comprehensive Copilot guidance
- `AGENTS.md` - Developer and AI agent guide
- `SM2_IMPLEMENTATION.md` - SM2 algorithm details
- `SM9_IMPLEMENTATION.md` - SM9 algorithm details
- `GM_ZIG_ANALYSIS_REPORT.md` - Complete project analysis

### Learning Resources

- [GM/T Standards Documentation](https://www.oscca.gov.cn/)
- [Zig Language Reference](https://ziglang.org/documentation/master/)
- [Cryptographic Engineering Best Practices](https://cryptopals.com/)

---

🎯 **Goal**: Make GitHub Copilot your cryptographic development partner with deep understanding of Chinese National Standards, Zig language patterns, and security-critical code requirements.

🔐 **Security**: All suggestions maintain cryptographic security properties with constant-time operations and secure memory handling.

⚡ **Performance**: Optimizations maintain the 10x+ performance gains between debug and optimized builds.

✅ **Quality**: All enhancements maintain the 219/219 test pass rate and production-ready status.