# MCP Configuration for GM-Zig

This directory contains Model Context Protocol (MCP) server configurations to enhance GitHub Copilot's understanding of the GM-Zig cryptographic library.

## What is MCP?

Model Context Protocol (MCP) allows AI assistants like GitHub Copilot to access external context and tools, making them smarter and more capable for specific domains and projects.

## Configuration Files

### `mcp-config.json`
Main MCP server configuration that provides Copilot with:

- **Project Context**: Understanding that this is a cryptographic library implementing Chinese National Standards
- **Algorithm Knowledge**: Specific knowledge about SM2, SM3, SM4, and SM9 algorithms
- **Security Patterns**: Awareness of constant-time implementations and secure memory handling
- **Performance Patterns**: Zig-specific optimization techniques for cryptographic operations

## Setting Up MCP with VS Code

1. **Install the MCP Extension** (if available):
   ```bash
   code --install-extension modelcontextprotocol.mcp-vscode
   ```

2. **Configure MCP in VS Code Settings**:
   Add to your VS Code settings.json:
   ```json
   {
     "mcp.servers": {
       "gm-zig": {
         "command": "npx",
         "args": ["-y", "@modelcontextprotocol/server-filesystem"],
         "env": {
           "CONFIG_FILE": ".github/mcp-config.json"
         }
       }
     }
   }
   ```

3. **Restart VS Code** to activate the MCP servers.

## What This Enables

With MCP configured, GitHub Copilot becomes aware of:

### 🔒 Cryptographic Security Patterns
- Constant-time implementations to prevent timing attacks
- Secure memory clearing and management
- Proper error handling for cryptographic operations

### 🏎️ Performance Optimization
- Memory-efficient algorithms using arena allocators
- Zig-specific compile-time optimizations
- SIMD operations where applicable

### 📐 Algorithm-Specific Knowledge
- **SM2**: Elliptic curve cryptography patterns
- **SM3**: Hash function implementations
- **SM4**: Block cipher operations
- **SM9**: Identity-based cryptography

### 🧪 Testing Patterns
- Roundtrip test implementations
- Edge case validation
- Performance benchmark patterns
- Security property verification

## Example Enhanced Suggestions

### Before MCP:
```zig
// Basic suggestion
pub fn sign(message: []const u8, key: PrivateKey) Signature {
    // Generic implementation
}
```

### After MCP:
```zig
// Context-aware suggestion with security considerations
pub fn sign(message: []const u8, private_key: PrivateKey) !Signature {
    // Validate inputs
    if (message.len == 0) return error.EmptyMessage;
    if (!private_key.isValid()) return error.InvalidPrivateKey;
    
    // Use constant-time operations to prevent timing attacks
    var k = try generateSecureNonce();
    defer crypto.utils.secureZero(@ptrCast([*]u8, &k)[0..@sizeOf(@TypeOf(k))]);
    
    // SM2 signature implementation with proper error handling
    const r = try computeR(message, k);
    const s = try computeS(message, private_key, k, r);
    
    return Signature{ .r = r, .s = s };
}
```

## Troubleshooting

### MCP Servers Not Working
1. Check that the MCP extension is installed and enabled
2. Verify the configuration paths in settings.json
3. Restart VS Code after configuration changes
4. Check the VS Code output panel for MCP-related errors

### Limited Context Improvement
- Ensure the `mcp-config.json` file is in the correct location
- Verify that the filesystem server has access to the project directory
- Check that environment variables are properly set

## Alternative Setup Methods

### Using GitHub Copilot Chat
Even without full MCP setup, you can provide context manually:

```
@workspace /explain this is a cryptographic library implementing Chinese National Standards GM/T algorithms including SM2, SM3, SM4, and SM9. All code must be constant-time for security and memory-safe for production use.
```

### Environment Variables
Set these environment variables to help tools understand the context:
```bash
export GM_ZIG_PROJECT=true
export CRYPTO_LIBRARY=gm-zig
export SECURITY_CRITICAL=true
```

## Contributing

If you find ways to improve the MCP configuration or have suggestions for additional context that would help AI assistants, please:

1. Test your changes thoroughly
2. Ensure they improve code suggestions quality
3. Document the improvements
4. Submit a pull request

---

📚 **Learn More**: [Model Context Protocol Documentation](https://github.com/modelcontextprotocol/specification)

🤖 **GitHub Copilot**: [Copilot Documentation](https://docs.github.com/en/copilot)