# SIMD Performance Benchmark Results

## Methodology

This benchmark compares scalar (SIMD disabled) vs SIMD-enabled performance in **the same build configuration** to isolate the actual benefit of the SIMD code paths, rather than comparing across different optimization levels.

## Test Environment

- **CPU**: x86_64 with AVX2 support
- **Compiler**: Zig 0.14.1
- **OS**: Linux
- **Test Sizes**: 1KB, 16KB, 1MB for block ciphers; 64KB, 1MB, 10MB for hash

## Results

### Debug Build

In debug builds, the SIMD optimization path shows **no measurable performance improvement**:

| Algorithm | Scalar | SIMD | Speedup | Result |
|-----------|--------|------|---------|--------|
| SM4 ECB   | 36 MB/s | 35 MB/s | 0.97x | ❌ No benefit |
| SM4 CBC decrypt | 29 MB/s | 29 MB/s | 1.00x | ❌ No benefit |
| SM3 Hash  | 19 MB/s | 19 MB/s | 1.00x | ❌ No benefit |

### ReleaseFast Build

In optimized builds, the SIMD path still shows **minimal to no improvement**, and in some cases slight slowdown:

| Algorithm | Scalar | SIMD | Speedup | Result |
|-----------|--------|------|---------|--------|
| SM4 ECB   | 140 MB/s | 135 MB/s | 0.95x | ❌ Slight slowdown |
| SM4 CBC decrypt | 123 MB/s | 122 MB/s | 0.99x | ❌ No benefit |
| SM3 Hash  | 245 MB/s | 248 MB/s | 1.01x | ⚠️ Minimal (1%) benefit |

## Why No Performance Improvement?

### 1. Compiler Auto-Vectorization

Zig's LLVM backend with `-Doptimize=ReleaseFast` already performs excellent automatic vectorization of the scalar code. The compiler:
- Automatically unrolls loops
- Uses SIMD instructions where beneficial
- Optimizes memory access patterns
- Eliminates redundant operations

### 2. Implementation Approach

The current "SIMD" implementation uses:
- **Loop unrolling**: Processing multiple blocks in a loop
- **Independent operations**: Calling the same function multiple times
- **NOT using** Zig's `@Vector` types for true SIMD parallelism

This approach provides:
✅ Code structure for parallel processing
✅ Better readability and maintainability
❌ No actual performance benefit over scalar + compiler optimization

### 3. Memory Bandwidth Limitations

At throughputs of 120-250 MB/s:
- Memory bandwidth becomes the bottleneck
- CPU can process data faster than it arrives from RAM
- Additional parallelism doesn't help when waiting on memory

## The Real Performance Gain: Build Optimization

The significant performance improvement comes from **build optimization level**, not SIMD:

| Algorithm | Debug | ReleaseFast | Improvement from Optimization |
|-----------|-------|-------------|-------------------------------|
| SM4 ECB   | 35 MB/s | 140 MB/s | **4.0x** ⭐ |
| SM4 CBC   | 29 MB/s | 122 MB/s | **4.2x** ⭐ |
| SM3       | 19 MB/s | 247 MB/s | **13.0x** ⭐ |

## Recommendations

### For Users
1. **Use `-Doptimize=ReleaseFast`** for production - this provides the real performance gain
2. **Don't worry about SIMD settings** - the library automatically uses the best code path
3. **Expect ~140 MB/s for SM4** and ~245 MB/s for SM3 on modern x86_64

### For Future Development

To achieve actual SIMD performance improvements, consider:

1. **Use `@Vector` types**: Replace loops with true vector operations
   ```zig
   const Vec4u32 = @Vector(4, u32);
   var blocks: Vec4u32 = ...;  // Process 4 values simultaneously
   ```

2. **SIMD intrinsics**: Use platform-specific intrinsics for specialized operations
   - x86: `@import("std").x86_64` for SSE/AVX
   - ARM: `@import("std").aarch64` for NEON

3. **Algorithm redesign**: Some operations (like message expansion) may need restructuring to be truly data-parallel

4. **Focus on hot paths**: Profile to find where CPU time is actually spent

## Conclusion

This implementation demonstrates that:
- ✅ **SIMD infrastructure** is in place for future work
- ✅ **Code quality** is maintained with proper testing
- ✅ **Compiler optimization** already provides excellent performance
- ❌ **Current SIMD path** doesn't provide measurable benefits
- ⚠️ **Future work** needed for true SIMD performance gains

**The honest assessment**: The major performance benefit comes from using `ReleaseFast` build mode, not from the SIMD code paths. The SIMD implementation provides a foundation for future work but doesn't currently improve performance over well-optimized scalar code.
