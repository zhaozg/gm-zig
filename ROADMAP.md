# GM-Zig Roadmap

> A comprehensive implementation of Chinese National Cryptographic Standards (GM/T) in Zig.
>
> **Current Version:** 0.0.0-alpha | **Zig:** 0.16.x | **Tests:** ✅ All passing

---

## 📊 Current State Assessment

### ✅ What Works Well

| Area | Status | Notes |
|------|--------|-------|
| **SM2** | ✅ Complete | Signature, Key Exchange, Encryption, DER encoding |
| **SM3** | ✅ Complete | Hash, HMAC, Streaming, Performance benchmark |
| **SM4** | ✅ Complete | ECB, CBC, CTR, GCM, XTS modes with T-table |
| **SM9** | ✅ Complete | IBE encryption, signature, key agreement, pairing |
| **ZUC** | ✅ Complete | Stream cipher, EEA3, EIA3 |
| **Field Arithmetic** | ✅ Complete | Montgomery form, constant-time Field type |
| **WASM Support** | ✅ Complete | WASI + freestanding targets |
| **Test Suite** | ✅ All passing | Comprehensive coverage across all algorithms |
| **CSPRNG** | ✅ Complete | System CSPRNG + WASM Web Crypto API fallback |
| **Benchmarking** | ✅ Complete | Benchmark + performance analysis tools |
| **SM2 Precomputed Hash** | ✅ Complete | Pre-computed hash mode for sign/verify |
| **SM2 KDF** | ✅ Complete | Key derivation function based on SM3 |
| **SM9 Compliance Tests** | ✅ Complete | GM/T 0044-2016 standard compliance tests |
| **Constant-Time Compare** | ✅ Complete | `constantTimeEqual` in SM2 utils |

### ⚠️ Identified Gaps & Risks

| Category | Severity | Issue |
|----------|----------|-------|
| **Security** | 🔴 Critical | No secure memory zeroing for private keys / sensitive data |
| **Security** | 🟡 High | Constant-time guarantees not verified across all code paths |
| **Versioning** | 🟡 High | Version is `0.0.0` — no semantic versioning or CHANGELOG |
| **API** | 🟡 High | Inconsistent error handling and allocator patterns across modules |
| **Testing** | 🟡 High | No fuzz testing, no property-based testing, no coverage reporting |
| **Performance** | 🟢 Medium | No SIMD optimizations, no assembly backends |
| **Compliance** | 🟡 High | No third-party audit, no formal verification |
| **Documentation** | 🟡 High | Missing doc comments, no API reference, no security guide |
| **CI/CD** | 🟢 Medium | No coverage, no fuzzing, no performance regression detection |
| **Interoperability** | 🟢 Medium | No C FFI, no language bindings, no PKI support |

---

## 🗺️ Roadmap

### Phase 1: Security Hardening (v0.1.0) — *Critical Foundation*

> **Goal:** Address all critical security issues before any production use.

#### 1.2 Secure Memory Management
- [ ] Add `secureZero` for all sensitive data:
  - Private keys (SM2, SM9)
  - Shared secrets (key exchange)
  - Intermediate computation buffers
- [ ] Audit all `defer allocator.free()` paths for sensitive data leaks
- [ ] Add `test "Secure memory zeroing"` — verify memory is zeroed after use

#### 1.3 Constant-Time Verification
- [ ] Audit all comparison operations — ensure `constantTimeEqual` is used everywhere
  - Signature verification (`src/sm2/signature.zig`)
  - MAC verification (`src/sm4` GCM mode)
  - SM9 pairing output comparison
- [ ] Add `ctverif` or similar constant-time analysis to CI
- [ ] Document which operations are guaranteed constant-time
- [ ] Add `test "Constant-time properties"` — timing-based test for known patterns

#### 1.4 Error Handling Unification
- [ ] Define top-level `GmError` error set in `src/root.zig`
- [ ] Standardize error naming across all modules:
  - `InvalidEncoding`, `InvalidKey`, `VerificationFailed`, etc.
- [ ] Ensure all public functions return proper error unions
- [ ] Add error documentation to all public APIs

---

### Phase 2: Versioning & Quality (v0.2.0) — *Release Readiness*

> **Goal:** Establish proper versioning, documentation, and quality gates.

#### 2.1 Semantic Versioning & Release Process
- [ ] Set version to `0.1.0` in `build.zig.zon`
- [ ] Create `CHANGELOG.md` following [Keep a Changelog](https://keepachangelog.com/) format
- [ ] Create `RELEASE.md` with release checklist
- [ ] Set up GitHub Releases with auto-generated changelogs
- [ ] Add version string to library info (`src/sm9.zig` pattern → all modules)

#### 2.2 Documentation
- [ ] Add doc comments (`///`) to all public functions, types, and constants
- [ ] Generate API documentation with `zig build docs`
- [ ] Create `docs/` directory with:
  - [ ] `docs/architecture.md` — Module structure and data flow
  - [ ] `docs/security.md` — Security considerations, threat model, limitations
  - [ ] `docs/performance.md` — Benchmark methodology and results
  - [ ] `docs/interop.md` — Interoperability with other GM implementations
  - [ ] `docs/standards.md` — GM/T standard compliance matrix
- [ ] Add usage examples to each module's doc comments
- [ ] Create `docs/quickstart.md` — 5-minute getting started guide

#### 2.3 Testing Improvements
- [ ] Add code coverage reporting to CI (`zig build test --summary all`)
- [ ] Add fuzz testing with `zig fuzz`:
  - [ ] SM3 hash — roundtrip and collision resistance
  - [ ] SM4 encrypt/decrypt — roundtrip for all modes
  - [ ] SM2 sign/verify — roundtrip and invalid signature rejection
  - [ ] SM2 encrypt/decrypt — roundtrip
  - [ ] DER encoding/decoding — roundtrip
- [ ] Add property-based tests:
  - [ ] `sign(verify) == true` for random messages
  - [ ] `decrypt(encrypt) == plaintext` for random data
  - [ ] Key exchange shared key equality
- [ ] Add memory leak detection (Valgrind / AddressSanitizer in CI)
- [ ] Add SM9 performance tests with timeout guards (pairing is slow)

#### 2.4 CI/CD Enhancements
- [ ] Add multi-platform matrix: Linux x86_64, macOS arm64, Windows x86_64
- [ ] Add Zig version matrix: 0.14.x, 0.15.x, 0.16.x
- [ ] Add WASM build verification in CI
- [ ] Add `zig fmt --check` as required CI step
- [ ] Add performance regression detection (compare benchmark results across commits)
- [ ] Add security linting (detect non-constant-time comparisons, insecure RNG usage)

---

### Phase 3: Feature Completeness (v0.3.0) — *Standard Compliance*

> **Goal:** Fill in missing algorithm features for full GM/T standard compliance.

#### 3.1 SM3 Enhancements
- [ ] Add CMAC mode (GM/T 0004-2012)
- [ ] Add HKDF (based on SM3)
- [ ] Add PBKDF2 (based on SM3)
- [ ] Add SM3-XOF (extendable output function) if specified in standards

#### 3.2 SM4 Enhancements
- [ ] Add CFB mode (Cipher Feedback)
- [ ] Add OFB mode (Output Feedback)
- [ ] Add CCM mode (Counter with CBC-MAC)
- [ ] Add key wrapping mode (SM4-KW)
- [ ] Optimize GCM with carry-less multiplication (CLMUL) where available

#### 3.3 SM2 Enhancements
- [ ] Add certificate handling:
  - [ ] X.509 certificate parsing (SM2-specific extensions)
  - [ ] Certificate generation
  - [ ] CRL parsing
- [ ] Add PKCS#8 private key format (DER/PEM)
- [ ] Add SPKI public key format (DER/PEM)
- [ ] Add PKCS#10 CSR generation
- [x] Add SM2 with SM3 precomputed hash mode (already partially implemented)
- [x] Add SM2 key derivation (KDF with SM3)

#### 3.4 SM9 Enhancements
- [ ] Add batch signature verification
- [ ] Add key derivation (KDF with SM3)
- [x] Add identity-based key agreement (already implemented, verify completeness)
- [ ] Add SM9 certificate format support
- [ ] Optimize pairing computation (final exponentiation)

#### 3.5 ZUC Enhancements
- [ ] Add comprehensive test vectors (currently missing)
- [ ] Add stream cipher mode documentation
- [ ] Add EEA3/EIA3 integration tests

---

### Phase 4: Performance Optimization (v0.4.0) — *Production Speed*

> **Goal:** Achieve competitive performance with reference implementations.

#### 4.1 SIMD Optimizations
- [ ] SM3: AVX2 / NEON vectorized implementation
- [ ] SM4: AVX2 / NEON parallel block encryption
- [ ] SM4 GCM: CLMUL-based GHASH
- [ ] Conditional compilation with `@import("builtin")` target CPU features

#### 4.2 Assembly Backends
- [ ] SM2 scalar multiplication: optimized windowed NAF
- [ ] SM2 point operations: projective coordinate optimizations
- [ ] SM9 pairing: optimized Miller loop
- [ ] Consider inline assembly for critical paths (with Zig `@asm`)

#### 4.3 Benchmarking Infrastructure
- [x] Standardize benchmark methodology (warmup, iterations, statistical analysis)
- [ ] Add benchmark comparison with:
  - [ ] Tongsuo (LibreSSL fork with GM support)
  - [ ] GmSSL
  - [ ] Bouncy Castle (Java GM implementation)
- [ ] Add benchmark results to `docs/performance.md`
- [ ] Add performance regression CI job

#### 4.4 Memory Optimization
- [ ] Reduce allocations in hot paths (SM4 block cipher, SM3 hash)
- [ ] Implement object pooling for repeated operations
- [ ] Add `noalias` and `align` hints for better compiler optimization

---

### Phase 5: Interoperability & Ecosystem (v0.5.0) — *Broader Adoption*

> **Goal:** Enable use in real-world applications and integration with other systems.

#### 5.1 C FFI Bindings
- [ ] Create `include/gm-zig.h` with C-compatible API
- [ ] Export all algorithms via `extern` functions
- [ ] Add `pkg-config` file (`gm-zig.pc`)
- [ ] Test C interop with a small C program

#### 5.2 Language Bindings
- [ ] Python bindings (via C FFI + ctypes/cffi)
- [ ] Go bindings (via C FFI + cgo)
- [ ] Node.js bindings (via N-API or ffi-napi)
- [ ] Document binding usage in `docs/bindings.md`

#### 5.3 PKI Infrastructure
- [ ] SM2 certificate chain validation
- [ ] SM2 OCSP responder support
- [ ] SM2 TLS cipher suite support (GM/T 0024-2014)
- [ ] Integration guide for using with existing TLS libraries

#### 5.4 WASM Improvements
- [ ] Optimize WASM binary size (tree shaking, dead code elimination)
- [ ] Add Web Crypto API compatibility layer
- [ ] Add npm package for browser usage
- [ ] Add WASI-native random number source

---

### Phase 6: Compliance & Audit (v1.0.0) — *Production Ready*

> **Goal:** Achieve production-grade security certification readiness.

#### 6.1 Standards Compliance Verification
- [x] Complete GM/T standard test vector coverage for all algorithms
- [x] Cross-validate with GmSSL reference implementation outputs
- [ ] Create compliance matrix document (`docs/standards.md`)
- [x] Add automated standard vector testing to CI

#### 6.2 Security Audit
- [ ] Engage third-party security audit firm
- [ ] Address all findings from audit
- [ ] Publish audit report (redacted if necessary)
- [ ] Implement ongoing security review process

#### 6.3 Formal Verification (Stretch Goal)
- [ ] Formal verification of critical field arithmetic
- [ ] Prove constant-time properties for signature verification
- [ ] Verify SM2/SM9 curve point operations

#### 6.4 Release Process
- [ ] Set version to `1.0.0`
- [ ] Create `SECURITY.md` with vulnerability disclosure policy
- [ ] Create `SUPPORT.md` with version support policy
- [ ] Set up automated release notes generation
- [ ] Publish to package registries (if applicable)

---

## 📋 Implementation Priority Matrix

| Priority | Phase | Effort | Impact | Dependencies |
|----------|-------|--------|--------|--------------|
| 🔴 P0 | Phase 1.1 | Medium | Critical | None |
| 🔴 P0 | Phase 1.2 | Medium | Critical | None |
| 🔴 P0 | Phase 1.3 | High | Critical | Phase 1.1 |
| 🟡 P1 | Phase 2.1 | Low | High | Phase 1 |
| 🟡 P1 | Phase 2.3 | Medium | High | Phase 1 |
| 🟡 P1 | Phase 3.1-3.5 | High | High | Phase 1 |
| 🟢 P2 | Phase 2.2 | Medium | Medium | Phase 2.1 |
| 🟢 P2 | Phase 4.1-4.4 | High | Medium | Phase 1 |
| 🟢 P2 | Phase 5.1-5.4 | High | Medium | Phase 3 |
| ⚪ P3 | Phase 6.1-6.4 | Very High | High | All phases |

---

## 🏗️ Technical Debt Backlog

### Short-term (Fix in Phase 2)
- [ ] `src/root.zig` — no unified error set, no version info
- [x] `src/sm9.zig` — version info only in SM9, not in other modules
- [ ] `src/sm4.zig` — verify all modes have proper deinit patterns
- [ ] `src/common.zig` — Field type lacks secure zeroing methods
- [ ] No `CHANGELOG.md`, no `SECURITY.md`, no `docs/` content

### Medium-term (Fix in Phase 3-4)
- [ ] SM3 missing CMAC, HKDF, PBKDF2
- [ ] SM4 missing CFB, OFB, CCM modes
- [ ] SM2 missing certificate handling, PKCS#8/SPKI formats
- [ ] No SIMD optimizations anywhere
- [ ] No benchmark comparison with reference implementations

### Long-term (Fix in Phase 5-6)
- [ ] No C FFI bindings
- [ ] No language bindings
- [ ] No PKI/TLS integration
- [ ] No third-party security audit
- [ ] No formal verification

---

## 📈 Success Metrics

| Metric | Current | v0.1.0 | v0.2.0 | v0.3.0 | v0.4.0 | v1.0.0 |
|--------|---------|--------|--------|--------|--------|--------|
| **Tests** | ✅ All pass | ✅ All pass | 350+ | 400+ | 400+ | 500+ |
| **Fuzz targets** | 0 | 0 | 3+ | 5+ | 5+ | 8+ |
| **Code coverage** | Unknown | Unknown | 80%+ | 85%+ | 85%+ | 90%+ |
| **CSPRNG** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Secure memory** | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Doc comments** | ~10% | ~10% | 60%+ | 80%+ | 80%+ | 95%+ |
| **CI platforms** | 1 | 1 | 3+ | 3+ | 3+ | 4+ |
| **SM modes** | 5 | 5 | 5 | 8+ | 8+ | 8+ |
| **Version** | 0.0.0 | 0.1.0 | 0.2.0 | 0.3.0 | 0.4.0 | 1.0.0 |
| **Benchmark tools** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **SM9 compliance** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **SM2 precomputed hash** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Constant-time compare** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |

---

## 🤝 Contributing Guidelines

See [CONTRIBUTING.md](CONTRIBUTING.md) (to be created in Phase 2).

### How to Pick an Issue

1. **Security-first:** Issues tagged `security` take priority
2. **Good first issue:** Look for `good-first-issue` label
3. **Algorithm-specific:** Tagged `sm2`, `sm3`, `sm4`, `sm9`, `zuc`
4. **Cross-cutting:** Tagged `ci`, `docs`, `performance`, `testing`

---

## 📝 Notes

- All phases are sequential — do not skip phases
- Security issues (Phase 1) must be resolved before any public release
- Performance optimizations (Phase 4) should not compromise constant-time guarantees
- Compliance verification (Phase 6) requires all previous phases complete
- This roadmap is a living document — update as priorities shift

---

*Last updated: 2026-05-23*
