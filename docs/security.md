# Security Notes

This document describes the security properties the project currently attempts
to provide, and the properties it does **not** provide. It is not a security
audit or a certification statement.

## Status

- The library is a work-in-progress implementation. It has not been
  independently audited.
- Do not use it to protect production secrets without a separate security
  review.
- Passing tests demonstrate expected behavior on the covered cases; they do not
  prove correctness, side-channel resistance, or standards conformance.

## Secure memory clearing

`gmlib.secure` provides volatile-write helpers for clearing secret material:

- `secure.zero(bytes)` clears a mutable byte slice.
- `secure.zeroValue(T, &value)` clears a fixed-size value.
- `secure.zeroSlice(T, slice)` clears a slice of fixed-size elements.

The following paths clear secrets they own or copy:

| Component | Cleared material |
|---|---|
| SM2 `KeyPair` | private key (`KeyPair.zeroize` / `KeyPair.deinit`) |
| SM2 signature | private-key copy, nonce, and intermediate scalars |
| SM2 encryption/decryption | nonce, shared-point coordinates, KDF output, and plaintext on authentication failure |
| SM2 key exchange | long-term/ephemeral private keys (`KeyExchangeContext.deinit`), shared point, KDF input/output, and returned shared-key buffer |
| SM4 | expanded round keys (`SM4.zeroize`) |
| ZUC | LFSR and register state, AEAD key/IV (`ZUC.zeroize`, `ZUC_AEAD.zeroize`) |
| SM9 key extraction | `H1` output and intermediate exponents; user private-key structs expose `zeroize` |
| SM9 ephemeral key agreement | ephemeral private scalar (`EphemeralKeyPair.zeroize`) |

Caller-owned plaintext and caller copies of private keys are not automatically
cleared. Call `zeroize`/`deinit` on objects that hold real secrets before
discarding them.

Remaining work: audit allocator-backed buffers and any long-lived key storage
for missing clears. See [ROADMAP.md](../ROADMAP.md) Phase 1.2.

## Constant-time comparisons

`gmlib.secure.constantTimeEqual` compares equal-length byte strings without
branching on their contents. It is used for:

- SM2 signature verification (`R == r`).
- SM4-GCM tag verification.
- SM9 signature hash verification, encryption `C3` verification, and `GtElement`
  equality used by pairing checks.

Other comparisons in SM2/SM9 curve and big-integer code may branch. Some of
those branches depend only on public curve parameters or public points; others
have not been reviewed. No automated constant-time analysis (`ctverif` or
equivalent) is currently run in CI.

## Known critical gap

SM9 signature verification currently accepts a signature if **either** the
pairing check or the hash check succeeds. That behavior was introduced to work
around incomplete pairing verification and is not acceptable for a security
boundary. The intended final behavior is to require both checks after the
pairing path is corrected. This is tracked in [ROADMAP.md](../ROADMAP.md).

## Randomness

Random scalars come from `std.Io.random` on native targets and from the Web
Crypto API in the freestanding WASM build. Applications remain responsible for
the quality of the host entropy source.

## Reporting

Do not open a public issue for a suspected vulnerability. Contact the
maintainers privately first. A formal `SECURITY.md` disclosure policy is still
on the roadmap.

## SM9 correctness status

The SM9 H1, H2, and KDF helpers in `src/sm9/hash.zig` now follow the
GM/T 0044-2016 construction and are checked against independently generated
vectors:

- H1: `SM3(hid || ID || ct_be32)`, `(hash mod (N-1)) + 1`, with the G1
  x-coordinate validity retry.
- H2: `SM3(0x02 || Z || ct_be32)`, `(hash mod (N-1)) + 1`.
- KDF: `SM3(Z || ct_be32)` blocks.

This does **not** make the legacy SM9 signature, encryption, or pairing code
standards-compliant. Those paths still rely on the simplified
`curve.zig`/`pairing.zig` implementation and remain on the roadmap for a full
BN254 pairing rewrite and external cross-validation.

## Standard SM9 foundation

`src/sm9/bn.zig` now contains native `u256` BN254 field and group primitives:
Fp, Fp2, Fp4, Fp12, G1, and G2. The constants and scalar multiplications are
checked against independently generated SM9 vectors (P1, P2, 2P1, 2P2), and
Fp12 inversion/multiplication are checked for internal consistency.

This module is a foundation, not yet a replacement for the legacy SM9 code.
The R-ate/Tate pairing, signature, encryption, and key-extraction paths still
need to be rebuilt on top of it and cross-validated with GmSSL/gmalg.

## Standard SM9 core

`src/sm9/standard.zig` implements GM/T 0044-2016 SM9 on top of the standard
BN254 pairing:

- master public keys: `P_pub-s = s*P2`, `P_pub-e = s*P1`;
- user keys: `d_A = s/(H1(ID||hid)+s) * P1`, `d_B = s/(H1(ID||hid)+s) * P2`;
- signature and verification using `e(P1, P_pub-s)`;
- encryption/decryption using `e(P_pub-e, P2)` and `e(C1, d_B)`.

The signature vector (ID "Alice", message "Chinese IBS standard", nonce
`0x0123456789abcdef`) and the encryption `C1`/`C2` vector are checked against
`gmalg` in `src/test/sm9_standard_test.zig`. Encryption `C3` uses the
HMAC-SM3 construction used by GmSSL v3.

Important: this standard core is **not yet wired into** the legacy
`SM9Context`, `sign.zig`, or `encrypt.zig` entry points. Applications that call
the old API still get the legacy non-standard behavior; use `sm9.standard`
directly until the migration is complete.
