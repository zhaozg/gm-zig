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

The SM9 implementation is now the standard BN254 implementation only; the old
simplified curve/pairing/sign/encrypt code has been removed.

- H1: `SM3(0x01 || ID || hid || ct)`, 40-byte reduction to `[1, N-1]`.
- H2: `SM3(0x02 || Z || ct)`, 40-byte reduction to `[1, N-1]`.
- KDF: `SM3(Z || ct)` blocks.
- Pairing: R-ate on BN254, checked against `gmalg` and for bilinearity.
- Signature, encryption/decryption, key extraction, and key agreement are
  implemented in `src/sm9/standard.zig`.

Signature, user signing key, encryption `C1`/`C2`, and the GmSSL-style
HMAC-SM3 `C3` are checked against external vectors in
`src/test/sm9_standard_test.zig`. Broader interop testing with the local
GmSSL CLI and more boundary vectors remain open.
