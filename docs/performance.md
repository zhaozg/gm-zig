# SM9 Performance

Measured on 2026-11-13 with Zig 0.16.0, `ReleaseFast`, on:

- CPU: Intel Core i7-1068NG7 @ 2.30 GHz
- OS: macOS x86_64
- RAM: 16 GiB

Command:

```bash
zig build bench -Doptimize=ReleaseFast -- --filter SM9
```

Results:

| Operation | Time |
|---|---:|
| SM9 pairing `e(P1, P2)` | 9.298 ms |
| SM9 key extraction | 0.335 ms |
| SM9 sign | 10.389 ms |
| SM9 verify | 24.765 ms |
| SM9 encrypt (32 B) | 10.450 ms |
| SM9 decrypt (32 B) | 10.566 ms |

Each sign/verify/encrypt/decrypt operation includes one or two full R-ate
pairings, so the pairing cost dominates. zbench reports a single run for these
operations because one run already exceeds the default time budget.

Optimizations that have landed:

1. Fp inverse changed from Fermat exponentiation to binary extended Euclid.
2. Fp multiplication changed to a 4x64 Montgomery multiplier (`mul` uses two
   Montgomery multiplications while keeping the public representation normal).
3. Frobenius changed from a 256-bit Fp12 exponentiation to precomputed diagonal
   factors.
4. G1/G2 scalar multiplication changed from affine to Jacobian coordinates,
   removing one Fp/Fp2 inversion per bit.
5. Fp add/sub no longer use a `u512` division; they use carry/borrow checks.
6. Fixed-base 4-bit comb tables for P1/P2 remove all doublings from generator
   multiplication; key extraction now performs 64 mixed additions.
7. Mod-N inverse uses binary extended Euclid instead of Fermat exponentiation.

Together these reduced pairing from ~1.15 s to ~9.3 ms and key extraction from
~330 ms to ~0.34 ms. ReleaseFast tests run in ~1-2 s.

These numbers are for this machine and this commit only. They are not a
comparison against GmSSL or another SM9 implementation.

## Full benchmark comparison (2026-11-14)

The full `zig build bench -Doptimize=ReleaseFast` run wrote
[`BenchLog.txt`](../BenchLog.txt). It was compared with the previous committed
log from 2026-05-25 on the same CPU/OS.

For the 42 non-SM9 benchmarks that exist in both logs (SM3, SM4, ZUC, SM2),
most results are within ±10%. There are isolated noise outliers, for example
SM3 64K reports a higher average, but its minimum is essentially unchanged
(182.5 µs vs 182.8 µs), so this is run-to-run noise rather than a code
regression. No SM3/SM4/ZUC/SM2 implementation code changed in this period.

SM9 timings are **not comparable** to the old log: the previous SM9 benchmark
measured the removed simplified implementation, which did no real pairing. The
new standard implementation performs the full BN254 R-ate pairing:

| SM9 operation | Old simplified log | New standard log |
|---|---:|---:|
| key extraction | 14.9 ms | 7.4 ms |
| sign | 45.5 ms | 1.221 s |
| verify | 145.6 ms | 2.269 s |
| encrypt (32 B) | 32.6 ms | 1.204 s |
| decrypt (32 B) | 31.8 ms | 1.086 s |
| pairing | not benchmarked | 1.211 s |

The old numbers are still shown only to make clear why they cannot be used as
a performance baseline for the standard implementation.


## Comparison with GmSSL 3.3.0-dev

GmSSL `3.3.0-dev.1183` was benchmarked with the C harness
[`scripts/bench_sm9_gmssl.c`](../scripts/bench_sm9_gmssl.c), linked against the
local `build/bin/libgmssl.dylib` on the same machine.

| Operation | GmSSL | gm-zig | gm-zig / GmSSL |
|---|---:|---:|---:|
| pairing | 7.5 ms | 9.30 ms | 1.24x |
| key extraction | 0.135 ms | 0.335 ms | 2.5x |
| sign | 11.4 ms | 10.39 ms | 0.91x |
| verify | 20.6 ms | 24.77 ms | 1.20x |
| encrypt (32 B) | 12.3 ms | 10.45 ms | 0.85x |
| decrypt (32 B) | 7.5 ms | 10.57 ms | 1.41x |

There is still substantial headroom. The remaining gap is dominated by:

- Signature and encryption are slightly faster than GmSSL in this run.
- Pairing is within ~1.24x and could be closed further with projective sparse
  lines.
- Key extraction is now ~2.5x slower; the remaining gap is mostly fixed-base
  table size (4-bit vs GmSSL's 7-bit Booth table) and inversion overhead.
- GLV/endomorphism was evaluated but not added: the fixed-base table already
  removes the doublings that GLV would target, so the additional complexity is
  not justified by the measured bottleneck.

Build and run the GmSSL harness with:

```bash
cc -O3 -I ~/work/Crypto/GmSSL/include scripts/bench_sm9_gmssl.c \
  -L ~/work/Crypto/GmSSL/build/bin -lgmssl \
  -Wl,-rpath,$HOME/work/Crypto/GmSSL/build/bin -o /tmp/bench_gmssl_sm9
/tmp/bench_gmssl_sm9
```

## Other algorithms vs GmSSL (2026-11-14)

GmSSL 3.3.0-dev was benchmarked with
[`scripts/bench_gmssl_all.c`](../scripts/bench_gmssl_all.c) on the same machine.
The benchmark order in `zig build bench` is now:

1. SM3
2. SM4 (all modes)
3. ZUC
4. SM2
5. SM9

### SM3

| Size | GmSSL | gm-zig | gm-zig / GmSSL |
|---|---:|---:|---:|
| 64 B | 0.530 µs | 0.433 µs | 0.82x |
| 1 KB | 4.23 µs | 3.48 µs | 0.82x |
| 64 KB | 254.8 µs | 203.6 µs | 0.80x |
| 1 MB | 4.36 ms | 3.42 ms | 0.79x |

gm-zig is slightly faster across the tested sizes.

### SM4

| Operation | GmSSL | gm-zig | gm-zig / GmSSL |
|---|---:|---:|---:|
| ECB encrypt 1 KB | 6.94 µs | 7.33 µs | 1.06x |
| ECB encrypt 64 KB | 451.9 µs | 467.4 µs | 1.03x |
| ECB encrypt 1 MB | 7.14 ms | 7.54 ms | 1.05x |

SM4 ECB is at parity (within about 5%). The GmSSL SM4 decrypt harness includes
per-iteration key scheduling, so the 16 B decrypt comparison is not
representative and is omitted.

### ZUC

| Operation | GmSSL | gm-zig | gm-zig / GmSSL |
|---|---:|---:|---:|
| crypt 1 KB | 2.67 µs | 3.17 µs | 1.19x |
| crypt 64 KB | 148.8 µs | 175.8 µs | 1.18x |

ZUC is about 18–19% slower. ZUC-AEAD is a gm-zig-specific construction and has
no direct GmSSL equivalent in this build.

### SM2

| Operation | GmSSL | gm-zig | gm-zig / GmSSL |
|---|---:|---:|---:|
| key generation | 7.86 µs | 38.0 µs | 4.8x |
| sign | 85.0 µs | 124.3 µs | 1.46x |
| verify | 66.9 µs | 400.9 µs | 6.0x |
| encrypt (32 B) | 72.4 µs | 368.1 µs | 5.1x |
| decrypt (32 B) | 60.3 µs | 301.9 µs | 5.0x |

SM2 is still the largest remaining gap among the non-SM9 algorithms, but it
improved substantially after adding a fixed-base comb table for `G` and a
4-bit window with mixed addition and batch inversion for arbitrary points.
Key generation dropped from ~321 µs to ~34.8 µs, and signing from ~385 µs to
~112 µs. The GmSSL harness signs/verifies a precomputed digest, while gm-zig's
benchmark also computes the SM3 user hash each time, so the sign/verify ratio
is somewhat inflated.

Verification and public-key operations remain about 5x slower because the
arbitrary-point multiplication still uses a 256-bit windowed loop and generic
field/point arithmetic, without GmSSL's wNAF, endomorphism, or assembly
backends. Verification also computes `s*G + t*PA` as two independent
multiplications instead of a simultaneous double-base multiplication.

The SM9 numbers in the previous section are already within roughly 0.8–1.4x of
GmSSL except key extraction (about 2.5x).
