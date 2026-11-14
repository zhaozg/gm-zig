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
| SM9 pairing `e(P1, P2)` | 204.0 ms |
| SM9 key extraction | 4.764 ms |
| SM9 sign | 229.3 ms |
| SM9 verify | 427.4 ms |
| SM9 encrypt (32 B) | 210.1 ms |
| SM9 decrypt (32 B) | 218.9 ms |

Each sign/verify/encrypt/decrypt operation includes one or two full R-ate
pairings, so the pairing cost dominates. zbench reports a single run for these
operations because one run already exceeds the default time budget.

Two optimizations have landed:

1. Fp inverse changed from Fermat exponentiation to binary extended Euclid.
2. Fp multiplication changed to a 4x64 Montgomery multiplier (`mul` now uses
   two Montgomery multiplications, keeping the public representation normal).

Together these reduced pairing from ~1.15 s to ~204 ms and ReleaseFast test time
from ~55 s to ~10 s. Further gains require precomputed Frobenius factors and a
projective/sparse pairing implementation.

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
| pairing | 7.5 ms | 204 ms | 27x |
| key extraction | 0.135 ms | 4.76 ms | 35x |
| sign | 11.4 ms | 229 ms | 20x |
| verify | 20.6 ms | 427 ms | 21x |
| encrypt (32 B) | 12.3 ms | 210 ms | 17x |
| decrypt (32 B) | 7.5 ms | 219 ms | 29x |

There is still substantial headroom. The remaining gap is dominated by:

- Frobenius currently computed as a full 256-bit Fp12 exponentiation; GmSSL
  uses precomputed Frobenius coefficients.
- Miller loop and line evaluation use Fp12 inversions; GmSSL uses projective
  coordinates and sparse line multiplication.
- Affine G2 scalar multiplication performs an Fp2 inversion per bit.

Build and run the GmSSL harness with:

```bash
cc -O3 -I ~/work/Crypto/GmSSL/include scripts/bench_sm9_gmssl.c \
  -L ~/work/Crypto/GmSSL/build/bin -lgmssl \
  -Wl,-rpath,$HOME/work/Crypto/GmSSL/build/bin -o /tmp/bench_gmssl_sm9
/tmp/bench_gmssl_sm9
```
