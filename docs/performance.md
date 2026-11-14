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
| SM9 pairing `e(P1, P2)` | 9.662 ms |
| SM9 key extraction | 1.194 ms |
| SM9 sign | 10.275 ms |
| SM9 verify | 24.367 ms |
| SM9 encrypt (32 B) | 10.358 ms |
| SM9 decrypt (32 B) | 9.772 ms |

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

Together these reduced pairing from ~1.15 s to ~9.7 ms and ReleaseFast test
time from ~55 s to ~1-2 s.

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
| pairing | 7.5 ms | 9.66 ms | 1.29x |
| key extraction | 0.135 ms | 1.19 ms | 8.8x |
| sign | 11.4 ms | 10.28 ms | 0.90x |
| verify | 20.6 ms | 24.37 ms | 1.18x |
| encrypt (32 B) | 12.3 ms | 10.36 ms | 0.84x |
| decrypt (32 B) | 7.5 ms | 9.77 ms | 1.30x |

There is still substantial headroom. The remaining gap is dominated by:

- Pairing is now within ~1.3x of GmSSL.
- Key extraction is the largest remaining gap (~8.8x): it uses a 256-bit
  double-and-add loop without a precomputed generator table/window.
- Miller loop / line evaluation could still use projective sparse lines for
  another modest gain.

Build and run the GmSSL harness with:

```bash
cc -O3 -I ~/work/Crypto/GmSSL/include scripts/bench_sm9_gmssl.c \
  -L ~/work/Crypto/GmSSL/build/bin -lgmssl \
  -Wl,-rpath,$HOME/work/Crypto/GmSSL/build/bin -o /tmp/bench_gmssl_sm9
/tmp/bench_gmssl_sm9
```
