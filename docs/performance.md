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
| SM9 pairing `e(P1, P2)` | 1.151 s |
| SM9 key extraction | 7.579 ms |
| SM9 sign | 1.182 s |
| SM9 verify | 2.227 s |
| SM9 encrypt (32 B) | 1.109 s |
| SM9 decrypt (32 B) | 1.113 s |

Each sign/verify/encrypt/decrypt operation includes one or two full R-ate
pairings, so the pairing cost dominates. zbench reports a single run for these
operations because one run already exceeds the default time budget.

The field inverse was changed from Fermat exponentiation (`a^(p-2)`) to a binary
extended Euclidean inverse. That reduced key extraction from roughly 330 ms to
about 7.6 ms. Further gains require a Montgomery/Barrett field multiplier and a
projective/sparse pairing implementation; those are tracked in
[ROADMAP.md](../ROADMAP.md).

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
